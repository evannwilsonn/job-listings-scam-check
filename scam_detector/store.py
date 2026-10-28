"""
Where reports, cases and outcomes live: Postgres when DATABASE_URL is set, JSONL files otherwise.

    store = get_store()
    store.add_report(record) -> id                      record from reports.make_report()
    store.list_reports(status="reported", school="") -> [record + {"id"}]
    store.decide_report(id, decision, reviewer, note="") -> record    confirmed | dismissed
    store.confirmed_reports(since="", school="") -> [record]          what export_evidence packages
    store.add_case(record)                               record from followup (hashed case code, no text)
    store.add_outcome(record) -> bool                    False if the case is unknown
    store.cases() / store.outcomes() -> [record]         what outcome_report reads

The learning loop (learning.py) also keeps its state here, with times as Unix seconds:

    store.labels() / store.add_label(rec) / store.set_label_splits({id: split})    reviewer labels (masked text)
    store.templates() / store.add_template(entry) / store.forget_template(text_key)    template memory (memory.py)
    store.save_model(spec) / store.get_model(version)     model files, so every server serves the same ones
    store.release() / store.set_release(**kw) / store.log_release(event, version, detail) / store.release_log(n)
    store.start_run(trigger, live_labels) -> id / store.finish_run(id, **kw) / store.last_run() / store.runs(n)
    store.add_traffic(rec) / store.traffic(since) / store.prune_traffic(before)     drift and shadow comparisons

Reviewer accounts for the review page (review_web.py, reviewers.py, tools/reviewers.py):

    store.add_reviewer(email, name, school, pw_hash) -> id     school "" means every school
    store.reviewer_by_email(email) -> record with pw_hash, or None / store.reviewers() -> [record without pw_hash]
    store.set_reviewer(email, pw_hash=None, active=None) -> bool / store.touch_login(reviewer_id)
    store.add_session(token_hash, reviewer_id, expires_at) / store.session_reviewer(token_hash) -> record or None
    store.drop_session(token_hash) / store.drop_sessions(reviewer_id) / store.get_report(id) -> record or None
    store.undo_decision(id, reviewer, within_seconds) -> record    the same reviewer, shortly after: back in the queue,
        its training label removed, and (Postgres) its indicators un-confirmed unless another confirmed report names them

A career center's own lists (guardrails.py):

    store.school_rules(school) -> [{kind, value, reason, added_by, added_at}]          active entries
    store.add_school_rule(school, kind, value, added_by, reason="") / store.remove_school_rule(school, kind, value, removed_by)

Both backends take and return the same dict shapes, so the API, the reviewer tools and the reports don't care which
one is in use. The file backend is for development and tests; production sets DATABASE_URL to a Neon role that is a
member of lurecheck_app (see db/migrations/001_initial.sql).

Postgres side effects that the file backend doesn't have:
  * a report's domains, wallets and hashed contacts are upserted into indicators (status 'reported'), linked through
    report_indicators, and each one gets a sighting for the school;
  * confirming a report confirms its indicators (with the reviewer's name) and adds its masked text to labels as a
    scam, so the next retrain can use it. Dismissing confirms nothing.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import time
from pathlib import Path
from typing import List, Optional

DATA = Path(os.environ.get("LURECHECK_DATA", Path(__file__).resolve().parent / "data"))
DECISIONS = ("confirmed", "dismissed")
RELEASE_DEFAULT = {"stage": "none", "lane": "full", "candidate_version": None, "active_version": None, "previous_version": None,
                   "run_id": None, "pct": 0, "created_at": None, "stage_started": None, "note": ""}
_RELEASE_COLS = tuple(RELEASE_DEFAULT)
_KINDS = (("domains", "domain", False), ("wallets", "wallet", False), ("email_hashes", "email", True),
          ("phone_hashes", "phone", True))


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def _epoch(t) -> Optional[float]:
    return t.timestamp() if t is not None else None


def _check_rule(kind: str, added_by: str) -> None:
    if kind not in ("trusted_domain", "blocked_domain"):
        raise ValueError("kind must be trusted_domain or blocked_domain")
    if not (added_by or "").strip():
        raise ValueError("say who is adding it")


def _label_source(kind, label: str) -> str:
    """Where a training label came from: report / report_real for a student's report, borderline / borderline_real
    for a close call the detector asked about (so the two can be told apart in the trends and retrain notes)."""
    base = "borderline" if kind == "borderline" else "report"
    return base if label == "scam" else base + "_real"


def _epoch_iso(iso) -> Optional[float]:
    try:
        return dt.datetime.fromisoformat(str(iso).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def _check_reviewer(email: str, name: str) -> tuple:
    email, name = (email or "").strip().lower(), (name or "").strip()[:80]
    if "@" not in email or email.startswith("@") or email.endswith("@") or len(email) > 254:
        raise ValueError(f"not an email address: {email!r}")
    if not name:
        raise ValueError("a reviewer needs a name (it's recorded on every decision)")
    return email, name


def _check_decision(decision: str, reviewer: str) -> None:
    if decision not in DECISIONS:
        raise ValueError(f"decision must be one of {DECISIONS}")
    if not (reviewer or "").strip():
        raise ValueError("a reviewer name is required")


# ---------------------------------------------------------------- files

class JsonlStore:
    def __init__(self, data_dir: Optional[Path] = None, reports_path: Optional[Path] = None):
        d = Path(data_dir or DATA)
        self.reports_path = Path(reports_path or os.environ.get("REPORT_QUEUE_PATH", d / "report_queue.jsonl"))
        self.cases_path, self.outcomes_path = d / "cases.jsonl", d / "outcomes.jsonl"

    @staticmethod
    def _read(path: Path) -> list:
        if not path.exists():
            return []
        out = []
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    @staticmethod
    def _append(path: Path, rec: dict) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")

    def _write(self, rows: list) -> None:
        tmp = self.reports_path.with_suffix(self.reports_path.suffix + ".tmp")
        tmp.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
        tmp.replace(self.reports_path)

    def add_report(self, record: dict) -> str:
        n = len(self._read(self.reports_path))
        self._append(self.reports_path, record)
        return str(n)

    def list_reports(self, status: str = "reported", school: str = "") -> List[dict]:
        return [{**r, "id": str(i)} for i, r in enumerate(self._read(self.reports_path))
                if (not status or r.get("status") == status) and (not school or r.get("school") == school)]

    def decide_report(self, report_id, decision: str, reviewer: str, note: str = "", real: bool = False) -> dict:
        """real=True with "dismissed": the reviewer says it's a real job, which also becomes a "legit" training label."""
        _check_decision(decision, reviewer)
        rows = self._read(self.reports_path)
        r = rows[int(report_id)]
        if r.get("status", "reported") != "reported":
            raise ValueError(f"report {report_id} was already reviewed")
        r.update({"status": decision, "reviewer": reviewer.strip()[:80], "note": (note or "").strip()[:500],
                  "reviewed_at": _now()})
        self._write(rows)
        label = "scam" if decision == "confirmed" else "legit" if real else None
        if label and r.get("text_masked"):
            self.add_label({"label": label, "description": r["text_masked"], "source": _label_source(r.get("kind"), label),
                            "report_id": str(report_id), "school": r.get("school", ""), "reviewer": r["reviewer"]})
        return {**r, "id": str(report_id)}

    def confirmed_reports(self, since: str = "", school: str = "") -> List[dict]:
        return [r for r in self.list_reports("confirmed", school) if not since or r.get("received", "") >= since]

    def add_case(self, record: dict) -> None:
        self._append(self.cases_path, record)

    def add_outcome(self, record: dict) -> bool:
        self._append(self.outcomes_path, record)
        return True

    def cases(self) -> List[dict]:
        return self._read(self.cases_path)

    def confirmed_matches(self, indicators: dict) -> List[dict]:
        """Confirmed indicators among these, with how many confirmed reports and schools named them."""
        out = []
        reports = self.confirmed_reports()
        for key, kind, _ in _KINDS:
            for v in indicators.get(key, []):
                hits = [r for r in reports if v in r.get("indicators", {}).get(key, [])]
                if hits:
                    days = sorted(r.get("received", "")[:10] for r in hits)
                    out.append({"kind": kind, "value": v, "reports": len(hits),
                                "schools": len({r.get("school") for r in hits if r.get("school")}),
                                "schools_7d": None, "first_seen": days[0], "last_seen": days[-1]})
        return out

    def _attestations(self) -> dict:
        p = self.cases_path.parent / "attestations.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}

    def attestation(self, company_key: str) -> Optional[dict]:
        a = self._attestations().get(company_key)
        return a if a and a.get("status", "active") == "active" else None

    def add_attestation(self, record: dict) -> None:
        p = self.cases_path.parent / "attestations.json"
        data = self._attestations()
        data[record["company_key"]] = {**record, "status": record.get("status", "active"), "verified_at": _now()}
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")

    def outcomes(self) -> List[dict]:
        return self._read(self.outcomes_path)

    # ---- the learning loop (learning.py) ----

    def _p(self, name: str) -> Path:
        return self.cases_path.parent / name

    def _rewrite(self, path: Path, rows: list) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
        tmp.replace(path)

    def labels(self) -> List[dict]:
        return [{**r, "id": str(i)} for i, r in enumerate(self._read(self._p("labels.jsonl")))]

    def add_label(self, rec: dict) -> None:
        self._append(self._p("labels.jsonl"), {"title": "", "company": "", "school": "", "split": None, **rec, "at": time.time()})

    def set_label_splits(self, splits: dict) -> None:
        """Only labels without a place get one; a place never changes."""
        rows = self._read(self._p("labels.jsonl"))
        for i, r in enumerate(rows):
            if not r.get("split") and str(i) in splits:
                r["split"] = splits[str(i)]
        self._rewrite(self._p("labels.jsonl"), rows)

    def templates(self) -> List[dict]:
        return self._read(self._p("templates.jsonl"))          # memory.py's replay format (entries and forget ops)

    def add_template(self, entry: dict) -> None:
        self._append(self._p("templates.jsonl"), entry)

    def forget_template(self, text_key: str) -> None:
        self._append(self._p("templates.jsonl"), {"op": "forget", "key": text_key})

    def save_model(self, spec: dict) -> None:
        p = self._p("models") / f"{spec['version']}.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(spec, separators=(",", ":"), sort_keys=True), encoding="utf-8")

    def get_model(self, version: str) -> Optional[dict]:
        p = self._p("models") / f"{version}.json"
        return json.loads(p.read_text(encoding="utf-8")) if version and p.exists() else None

    def release(self) -> dict:
        p = self._p("release.json")
        return {**RELEASE_DEFAULT, **(json.loads(p.read_text(encoding="utf-8")) if p.exists() else {})}

    def set_release(self, **kw) -> None:
        bad = set(kw) - set(_RELEASE_COLS)
        if bad:
            raise ValueError(f"unknown release fields {bad}")
        p = self._p("release.json")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({**self.release(), **kw}), encoding="utf-8")

    def log_release(self, event: str, version: Optional[str], detail: str = "") -> None:
        self._append(self._p("release_log.jsonl"), {"at": time.time(), "event": event, "version": version, "detail": detail[:2000]})

    def release_log(self, limit: int = 20) -> List[dict]:
        return list(reversed(self._read(self._p("release_log.jsonl"))))[:limit]

    def start_run(self, trigger: str, live_labels: int = 0) -> str:
        runs = self._read(self._p("runs.jsonl"))
        self._append(self._p("runs.jsonl"), {"id": str(len(runs)), "started_at": time.time(), "trigger": trigger, "status": "running",
                                             "live_labels": live_labels, "train_rows": 0, "version": None, "report": ""})
        return str(len(runs))

    def finish_run(self, run_id, **kw) -> None:
        runs = self._read(self._p("runs.jsonl"))
        runs[int(run_id)].update({**kw, "finished_at": time.time()})
        self._rewrite(self._p("runs.jsonl"), runs)

    def runs(self, limit: int = 20) -> List[dict]:
        return list(reversed(self._read(self._p("runs.jsonl"))))[:limit]

    def last_run(self) -> Optional[dict]:
        done = [r for r in self._read(self._p("runs.jsonl")) if r.get("status") in ("candidate", "refused")]
        return max(done, key=lambda r: r["started_at"]) if done else None

    def add_traffic(self, rec: dict) -> None:
        self._append(self._p("traffic.jsonl"), {"at": time.time(), "other": None, "other_p": None, "other_flag": None, **rec})

    def traffic(self, since: float = 0.0) -> List[dict]:
        return [r for r in self._read(self._p("traffic.jsonl")) if r.get("at", 0) > since]

    def prune_traffic(self, before: float) -> None:
        p = self._p("traffic.jsonl")
        if p.exists():
            self._rewrite(p, [r for r in self._read(p) if r.get("at", 0) >= before])

    # ---- a career center's own lists (guardrails.py) ----

    def school_rules(self, school: str) -> List[dict]:
        return [r for r in self._read(self._p("school_rules.jsonl")) if r["school"] == school and r.get("status") == "active"]

    def add_school_rule(self, school: str, kind: str, value: str, added_by: str, reason: str = "") -> None:
        _check_rule(kind, added_by)
        if any(r["kind"] == kind and r["value"] == value for r in self.school_rules(school)):
            return
        self._append(self._p("school_rules.jsonl"), {"school": school, "kind": kind, "value": value, "reason": reason[:300],
                                                     "added_by": added_by.strip()[:80], "added_at": time.time(), "status": "active"})

    def remove_school_rule(self, school: str, kind: str, value: str, removed_by: str) -> bool:
        p = self._p("school_rules.jsonl")
        rows, hit = self._read(p), False
        for r in rows:
            if r["school"] == school and r["kind"] == kind and r["value"] == value and r.get("status") == "active":
                r.update({"status": "removed", "removed_by": removed_by.strip()[:80], "removed_at": time.time()})
                hit = True
        if hit:
            self._rewrite(p, rows)
        return hit

    # ---- reviewer accounts (review_web.py) ----

    def get_report(self, report_id) -> Optional[dict]:
        rows = self._read(self.reports_path)
        try:
            i = int(report_id)
        except (TypeError, ValueError):
            return None
        return {**rows[i], "id": str(i)} if 0 <= i < len(rows) else None

    def _reviewer_rows(self) -> list:
        return self._read(self._p("reviewers.jsonl"))

    @staticmethod
    def _public(r: dict) -> dict:
        return {k: v for k, v in r.items() if k != "pw_hash"}

    def add_reviewer(self, email: str, name: str, school: str, pw_hash: str) -> str:
        email, name = _check_reviewer(email, name)
        rows = self._reviewer_rows()
        if any(r["email"] == email for r in rows):
            raise ValueError(f"{email} already has an account")
        rid = str(len(rows) + 1)
        self._append(self._p("reviewers.jsonl"), {"id": rid, "email": email, "name": name, "school": school or "",
                                                  "pw_hash": pw_hash, "active": True, "created_at": time.time(),
                                                  "last_login": None})
        return rid

    def reviewer_by_email(self, email: str) -> Optional[dict]:
        email = (email or "").strip().lower()
        return next((r for r in self._reviewer_rows() if r["email"] == email), None)

    def reviewers(self) -> List[dict]:
        return [self._public(r) for r in self._reviewer_rows()]

    def set_reviewer(self, email: str, pw_hash: Optional[str] = None, active: Optional[bool] = None) -> bool:
        p, rows, hit = self._p("reviewers.jsonl"), self._reviewer_rows(), False
        for r in rows:
            if r["email"] == (email or "").strip().lower():
                if pw_hash is not None:
                    r["pw_hash"] = pw_hash
                if active is not None:
                    r["active"] = bool(active)
                hit = True
        if hit:
            self._rewrite(p, rows)
        return hit

    def touch_login(self, reviewer_id) -> None:
        p, rows = self._p("reviewers.jsonl"), self._reviewer_rows()
        for r in rows:
            if r["id"] == str(reviewer_id):
                r["last_login"] = time.time()
        self._rewrite(p, rows)

    def add_session(self, token_hash: str, reviewer_id, expires_at: float) -> None:
        self._append(self._p("reviewer_sessions.jsonl"), {"token_hash": token_hash, "reviewer_id": str(reviewer_id),
                                                          "expires_at": float(expires_at)})

    def session_reviewer(self, token_hash: str) -> Optional[dict]:
        now = time.time()
        s = next((x for x in self._read(self._p("reviewer_sessions.jsonl"))
                  if x["token_hash"] == token_hash and x["expires_at"] > now), None)
        if s is None:
            return None
        r = next((x for x in self._reviewer_rows() if x["id"] == s["reviewer_id"] and x.get("active")), None)
        return self._public(r) if r else None

    def drop_session(self, token_hash: str) -> None:
        p = self._p("reviewer_sessions.jsonl")
        self._rewrite(p, [x for x in self._read(p) if x["token_hash"] != token_hash and x["expires_at"] > time.time()])

    def undo_decision(self, report_id, reviewer: str, within: float) -> dict:
        rows = self._read(self.reports_path)
        try:
            i = int(report_id)
            r = rows[i]
        except (TypeError, ValueError, IndexError):
            raise ValueError("no such report")
        when = _epoch_iso(r.get("reviewed_at"))
        if r.get("status", "reported") == "reported" or r.get("reviewer") != (reviewer or "").strip()[:80] \
                or when is None or time.time() - when > within:
            raise ValueError("that decision can't be undone any more")
        for k in ("reviewer", "note", "reviewed_at"):
            r.pop(k, None)
        r["status"] = "reported"
        self._write(rows)
        lp = self._p("labels.jsonl")
        self._rewrite(lp, [x for x in self._read(lp) if str(x.get("report_id", "")) != str(i)])
        return {**r, "id": str(i)}

    def drop_sessions(self, reviewer_id) -> None:
        p = self._p("reviewer_sessions.jsonl")
        self._rewrite(p, [x for x in self._read(p) if x["reviewer_id"] != str(reviewer_id)])


# ---------------------------------------------------------------- Postgres

class PostgresStore:
    def __init__(self, url: str):
        import psycopg                                  # only needed when DATABASE_URL is set
        self._psycopg = psycopg
        self.url = url
        self._schools: Optional[set] = None

    def _conn(self):
        # Neon's pooled URL goes through PgBouncer in transaction mode; psycopg's automatic server-side prepared
        # statements (after 5 runs of the same query) don't belong there, so they're off.
        return self._psycopg.connect(self.url, connect_timeout=10, prepare_threshold=None)

    def _school(self, cur, school: str) -> Optional[str]:
        if self._schools is None:
            cur.execute("SELECT id FROM schools")
            self._schools = {r[0] for r in cur.fetchall()}
        return school if school in self._schools else None

    def add_report(self, record: dict) -> str:
        with self._conn() as conn, conn.cursor() as cur:
            school = self._school(cur, record.get("school", ""))
            cur.execute("INSERT INTO reports (school_id, outcome, text_masked, kind) VALUES (%s, %s, %s, %s) RETURNING id",
                        (school, record.get("outcome") or None, record.get("text_masked"), record.get("kind") or "report"))
            rid = cur.fetchone()[0]
            ind = record.get("indicators", {})
            for key, kind, hashed in _KINDS:
                for value in ind.get(key, []):
                    cur.execute(
                        "INSERT INTO indicators (kind, value, hashed) VALUES (%s, %s, %s) "
                        "ON CONFLICT (kind, value) DO UPDATE SET last_seen = now() RETURNING id",
                        (kind, value, hashed))
                    iid = cur.fetchone()[0]
                    cur.execute("INSERT INTO report_indicators (report_id, indicator_id) VALUES (%s, %s) "
                                "ON CONFLICT DO NOTHING", (rid, iid))
                    if school:
                        cur.execute("INSERT INTO sightings (indicator_id, school_id, report_id) VALUES (%s, %s, %s)",
                                    (iid, school, rid))
            return str(rid)

    _REPORT_SQL = """
        SELECT r.id, r.received_at, coalesce(r.school_id, ''), coalesce(r.outcome, ''), coalesce(r.text_masked, ''),
               r.status, r.reviewer, r.reviewed_at, r.note, coalesce(r.kind, 'report'),
               coalesce(json_agg(json_build_object('kind', i.kind, 'value', i.value))
                        FILTER (WHERE i.id IS NOT NULL), '[]')
        FROM reports r
        LEFT JOIN report_indicators ri ON ri.report_id = r.id
        LEFT JOIN indicators i ON i.id = ri.indicator_id
        WHERE (%(status)s = '' OR r.status = %(status)s) AND (%(school)s = '' OR r.school_id = %(school)s)
          AND (%(since)s = '' OR r.received_at >= %(since)s::date)
        GROUP BY r.id ORDER BY r.received_at, r.id"""

    @staticmethod
    def _record(row) -> dict:
        rid, received, school, outcome, text, status, reviewer, reviewed_at, note, kind, inds = row
        if isinstance(inds, str):
            inds = json.loads(inds)
        by_kind = {key: sorted(i["value"] for i in inds if i["kind"] == k) for key, k, _ in _KINDS}
        rec = {"id": str(rid), "received": received.replace(microsecond=0).isoformat(), "school": school,
               "outcome": outcome, "text_masked": text, "indicators": by_kind, "status": status, "kind": kind}
        if reviewer:
            rec.update({"reviewer": reviewer, "note": note or "",
                        "reviewed_at": reviewed_at.replace(microsecond=0).isoformat()})
        return rec

    def list_reports(self, status: str = "reported", school: str = "") -> List[dict]:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(self._REPORT_SQL, {"status": status or "", "school": school or "", "since": ""})
            return [self._record(r) for r in cur.fetchall()]

    def decide_report(self, report_id, decision: str, reviewer: str, note: str = "", real: bool = False) -> dict:
        _check_decision(decision, reviewer)
        reviewer, note = reviewer.strip()[:80], (note or "").strip()[:500]
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("UPDATE reports SET status = %s, reviewer = %s, reviewed_at = now(), note = %s "
                        "WHERE id = %s AND status = 'reported' RETURNING school_id, text_masked, coalesce(kind, 'report')",
                        (decision, reviewer, note, int(report_id)))
            row = cur.fetchone()
            if row is None:
                raise ValueError(f"report {report_id} doesn't exist or was already reviewed")
            school, text, kind = row
            if decision == "confirmed":
                cur.execute("UPDATE indicators SET status = 'confirmed', confirmed_by = %s, confirmed_at = now() "
                            "WHERE status = 'reported' AND id IN "
                            "(SELECT indicator_id FROM report_indicators WHERE report_id = %s)",
                            (reviewer, int(report_id)))
                if text:
                    cur.execute("INSERT INTO labels (label, description, source, report_id, school_id, reviewer) "
                                "VALUES ('scam', %s, %s, %s, %s, %s)",
                                (text, _label_source(kind, "scam"), int(report_id), school, reviewer))
            elif real and text:                         # the reviewer says it's a real job: a "legit" training label
                cur.execute("INSERT INTO labels (label, description, source, report_id, school_id, reviewer) "
                            "VALUES ('legit', %s, %s, %s, %s, %s)",
                            (text, _label_source(kind, "legit"), int(report_id), school, reviewer))
            cur.execute(self._REPORT_SQL.replace("WHERE (", "WHERE r.id = %(id)s AND ("),
                        {"id": int(report_id), "status": "", "school": "", "since": ""})
            return self._record(cur.fetchone())

    def confirmed_reports(self, since: str = "", school: str = "") -> List[dict]:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(self._REPORT_SQL, {"status": "confirmed", "school": school or "", "since": since or ""})
            return [self._record(r) for r in cur.fetchall()]

    def add_case(self, record: dict) -> None:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO cases (case_hash, school_id, opened_on, band, score, rules, model_flag) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s) ON CONFLICT DO NOTHING",
                        (record["case"], self._school(cur, record.get("school", "")), record["date"], record["band"],
                         record["score"], record.get("rules", []), record.get("model_flag", False)))

    def add_outcome(self, record: dict) -> bool:
        try:
            with self._conn() as conn, conn.cursor() as cur:
                cur.execute("INSERT INTO outcomes (case_hash, answered_on, happened, verified) VALUES (%s, %s, %s, %s)",
                            (record["case"], record["date"], record["happened"], record.get("verified", "")))
            return True
        except self._psycopg.errors.ForeignKeyViolation:
            return False                                # no such case code

    def cases(self) -> List[dict]:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT case_hash, opened_on, coalesce(school_id, ''), band, score, rules, model_flag FROM cases")
            return [{"case": c, "date": d.isoformat(), "school": s, "band": b, "score": sc, "rules": list(r),
                     "model_flag": m} for c, d, s, b, sc, r, m in cur.fetchall()]

    def confirmed_matches(self, indicators: dict) -> List[dict]:
        pairs = [(kind, v) for key, kind, _ in _KINDS for v in indicators.get(key, [])]
        if not pairs:
            return []
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("""
                SELECT i.kind::text, i.value, count(DISTINCT r.id) FILTER (WHERE r.status = 'confirmed'),
                       count(DISTINCT s.school_id),
                       count(DISTINCT s.school_id) FILTER (WHERE s.seen_at > now() - interval '7 days'),
                       min(i.first_seen)::date, max(i.last_seen)::date
                FROM indicators i
                JOIN unnest(%s::text[], %s::text[]) AS q(kind, value) ON q.kind = i.kind::text AND q.value = i.value
                LEFT JOIN report_indicators ri ON ri.indicator_id = i.id
                LEFT JOIN reports r ON r.id = ri.report_id
                LEFT JOIN sightings s ON s.indicator_id = i.id
                WHERE i.status = 'confirmed'
                GROUP BY i.kind, i.value""", ([k for k, _ in pairs], [v for _, v in pairs]))
            return [{"kind": k, "value": v, "reports": r, "schools": sc, "schools_7d": s7,
                     "first_seen": f.isoformat(), "last_seen": l.isoformat()} for k, v, r, sc, s7, f, l in cur.fetchall()]

    def attestation(self, company_key: str) -> Optional[dict]:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT company, company_key, email_domains, careers_url, never_text, never_chat_apps, "
                        "never_checks, never_fees FROM employer_attestations WHERE company_key = %s AND status = 'active'",
                        (company_key,))
            row = cur.fetchone()
        if not row:
            return None
        keys = ("company", "company_key", "email_domains", "careers_url", "never_text", "never_chat_apps",
                "never_checks", "never_fees")
        return {**dict(zip(keys, row)), "email_domains": list(row[2])}

    def add_attestation(self, record: dict) -> None:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("""
                INSERT INTO employer_attestations (company, company_key, email_domains, careers_url, never_text,
                    never_chat_apps, never_checks, never_fees, contact, verified_by)
                VALUES (%(company)s, %(company_key)s, %(email_domains)s, %(careers_url)s, %(never_text)s,
                    %(never_chat_apps)s, %(never_checks)s, %(never_fees)s, %(contact)s, %(verified_by)s)
                ON CONFLICT (company_key) DO UPDATE SET company = EXCLUDED.company,
                    email_domains = EXCLUDED.email_domains, careers_url = EXCLUDED.careers_url,
                    never_text = EXCLUDED.never_text, never_chat_apps = EXCLUDED.never_chat_apps,
                    never_checks = EXCLUDED.never_checks, never_fees = EXCLUDED.never_fees,
                    contact = EXCLUDED.contact, verified_by = EXCLUDED.verified_by, verified_at = now(),
                    status = 'active'""",
                {"careers_url": None, "contact": None, "never_text": False, "never_chat_apps": False,
                 "never_checks": True, "never_fees": True, **record})

    def outcomes(self) -> List[dict]:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT case_hash, answered_on, happened, verified FROM outcomes ORDER BY answered_on, id")
            return [{"case": c, "date": d.isoformat(), "happened": list(h), "verified": v}
                    for c, d, h, v in cur.fetchall()]

    # ---- the learning loop (learning.py) ----

    def labels(self) -> List[dict]:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT id, label, title, company, description, source, coalesce(school_id, ''), reviewer, created_at, "
                        "split FROM labels ORDER BY id")
            return [{"id": str(i), "label": l, "title": t, "company": c, "description": d, "source": s, "school": sc,
                     "reviewer": r, "at": _epoch(at), "split": sp} for i, l, t, c, d, s, sc, r, at, sp in cur.fetchall()]

    def set_label_splits(self, splits: dict) -> None:
        """Only labels without a place get one; a place never changes."""
        if not splits:
            return
        with self._conn() as conn, conn.cursor() as cur:
            for lid, split in splits.items():
                cur.execute("UPDATE labels SET split = %s, holdout = %s WHERE id = %s AND split IS NULL",
                            (split, split == "holdout", int(lid)))

    def add_label(self, rec: dict) -> None:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO labels (label, title, company, description, source, report_id, school_id, reviewer) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                        (rec["label"], rec.get("title", ""), rec.get("company", ""), rec["description"], rec.get("source", "manual"),
                         int(rec["report_id"]) if rec.get("report_id") else None, self._school(cur, rec.get("school", "")),
                         rec["reviewer"]))

    @staticmethod
    def _signed(x: int) -> int:
        return x - 2 ** 64 if x >= 2 ** 63 else x

    def templates(self) -> List[dict]:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT id, coalesce(text_key, ''), sketch, kid, coalesce(title, ''), created_at, coalesce(school_id, '') "
                        "FROM templates WHERE status = 'active' ORDER BY id")
            return [{"key": k or f"t{i}", "sketch": sorted(x + 2 ** 64 if x < 0 else x for x in sk), "kid": kid, "title": t,
                     "when": at.date().isoformat(), "source": f"school:{sc}" if sc else "reviewer", "note": ""}
                    for i, k, sk, kid, t, at, sc in cur.fetchall()]

    def add_template(self, entry: dict) -> None:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO templates (report_id, school_id, title, sketch, kid, text_key) VALUES (%s, %s, %s, %s, %s, %s)",
                        (int(entry["report_id"]) if entry.get("report_id") else None, self._school(cur, entry.get("school", "")),
                         entry.get("title") or None, [self._signed(x) for x in entry["sketch"]], entry.get("kid", "0"), entry["key"]))

    def forget_template(self, text_key: str) -> None:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("UPDATE templates SET status = 'forgotten' WHERE text_key = %s", (text_key,))

    def save_model(self, spec: dict) -> None:
        from psycopg.types.json import Jsonb
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO models (version, spec) VALUES (%s, %s) ON CONFLICT (version) DO NOTHING",
                        (spec["version"], Jsonb(spec)))

    def get_model(self, version: str) -> Optional[dict]:
        if not version:
            return None
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT spec FROM models WHERE version = %s", (version,))
            row = cur.fetchone()
        return row[0] if row else None

    def release(self) -> dict:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(f"SELECT {', '.join(_RELEASE_COLS)} FROM model_release WHERE id = 1")
            row = cur.fetchone()
        if not row:
            return dict(RELEASE_DEFAULT)
        rec = dict(zip(_RELEASE_COLS, row))
        for k in ("created_at", "stage_started"):
            rec[k] = _epoch(rec[k])
        rec["run_id"] = str(rec["run_id"]) if rec["run_id"] is not None else None
        return rec

    def set_release(self, **kw) -> None:
        bad = set(kw) - set(_RELEASE_COLS)
        if bad:
            raise ValueError(f"unknown release fields {bad}")
        vals = []
        for k, v in kw.items():
            if k in ("created_at", "stage_started") and v is not None:
                v = dt.datetime.fromtimestamp(v, dt.timezone.utc)
            elif k == "run_id" and v is not None:
                v = int(v)
            vals.append(v)
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO model_release (id) VALUES (1) ON CONFLICT (id) DO NOTHING")   # the one row always exists
            cur.execute(f"UPDATE model_release SET {', '.join(k + ' = %s' for k in kw)} WHERE id = 1", vals)

    def log_release(self, event: str, version: Optional[str], detail: str = "") -> None:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO release_log (event, version, detail) VALUES (%s, %s, %s)", (event, version, detail[:2000]))

    def release_log(self, limit: int = 20) -> List[dict]:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT at, event, version, detail FROM release_log ORDER BY id DESC LIMIT %s", (limit,))
            return [{"at": _epoch(a), "event": e, "version": v, "detail": d} for a, e, v, d in cur.fetchall()]

    def start_run(self, trigger: str, live_labels: int = 0) -> str:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO retrain_runs (trigger, live_labels) VALUES (%s, %s) RETURNING id", (trigger, live_labels))
            return str(cur.fetchone()[0])

    def finish_run(self, run_id, **kw) -> None:
        cols = [k for k in ("status", "version", "train_rows", "report") if k in kw]
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(f"UPDATE retrain_runs SET finished_at = now(){''.join(', ' + c + ' = %s' for c in cols)} WHERE id = %s",
                        [kw[c] for c in cols] + [int(run_id)])

    _RUN_SQL = "SELECT id, started_at, trigger, status, version, live_labels, train_rows, report FROM retrain_runs"

    @staticmethod
    def _run(row) -> dict:
        i, at, trig, st, v, live, rows, rep = row
        return {"id": str(i), "started_at": _epoch(at), "trigger": trig, "status": st, "version": v, "live_labels": live,
                "train_rows": rows, "report": rep}

    def runs(self, limit: int = 20) -> List[dict]:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(self._RUN_SQL + " ORDER BY id DESC LIMIT %s", (limit,))
            return [self._run(r) for r in cur.fetchall()]

    def last_run(self) -> Optional[dict]:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(self._RUN_SQL + " WHERE status IN ('candidate', 'refused') ORDER BY started_at DESC LIMIT 1")
            row = cur.fetchone()
        return self._run(row) if row else None

    def add_traffic(self, rec: dict) -> None:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO model_traffic (key, served, p, flag, novelty, other, other_p, other_flag) "
                        "VALUES (%(key)s, %(served)s, %(p)s, %(flag)s, %(novelty)s, %(other)s, %(other_p)s, %(other_flag)s)",
                        {"other": None, "other_p": None, "other_flag": None, **rec})

    def traffic(self, since: float = 0.0) -> List[dict]:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT at, key, served, p, flag, novelty, other, other_p, other_flag FROM model_traffic "
                        "WHERE at > to_timestamp(%s) ORDER BY id", (since,))
            keys = ("at", "key", "served", "p", "flag", "novelty", "other", "other_p", "other_flag")
            return [{**dict(zip(keys, r)), "at": _epoch(r[0])} for r in cur.fetchall()]

    def prune_traffic(self, before: float) -> None:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM model_traffic WHERE at < to_timestamp(%s)", (before,))

    # ---- a career center's own lists (guardrails.py) ----

    def school_rules(self, school: str) -> List[dict]:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT kind, value, reason, added_by, added_at FROM school_rules WHERE school_id = %s AND status = 'active' "
                        "ORDER BY id", (school,))
            return [{"school": school, "kind": k, "value": v, "reason": r, "added_by": b, "added_at": _epoch(a), "status": "active"}
                    for k, v, r, b, a in cur.fetchall()]

    def add_school_rule(self, school: str, kind: str, value: str, added_by: str, reason: str = "") -> None:
        _check_rule(kind, added_by)
        with self._conn() as conn, conn.cursor() as cur:
            if self._school(cur, school) is None:
                raise ValueError(f"unknown school {school!r}")
            cur.execute("INSERT INTO school_rules (school_id, kind, value, reason, added_by) VALUES (%s, %s, %s, %s, %s) "
                        "ON CONFLICT (school_id, kind, value) WHERE status = 'active' DO NOTHING",
                        (school, kind, value, reason[:300], added_by.strip()[:80]))

    def remove_school_rule(self, school: str, kind: str, value: str, removed_by: str) -> bool:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("UPDATE school_rules SET status = 'removed', removed_by = %s, removed_at = now() "
                        "WHERE school_id = %s AND kind = %s AND value = %s AND status = 'active'",
                        (removed_by.strip()[:80], school, kind, value))
            return cur.rowcount > 0

    # ---- reviewer accounts (review_web.py) ----

    def get_report(self, report_id) -> Optional[dict]:
        try:
            rid = int(report_id)
        except (TypeError, ValueError):
            return None
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(self._REPORT_SQL.replace("WHERE (", "WHERE r.id = %(id)s AND ("),
                        {"id": rid, "status": "", "school": "", "since": ""})
            row = cur.fetchone()
            return self._record(row) if row else None

    _REVIEWER_COLS = "r.id, r.email, r.name, coalesce(r.school_id, ''), r.active, r.created_at, r.last_login"

    @staticmethod
    def _reviewer(row) -> dict:
        rid, email, name, school, active, created, last = row[:7]
        rec = {"id": str(rid), "email": email, "name": name, "school": school, "active": active,
               "created_at": _epoch(created), "last_login": _epoch(last)}
        if len(row) > 7:
            rec["pw_hash"] = row[7]
        return rec

    def add_reviewer(self, email: str, name: str, school: str, pw_hash: str) -> str:
        email, name = _check_reviewer(email, name)
        with self._conn() as conn, conn.cursor() as cur:
            if school and self._school(cur, school) is None:
                raise ValueError(f"unknown school {school!r}")
            cur.execute("INSERT INTO reviewers (email, name, school_id, pw_hash) VALUES (%s, %s, %s, %s) "
                        "ON CONFLICT (email) DO NOTHING RETURNING id", (email, name, school or None, pw_hash))
            row = cur.fetchone()
            if row is None:
                raise ValueError(f"{email} already has an account")
            return str(row[0])

    def reviewer_by_email(self, email: str) -> Optional[dict]:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(f"SELECT {self._REVIEWER_COLS}, r.pw_hash FROM reviewers r WHERE r.email = %s",
                        ((email or "").strip().lower(),))
            row = cur.fetchone()
            return self._reviewer(row) if row else None

    def reviewers(self) -> List[dict]:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(f"SELECT {self._REVIEWER_COLS} FROM reviewers r ORDER BY r.id")
            return [self._reviewer(x) for x in cur.fetchall()]

    def set_reviewer(self, email: str, pw_hash: Optional[str] = None, active: Optional[bool] = None) -> bool:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("UPDATE reviewers SET pw_hash = coalesce(%s, pw_hash), active = coalesce(%s, active) "
                        "WHERE email = %s", (pw_hash, active, (email or "").strip().lower()))
            return cur.rowcount > 0

    def touch_login(self, reviewer_id) -> None:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("UPDATE reviewers SET last_login = now() WHERE id = %s", (int(reviewer_id),))

    def add_session(self, token_hash: str, reviewer_id, expires_at: float) -> None:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM reviewer_sessions WHERE expires_at < now()")
            cur.execute("INSERT INTO reviewer_sessions (token_hash, reviewer_id, expires_at) "
                        "VALUES (%s, %s, to_timestamp(%s))", (token_hash, int(reviewer_id), float(expires_at)))

    def session_reviewer(self, token_hash: str) -> Optional[dict]:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(f"SELECT {self._REVIEWER_COLS} FROM reviewer_sessions s JOIN reviewers r ON r.id = s.reviewer_id "
                        "WHERE s.token_hash = %s AND s.expires_at > now() AND r.active", (token_hash,))
            row = cur.fetchone()
            return self._reviewer(row) if row else None

    def drop_session(self, token_hash: str) -> None:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM reviewer_sessions WHERE token_hash = %s OR expires_at < now()", (token_hash,))

    def undo_decision(self, report_id, reviewer: str, within: float) -> dict:
        try:
            rid = int(report_id)
        except (TypeError, ValueError):
            raise ValueError("no such report")
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("UPDATE reports SET status = 'reported', reviewer = NULL, reviewed_at = NULL, note = NULL "
                        "WHERE id = %s AND status <> 'reported' AND reviewer = %s "
                        "AND reviewed_at > now() - make_interval(secs => %s) RETURNING id",
                        (rid, (reviewer or "").strip()[:80], float(within)))
            if cur.fetchone() is None:
                raise ValueError("that decision can't be undone any more")
            cur.execute("UPDATE indicators i SET status = 'reported', confirmed_by = NULL, confirmed_at = NULL "
                        "WHERE i.status = 'confirmed' AND i.id IN (SELECT indicator_id FROM report_indicators WHERE report_id = %s) "
                        "AND NOT EXISTS (SELECT 1 FROM report_indicators ri JOIN reports r ON r.id = ri.report_id "
                        "WHERE ri.indicator_id = i.id AND r.status = 'confirmed')", (rid,))
            cur.execute("DELETE FROM labels WHERE report_id = %s", (rid,))
            cur.execute(self._REPORT_SQL.replace("WHERE (", "WHERE r.id = %(id)s AND ("),
                        {"id": rid, "status": "", "school": "", "since": ""})
            return self._record(cur.fetchone())

    def drop_sessions(self, reviewer_id) -> None:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("DELETE FROM reviewer_sessions WHERE reviewer_id = %s", (int(reviewer_id),))


_STORE = None


def get_store():
    """Postgres if DATABASE_URL is set, else files. Cached per process; reset_store() for tests."""
    global _STORE
    if _STORE is None:
        url = os.environ.get("DATABASE_URL", "").strip()
        _STORE = PostgresStore(url) if url else JsonlStore()
    return _STORE


def reset_store(store=None) -> None:
    global _STORE
    _STORE = store
