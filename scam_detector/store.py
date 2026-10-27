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
from pathlib import Path
from typing import List, Optional

DATA = Path(os.environ.get("LURECHECK_DATA", Path(__file__).resolve().parent / "data"))
DECISIONS = ("confirmed", "dismissed")
_KINDS = (("domains", "domain", False), ("wallets", "wallet", False), ("email_hashes", "email", True),
          ("phone_hashes", "phone", True))


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


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

    def decide_report(self, report_id, decision: str, reviewer: str, note: str = "") -> dict:
        _check_decision(decision, reviewer)
        rows = self._read(self.reports_path)
        r = rows[int(report_id)]
        r.update({"status": decision, "reviewer": reviewer.strip()[:80], "note": (note or "").strip()[:500],
                  "reviewed_at": _now()})
        self._write(rows)
        return r

    def confirmed_reports(self, since: str = "", school: str = "") -> List[dict]:
        return [r for r in self.list_reports("confirmed", school) if not since or r.get("received", "") >= since]

    def add_case(self, record: dict) -> None:
        self._append(self.cases_path, record)

    def add_outcome(self, record: dict) -> bool:
        self._append(self.outcomes_path, record)
        return True

    def cases(self) -> List[dict]:
        return self._read(self.cases_path)

    def outcomes(self) -> List[dict]:
        return self._read(self.outcomes_path)


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
            cur.execute("INSERT INTO reports (school_id, outcome, text_masked) VALUES (%s, %s, %s) RETURNING id",
                        (school, record.get("outcome") or None, record.get("text_masked")))
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
               r.status, r.reviewer, r.reviewed_at, r.note,
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
        rid, received, school, outcome, text, status, reviewer, reviewed_at, note, inds = row
        if isinstance(inds, str):
            inds = json.loads(inds)
        by_kind = {key: sorted(i["value"] for i in inds if i["kind"] == kind) for key, kind, _ in _KINDS}
        rec = {"id": str(rid), "received": received.replace(microsecond=0).isoformat(), "school": school,
               "outcome": outcome, "text_masked": text, "indicators": by_kind, "status": status}
        if reviewer:
            rec.update({"reviewer": reviewer, "note": note or "",
                        "reviewed_at": reviewed_at.replace(microsecond=0).isoformat()})
        return rec

    def list_reports(self, status: str = "reported", school: str = "") -> List[dict]:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(self._REPORT_SQL, {"status": status or "", "school": school or "", "since": ""})
            return [self._record(r) for r in cur.fetchall()]

    def decide_report(self, report_id, decision: str, reviewer: str, note: str = "") -> dict:
        _check_decision(decision, reviewer)
        reviewer, note = reviewer.strip()[:80], (note or "").strip()[:500]
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("UPDATE reports SET status = %s, reviewer = %s, reviewed_at = now(), note = %s "
                        "WHERE id = %s AND status = 'reported' RETURNING school_id, text_masked",
                        (decision, reviewer, note, int(report_id)))
            row = cur.fetchone()
            if row is None:
                raise ValueError(f"report {report_id} doesn't exist or was already reviewed")
            school, text = row
            if decision == "confirmed":
                cur.execute("UPDATE indicators SET status = 'confirmed', confirmed_by = %s, confirmed_at = now() "
                            "WHERE status = 'reported' AND id IN "
                            "(SELECT indicator_id FROM report_indicators WHERE report_id = %s)",
                            (reviewer, int(report_id)))
                if text:
                    cur.execute("INSERT INTO labels (label, description, source, report_id, school_id, reviewer) "
                                "VALUES ('scam', %s, 'report', %s, %s, %s)", (text, int(report_id), school, reviewer))
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

    def outcomes(self) -> List[dict]:
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute("SELECT case_hash, answered_on, happened, verified FROM outcomes ORDER BY answered_on, id")
            return [{"case": c, "date": d.isoformat(), "happened": list(h), "verified": v}
                    for c, d, h, v in cur.fetchall()]


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
