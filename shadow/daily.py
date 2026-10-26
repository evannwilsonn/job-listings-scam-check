"""Daily shadow test: score brand-new real postings and new scam emails with the shipped model and a candidate.

    python -m shadow.daily            # fetch new items, score, append to shadow/log.jsonl, rewrite shadow/REPORT.md

Nothing here reaches students. Sources:
  * real jobs:  BYU-Idaho Help Wanted board (university-moderated community postings)  -> label "legit (by source)"
  * scams:      University of Arizona phishing alerts, job-offer ones only (the security team publishes the email text).
                UChicago's email-scam posts were tried; recent ones show the email as an image, so they are not used.                                  -> label "scam (by source)"
Items are new to both models: anything whose source URL (or Arizona subject line) appears in the training data, listed
in shadow/train_index.json (public URLs and subject lines only, no text), is skipped. The log stores URLs and scores, never the text.
"""
from __future__ import annotations
import hashlib, html, json, re, sys, urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from scam_detector import ml                      # noqa: E402
from scam_detector.scorer import score_posting    # noqa: E402

HERE = ROOT / "shadow"
SEEN, LOG, REPORT, INDEX = HERE / "seen.json", HERE / "log.jsonl", HERE / "REPORT.md", HERE / "train_index.json"
UA = {"User-Agent": "Mozilla/5.0 (LureCheck shadow test)"}
JOBWORDS = re.compile(r"(?i)(job offer|\bjobs?\b|position|hiring|part[- ]time|assistant|\bintern|salary|per hour|/hr\b|"
                      r"weekly pay|\$\s?\d[\d,]*\s*(?:weekly|per week|a week|/week|daily|per day)|tutor|shopper|research assistant|"
                      r"recruit|work from home|remote (?:job|work|position|role)|vacanc|freelance|stipend)")

def fetch(url: str) -> str | None:
    try:
        return urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=30).read().decode("utf-8", "replace")
    except Exception as e:                                  # noqa: BLE001
        print("fetch failed", url, str(e)[:80]); return None

def text_of(h: str) -> str:
    h = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", h)
    t = html.unescape(re.sub(r"(?i)<br\s*/?>|</p>|</li>|</div>|</h\d>", "\n", h))
    t = html.unescape(re.sub(r"<[^>]+>", "\n", t)).replace("\xa0", " ")
    return re.sub(r"\n\s*\n+", "\n", re.sub(r"[ \t]+", " ", t)).strip()

# ---------------------------------------------------------------- sources
def byui():
    idx = fetch("https://www.byui.edu/help-wanted-postings/")
    if not idx: return
    for url in sorted(set(re.findall(r'href="(https://www\.byui\.edu/help-wanted-postings/[a-z0-9-]+)"', idx))):
        page = fetch(url)
        if not page: continue
        t = text_of(page); a = t.find("Contact Name")
        if a < 0: continue
        ends = [x for x in (t.find("Application Deadline", a), t.find("\nTags\n", a)) if x > 0]
        seg = t[a:min(ends) if ends else a + 4000]
        title = (re.search(r"Job Title\s*\n(.*)", seg) or [None, ""])[1].strip()
        company = (re.search(r"Company[^\n]*\n(.*)", seg) or [None, ""])[1].strip()
        for lab in ("Contact Name", "Contact Phone[^\n]*", "Email Address", "Address[^\n]*"):
            seg = re.sub(lab + r"\s*\n.*?\n", "", seg, count=1)
        yield {"id": "byui:" + url.rsplit("/", 1)[-1], "source": "byui", "label": "legit", "url": url,
               "title": title, "company": "" if company.upper() in ("N/A", "NA") else company, "text": seg}

def arizona():
    idx = fetch("https://security.arizona.edu/phishing_alerts")
    if not idx: return
    t = text_of(idx)
    for blk in t.split("\nDate\n")[1:]:
        lines = blk.strip().split("\n")
        head = lines[1] if len(lines) > 1 else lines[0]
        body = blk.split("External Mail", 1)[-1].split("* The University generally", 1)[0]
        if not JOBWORDS.search(head + " " + body): continue
        yield {"id": "az:" + hashlib.sha1(head.encode()).hexdigest()[:12], "source": "arizona", "label": "scam",
               "url": "https://security.arizona.edu/phishing_alerts", "title": head[:120], "company": "", "text": body.strip()}

def uchicago():
    idx = fetch("https://security.uchicago.edu/category/phishing/")
    if not idx: return
    for url in sorted(set(re.findall(r'href="(https://security\.uchicago\.edu/\d{4}/\d\d/\d\d/email-scam-[^"]+)"', idx))):
        page = fetch(url)
        if not page: continue
        t = text_of(page)
        m = re.search(r"Subject\s*\n\s*:\s*(.*)\n", t)
        if not m: continue
        body = t[m.end():].split("security@uchicago.edu", 1)[0]
        if not JOBWORDS.search(m.group(1) + " " + body): continue
        yield {"id": "uc:" + url.rstrip("/").rsplit("/", 1)[-1][:80], "source": "uchicago", "label": "scam", "url": url,
               "title": m.group(1).strip()[:120], "company": "", "text": body.strip()}

# ---------------------------------------------------------------- scoring
def main() -> int:
    seen = set(json.loads(SEEN.read_text())) if SEEN.exists() else set()
    idx = json.loads(INDEX.read_text()) if INDEX.exists() else {"urls": [], "arizona_subjects": []}
    known_urls, known_az = set(idx["urls"]), set(idx["arizona_subjects"])
    shipped = ml.load(ROOT / "scam_detector" / "models" / "scam_model.json")
    cand = ml.load(HERE / "candidate_model.json")
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    new = []
    for src in (byui, arizona):
        for it in src():
            if it["id"] in seen: continue
            seen.add(it["id"])
            if len(re.findall(r"\w+", it["text"])) < 15: continue
            if it["url"].rstrip("/") in known_urls and it["source"] != "arizona" or it["title"].strip() in known_az:
                print("skip (in training data)", it["id"]); continue
            res = score_posting(it["title"], it["text"], it["company"], run_network=False)
            row = {"date": today, "id": it["id"], "source": it["source"], "label": it["label"], "url": it["url"],
                   "title": it["title"][:100], "rules_band": res.band, "rules_flag": res.band in ("review", "block")}
            for name, m in (("shipped", shipped), ("candidate", cand)):
                p = m.predict(it["title"], it["text"], it["company"], "", res.findings, res.score)
                row[name] = {"version": m.version, "p": round(p["probability"], 3), "flag": row["rules_flag"] or p["flag"]}
            new.append(row)
    with LOG.open("a", encoding="utf-8") as f:
        for r in new: f.write(json.dumps(r, ensure_ascii=False) + "\n")
    SEEN.write_text(json.dumps(sorted(seen), indent=0))
    write_report(today, len(new))
    print(f"{len(new)} new items scored")
    return 0

def write_report(today: str, n_new: int):
    rows = [json.loads(l) for l in LOG.read_text(encoding="utf-8").splitlines() if l.strip()] if LOG.exists() else []
    def tally(name):
        sc = [r for r in rows if r["label"] == "scam"]; lg = [r for r in rows if r["label"] == "legit"]
        return (sum(r[name]["flag"] for r in sc), len(sc), sum(r[name]["flag"] for r in lg), len(lg))
    s, c = tally("shipped"), tally("candidate")
    rules_sc = sum(r["rules_flag"] for r in rows if r["label"] == "scam")
    rules_lg = sum(r["rules_flag"] for r in rows if r["label"] == "legit")
    nsc = sum(r["label"] == "scam" for r in rows); nlg = sum(r["label"] == "legit" for r in rows)
    first = rows[0]["date"] if rows else today
    L = [f"# Shadow test report", "", f"Brand-new items since {first}, last run {today} ({n_new} new today). Labels come from the source "
         "(university-moderated job board = real; university security team's published scam email = scam) and are not reviewed.", "",
         "| | Scams caught | Real jobs flagged |", "|---|---|---|",
         f"| Rules alone | {rules_sc}/{nsc} | {rules_lg}/{nlg} |",
         f"| Rules + shipped model | {s[0]}/{s[1]} | {s[2]}/{s[3]} |",
         f"| Rules + candidate model | {c[0]}/{c[1]} | {c[2]}/{c[3]} |", "",
         "## Where the two models disagree", ""]
    for r in rows:
        if r["shipped"]["flag"] != r["candidate"]["flag"]:
            who = "candidate only" if r["candidate"]["flag"] else "shipped only"
            L.append(f"- {r['date']} · {r['label']} · flagged by {who} (p {r['shipped']['p']} vs {r['candidate']['p']}) · {r['title']} · {r['url']}")
    L += ["", "## Real jobs flagged by either model", ""]
    for r in rows:
        if r["label"] == "legit" and (r["shipped"]["flag"] or r["candidate"]["flag"]):
            L.append(f"- {r['date']} · rules {r['rules_band']} · shipped {r['shipped']['p']} · candidate {r['candidate']['p']} · {r['title']} · {r['url']}")
    L += ["", "## Scams missed by both", ""]
    for r in rows:
        if r["label"] == "scam" and not (r["shipped"]["flag"] or r["candidate"]["flag"]):
            L.append(f"- {r['date']} · shipped {r['shipped']['p']} · candidate {r['candidate']['p']} · {r['title']} · {r['url']}")
    REPORT.write_text("\n".join(L) + "\n", encoding="utf-8")

if __name__ == "__main__":
    raise SystemExit(main())
