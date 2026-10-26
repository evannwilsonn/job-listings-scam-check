# Daily shadow test

Scores brand-new items with the shipped model (`scam_detector/models/scam_model.json` on `main`) and a candidate
(`shadow/candidate_model.json`), using whatever rules are on `main` that day. Nothing here reaches students.

- `daily.py` fetches new BYU-Idaho Help Wanted postings (real, by source) and new job-offer emails from the University of
  Arizona phishing alerts (scam, by source), skips anything already in the training data (`train_index.json`: public URLs
  and subject lines only), and appends scores to `log.jsonl` (URLs and scores, never the text).
- `REPORT.md` is the running tally: scams caught and real jobs flagged by rules alone, rules + shipped, rules + candidate,
  plus the items where the two models disagree.
- Labels come from the source and are not reviewed; anything listed under "Real jobs flagged" or "Scams missed" deserves a
  human look before it counts.
- The current candidate (`646883f96e34`) was refused by the release gate (2/12 hard-legit flagged) and is trained on
  unconfirmed 2026-10-24 labels. It is here to be measured, not shipped.

Run by a daily scheduled task: check out `main`, take `shadow/` from this branch, run `python -m shadow.daily`, commit the
updated `seen.json`, `log.jsonl` and `REPORT.md` back to this branch.
