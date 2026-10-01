# Model training report (2026-09-30)

Trained on 306 rows (88 scam, 173 legit, 45 lead-gen) in 305 template groups. Dropped 0 training rows that near-copied a holdout or hard-legit row.
Threshold 0.70 (lowest that flags no rules-quiet legit row in cross-validation).

| Set | Scams caught | Legit wrongly flagged | Lead-gen called scam |
|---|---|---|---|
| Cross-validation, rules + model | 73/88 | 1/173 | 2/45 |
| Holdout, rules alone | 15/28 | 1/42 | 0/10 |
| Holdout, rules + shipped model | 19/28 | 1/42 | 0/10 |
| Holdout, rules + this model | 19/28 | 1/42 | 0/10 |
|   field_2026_09_holdout.jsonl, rules alone | 11/14 | 0/16 | 0/4 |
|   field_2026_09_holdout.jsonl, rules + this model | 13/14 | 0/16 | 0/4 |
|   field_2026_10_holdout.jsonl, rules alone | 4/14 | 1/26 | 0/6 |
|   field_2026_10_holdout.jsonl, rules + this model | 6/14 | 1/26 | 0/6 |
| Hard-legit set, rules alone | 0/0 | 0/12 | - |
| Hard-legit set, rules + this model | 0/0 | 0/12 | - |

**Result: passed**

Numbers this small are a sanity check, not a measured accuracy. Add reviewer decisions with --extra and retrain.
