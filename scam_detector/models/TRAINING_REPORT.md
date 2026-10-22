# Model training report (2026-10-22)

Trained on 341 rows (108 scam, 188 legit, 45 lead-gen) in 340 template groups, plus 648 adversarial copies of the training scams at 0.3 weight. Dropped 0 training rows that near-copied a holdout or hard-legit row.
Threshold 0.88 (lowest that flags no rules-quiet legit row in cross-validation, plus a 0.1 margin). Model format 2: rules, words and phrases, pieces of words, and the shape of the text.

| Set | Scams caught | Legit wrongly flagged | Lead-gen called scam |
|---|---|---|---|
| Cross-validation, rules + model | 83/108 | 0/188 | 2/45 |
| Holdout, rules alone | 17/28 | 0/42 | 0/10 |
| Holdout, rules + shipped model | 21/28 | 0/42 | 1/10 |
| Holdout, rules + this model | 22/28 | 0/42 | 1/10 |
|   field_2026_09_holdout.jsonl, rules alone | 12/14 | 0/16 | 0/4 |
|   field_2026_09_holdout.jsonl, rules + this model | 14/14 | 0/16 | 1/4 |
|   field_2026_10_holdout.jsonl, rules alone | 5/14 | 0/26 | 0/6 |
|   field_2026_10_holdout.jsonl, rules + this model | 8/14 | 0/26 | 0/6 |
| Hard-legit set, rules alone | 0/0 | 0/12 | - |
| Hard-legit set, rules + this model | 0/0 | 0/12 | - |

**Result: passed**

## Learned, not yet a rule

Wording the model now weighs toward scam that no rule fires on by itself. Read these; the useful ones become rules (`--propose` writes them as a proposed rulepack fragment for tools/regress.py).

| Wording | Weight | In labeled scams | In legit rows |
|---|---|---|---|
| ly | +0.636 | 2 | 0 |
| i am | +0.547 | 13 | 2 |
| kindly | +0.494 | 21 | 1 |
| hi | +0.416 | 9 | 1 |
| shippers | +0.409 | 3 | 0 |
| qy | +0.408 | 3 | 0 |
| qy shippers | +0.408 | 3 | 0 |
| walmart | +0.385 | 4 | 1 |
| me | +0.368 | 17 | 5 |
| hello | +0.343 | 22 | 0 |
| and also | +0.322 | 6 | 1 |
| regards | +0.313 | 22 | 1 |
| hi i | +0.306 | 6 | 0 |
| back | +0.3 | 12 | 4 |
| am a | +0.299 | 3 | 0 |
| she | +0.29 | 3 | 1 |
| soon | +0.289 | 9 | 2 |
| possess a | +0.28 | 3 | 1 |
| the assignment | +0.279 | 2 | 0 |
| professor | +0.272 | 6 | 0 |
| remote research | +0.267 | 3 | 0 |
| hello we | +0.263 | 4 | 0 |
| the lessons | +0.26 | 3 | 0 |
| 00 if | +0.257 | 3 | 0 |
| usd weekly | +0.254 | 4 | 0 |

Numbers this small are a sanity check, not a measured accuracy. Add reviewer decisions with --extra and retrain.
