# Model training report (2026-10-22)

Trained on 360 rows (108 scam, 207 legit, 45 lead-gen) in 359 template groups, plus 648 adversarial copies of the training scams at 0.3 weight. Dropped 0 training rows that near-copied a holdout or hard-legit row.
Threshold 0.88 (lowest that flags no rules-quiet legit row in cross-validation, plus a 0.1 margin). Model format 2: rules, words and phrases, pieces of words, and the shape of the text.

| Set | Scams caught | Legit wrongly flagged | Lead-gen called scam |
|---|---|---|---|
| Cross-validation, rules + model | 84/108 | 0/207 | 3/45 |
| Holdout, rules alone | 17/28 | 0/42 | 0/10 |
| Holdout, rules + shipped model | 22/28 | 0/42 | 1/10 |
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
| ly | +0.676 | 2 | 0 |
| i am | +0.606 | 13 | 2 |
| kindly | +0.483 | 21 | 1 |
| hi | +0.452 | 9 | 1 |
| walmart | +0.43 | 4 | 1 |
| shippers | +0.425 | 3 | 0 |
| qy | +0.425 | 3 | 0 |
| qy shippers | +0.425 | 3 | 0 |
| me | +0.399 | 17 | 5 |
| hello | +0.34 | 22 | 0 |
| am a | +0.338 | 3 | 0 |
| back | +0.327 | 12 | 4 |
| hi i | +0.323 | 6 | 0 |
| usd weekly | +0.313 | 4 | 0 |
| she | +0.306 | 3 | 1 |
| the assignment | +0.303 | 2 | 0 |
| soon | +0.3 | 9 | 2 |
| the lessons | +0.291 | 3 | 0 |
| salary of | +0.285 | 6 | 0 |
| you free | +0.282 | 2 | 0 |
| dollars | +0.275 | 5 | 0 |
| 00 if | +0.275 | 3 | 0 |
| 000 dollars | +0.271 | 3 | 0 |
| assistant needed | +0.27 | 4 | 0 |
| me with | +0.27 | 4 | 0 |

Numbers this small are a sanity check, not a measured accuracy. Add reviewer decisions with --extra and retrain.
