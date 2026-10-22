# Model training report (2026-10-22)

Trained on 360 rows (108 scam, 207 legit, 45 lead-gen) in 359 template groups, plus 648 adversarial copies of the training scams at 0.3 weight. Dropped 0 training rows that near-copied a holdout or hard-legit row.
Threshold 0.92 (lowest that flags no rules-quiet legit row in cross-validation, plus a 0.1 margin). Model format 2: rules, words and phrases, pieces of words, and the shape of the text.

| Set | Scams caught | Legit wrongly flagged | Lead-gen called scam |
|---|---|---|---|
| Cross-validation, rules + model | 83/108 | 0/207 | 2/45 |
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
| ly | +0.673 | 2 | 0 |
| i am | +0.58 | 13 | 2 |
| kindly | +0.505 | 21 | 1 |
| shippers | +0.422 | 3 | 0 |
| qy | +0.421 | 3 | 0 |
| qy shippers | +0.421 | 3 | 0 |
| hi | +0.416 | 9 | 1 |
| walmart | +0.402 | 4 | 1 |
| me | +0.401 | 17 | 5 |
| hello | +0.351 | 22 | 0 |
| regards | +0.335 | 22 | 1 |
| and also | +0.33 | 6 | 1 |
| back | +0.329 | 12 | 4 |
| soon | +0.305 | 9 | 2 |
| hi i | +0.303 | 6 | 0 |
| she | +0.303 | 3 | 1 |
| the assignment | +0.301 | 2 | 0 |
| am a | +0.297 | 3 | 0 |
| professor | +0.291 | 6 | 0 |
| the lessons | +0.29 | 3 | 0 |
| remote research | +0.28 | 3 | 0 |
| possess a | +0.276 | 3 | 1 |
| 00 if | +0.268 | 3 | 0 |
| hope | +0.266 | 3 | 1 |
| you free | +0.265 | 2 | 0 |

Numbers this small are a sanity check, not a measured accuracy. Add reviewer decisions with --extra and retrain.
