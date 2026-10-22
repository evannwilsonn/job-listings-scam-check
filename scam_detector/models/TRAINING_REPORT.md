# Model training report (2026-10-22)

Trained on 306 rows (88 scam, 173 legit, 45 lead-gen) in 305 template groups, plus 528 adversarial copies of the training scams at 0.3 weight. Dropped 0 training rows that near-copied a holdout or hard-legit row.
Threshold 0.73 (lowest that flags no rules-quiet legit row in cross-validation, plus a 0.1 margin). Model format 2: rules, words and phrases, pieces of words, and the shape of the text.

| Set | Scams caught | Legit wrongly flagged | Lead-gen called scam |
|---|---|---|---|
| Cross-validation, rules + model | 75/88 | 0/173 | 2/45 |
| Holdout, rules alone | 17/28 | 0/42 | 0/10 |
| Holdout, rules + shipped model | 21/28 | 0/42 | 1/10 |
| Holdout, rules + this model | 21/28 | 0/42 | 1/10 |
|   field_2026_09_holdout.jsonl, rules alone | 12/14 | 0/16 | 0/4 |
|   field_2026_09_holdout.jsonl, rules + this model | 14/14 | 0/16 | 1/4 |
|   field_2026_10_holdout.jsonl, rules alone | 5/14 | 0/26 | 0/6 |
|   field_2026_10_holdout.jsonl, rules + this model | 7/14 | 0/26 | 0/6 |
| Hard-legit set, rules alone | 0/0 | 0/12 | - |
| Hard-legit set, rules + this model | 0/0 | 0/12 | - |

**Result: passed**

## Learned, not yet a rule

Wording the model now weighs toward scam that no rule fires on by itself. Read these; the useful ones become rules (`--propose` writes them as a proposed rulepack fragment for tools/regress.py).

| Wording | Weight | In labeled scams | In legit rows |
|---|---|---|---|
| shippers | +0.465 | 3 | 0 |
| qy | +0.464 | 3 | 0 |
| qy shippers | +0.464 | 3 | 0 |
| hi | +0.361 | 5 | 1 |
| and also | +0.33 | 5 | 1 |
| kindly | +0.297 | 16 | 1 |
| hello | +0.285 | 16 | 0 |
| to put | +0.276 | 2 | 0 |
| assistant needed | +0.27 | 4 | 0 |
| receive a | +0.269 | 5 | 0 |
| salary of | +0.268 | 5 | 0 |
| this email | +0.263 | 4 | 0 |
| dollars | +0.252 | 5 | 0 |
| contact our | +0.251 | 3 | 0 |
| 000 dollars | +0.249 | 3 | 0 |
| employment agreement | +0.248 | 2 | 0 |
| logo | +0.246 | 2 | 0 |
| block | +0.246 | 4 | 0 |
| hr department | +0.244 | 4 | 0 |
| fri | +0.241 | 3 | 0 |
| participate please | +0.233 | 3 | 0 |
| no time | +0.233 | 3 | 1 |
| of $0 | +0.232 | 3 | 1 |
| message | +0.23 | 13 | 2 |
| i am | +0.223 | 8 | 2 |

Numbers this small are a sanity check, not a measured accuracy. Add reviewer decisions with --extra and retrain.
