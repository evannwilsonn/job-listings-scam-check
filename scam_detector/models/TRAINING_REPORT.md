# Model training report (2026-10-22)

Trained on 325 rows (88 scam, 192 legit, 45 lead-gen) in 324 template groups, plus 528 adversarial copies of the training scams at 0.3 weight. Dropped 0 training rows that near-copied a holdout or hard-legit row.
Threshold 0.69 (lowest that flags no rules-quiet legit row in cross-validation, plus a 0.1 margin). Model format 2: rules, words and phrases, pieces of words, and the shape of the text.

| Set | Scams caught | Legit wrongly flagged | Lead-gen called scam |
|---|---|---|---|
| Cross-validation, rules + model | 77/88 | 1/192 | 2/45 |
| Holdout, rules alone | 17/28 | 1/42 | 0/10 |
| Holdout, rules + shipped model | 21/28 | 1/42 | 1/10 |
| Holdout, rules + this model | 22/28 | 1/42 | 1/10 |
|   field_2026_09_holdout.jsonl, rules alone | 12/14 | 0/16 | 0/4 |
|   field_2026_09_holdout.jsonl, rules + this model | 14/14 | 0/16 | 1/4 |
|   field_2026_10_holdout.jsonl, rules alone | 5/14 | 1/26 | 0/6 |
|   field_2026_10_holdout.jsonl, rules + this model | 8/14 | 1/26 | 0/6 |
| Hard-legit set, rules alone | 0/0 | 0/12 | - |
| Hard-legit set, rules + this model | 0/0 | 0/12 | - |

**Result: passed**

## Learned, not yet a rule

Wording the model now weighs toward scam that no rule fires on by itself. Read these; the useful ones become rules (`--propose` writes them as a proposed rulepack fragment for tools/regress.py).

| Wording | Weight | In labeled scams | In legit rows |
|---|---|---|---|
| shippers | +0.476 | 3 | 0 |
| qy | +0.476 | 3 | 0 |
| qy shippers | +0.476 | 3 | 0 |
| hi | +0.37 | 5 | 1 |
| and also | +0.345 | 5 | 1 |
| kindly | +0.325 | 16 | 1 |
| hello | +0.306 | 16 | 0 |
| to put | +0.288 | 2 | 0 |
| salary of | +0.274 | 5 | 0 |
| dollars | +0.272 | 5 | 0 |
| 000 dollars | +0.267 | 3 | 0 |
| this email | +0.266 | 4 | 0 |
| employment agreement | +0.259 | 2 | 0 |
| assistant needed | +0.259 | 4 | 0 |
| block | +0.257 | 4 | 0 |
| logo | +0.256 | 2 | 0 |
| message hi | +0.253 | 2 | 0 |
| contact our | +0.248 | 3 | 0 |
| hr department | +0.247 | 4 | 0 |
| fri | +0.245 | 3 | 0 |
| regards | +0.244 | 16 | 1 |
| message | +0.243 | 13 | 2 |
| 0000 text | +0.234 | 3 | 0 |
| i am | +0.234 | 8 | 2 |
| time job | +0.23 | 15 | 4 |

Numbers this small are a sanity check, not a measured accuracy. Add reviewer decisions with --extra and retrain.
