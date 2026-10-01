# Job Scam Detector

A job-posting scam detector that does the small honest version of the job:
transparent rules plus lightweight enrichment, an evaluation harness so every
claim about accuracy is a measured number, and a loop for adapting to new scam
techniques without rewriting code.

No Kafka, no GPU, no scraping. One Python service you can run on a laptop.

## What it produces

Two independent verdicts, because they are different problems:

* **Fraud score and band** (`block` / `review` / `caution` / `clear`): does this look
  like a scam? Money-mule work, fake checks, fees to start, "task" scams, ID
  requests up front, gift-card or crypto pay, off-platform pushes, and so on.
* **Lead-gen flag**: is this an aggregator wrapping a real job in a signup wall,
  affiliate redirects, or an unnamed employer? That is not fraud, and telling a
  student "treat this as a scam" would be wrong. It gets its own verdict ("find
  the employer's own posting") and never moves the fraud band.

Every finding names the exact text that matched. Every result carries the
`ruleset_version` that produced it.

## How it works

**Rules are data** (`rulepack/core.json`), not code. Each rule has phrases and/or
regex patterns, a severity, a weight, an explanation shown to the user, and the
date and source it was added. The engine (`rules.py`) adds what keyword lists
cannot:

* **Normalization**: `T e l e g r a m`, `wh@tsapp`, zero-width characters and
  look-alike letters are folded before matching.
* **Negation**: "we will never ask for a training fee" does not fire the fee rule.
  A stray "don't" cannot hide a real ask ("don't worry, you must pay a fee").
* **Post-hire context**: "Social Security number for payroll upon hire" is normal;
  "send me your SSN and a photo of your license" is not.

Other signals: domain age (RDAP), MX records, pay vs. BLS medians
(`enrichment/`), implied hourly pay ("$650 weekly for 1-2 hrs, 3 days a week"),
free-mail addresses on a named employer, and URL structure (`enrichment/url_flow.py`).

## Run it

```bash
pip install -r requirements.txt
uvicorn scam_detector.api:app --reload        # HTTP API
python -m pytest -q tests                       # 35 tests
python -m scam_detector.tools.evaluate scam_detector/data/*.jsonl --observed
python -m scam_detector.tools.regress          # the pass/fail gate
```

## Measured results, with the caveats that matter

Run `python -m scam_detector.tools.regress` for the current numbers. What each set
is, and how far to trust it:

| Set | What it is | Scam caught | False positives | Trust |
|---|---|---|---|---|
| `real_corpus_clean` | 9 real listings from the author's own LinkedIn | 3 of 3 | 0 of 2 legit | **In-sample.** Rules were developed with these visible. Lead-gen: 2 of 4 from text+URL alone, 4 of 4 with user-reported context. |
| `external_scams` | 5 excerpts of real scam messages quoted in university alerts | 3 of 5 | n/a | Real, but the author read them before writing the rules that catch them, so this is a development set, not a blind test. |
| `synthetic_scams` | 12 paraphrases of known scam families, written by the rule author | 12 of 12 | n/a | Regression only. Written by the same person as the rules; proves nothing about unseen scams. |
| `stress_legit` | 12 hard legitimate postings written to probe known false-positive patterns | n/a | 0 of 12 | Regression only. It encodes what the author thinks legitimate postings look like. |

Before this rewrite the same sets scored: real external scams 0 of 5, synthetic
scams 4 of 12, and 5 of 12 legitimate postings wrongly blocked or flagged. The old
"precision 1.000" was true only because the original test set contained no hard
legitimate posting.

**There is still no honest estimate of accuracy on unseen, real postings.** The
only way to get one is real labeled data you did not write, which is what the
review queue produces (below). Until a few hundred real labels exist, treat every
number here as a regression check, not a forecast.

## Adapting to new scam techniques

See `ADAPTING.md`. In short: reviewers' decisions on the job board become labeled
data, the miner proposes rules from the misses, the regression gate blocks any
rule that flags legitimate postings, and a person promotes what passes.
Machine-proposed rules are inert until a human promotes them, because the
postings are written by the people being defended against.

## What this is not

It only uses what a job seeker can see: posting text, the link, and public
DNS/registry data. It has no account histories, login IPs or device fingerprints,
so it cannot do account-takeover or graph analysis, and text alone cannot identify
a lead-gen listing whose tell is in the click path. Rules-based detection will
always trail new techniques by however long it takes a person to notice one;
the loop above shortens that gap, it does not remove it.
