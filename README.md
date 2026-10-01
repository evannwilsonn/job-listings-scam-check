# Job Scam Check

Paste a job posting or a recruiter's message and see whether it matches known
job-scam patterns. Open `index.html` in any browser (or serve it with GitHub
Pages). It's one file with no server: nothing you paste leaves your browser.

## What it checks

- **Posting text**: fees to start, fake checks and "send the balance back",
  money-mule work, gift-card or crypto pay, flat weekly pay for a few hours,
  instant hires, requests for SSN or bank details up front, and pushes to
  WhatsApp, Telegram or Signal.
- **Messages and emails**: official-sounding messages sent from personal
  accounts, display names that don't match the address, look-alike university
  domains, shortened links, chat-app links and links to bare IP addresses.
- **Middleman listings**: aggregator or lead-generation posts that wrap a real
  job in a signup wall. These get their own "find the employer's own posting"
  verdict instead of being called a scam.

The checker folds look-alike tricks (`T e l e g r a m`, `wh@tsapp`, hidden
characters) before matching. It also skips safe phrasing like "we will never ask
for a fee" and "SSN for payroll upon hire". Every warning shows the exact words
that triggered it.

## The Python detector

`scam_detector/` is the full engine the browser page is ported from. It covers
the rules, the scorer, lead-gen detection, enrichment (domain age, MX records,
pay vs. BLS medians, link structure), the learned second-look model and an HTTP
API.

```bash
pip install -r requirements.txt
python -m pytest -q tests
uvicorn scam_detector.api:app --reload
```

The rules are data, in `scam_detector/rulepack/core.json`. See
`scam_detector/README.md` for how scoring works and `ADAPTING.md` for adding
rules.

The labeled evaluation sets are not in this public repo, because they contain
real people's contact details. So `tools/regress.py`, `tools/evaluate.py` and
`tools/train_model.py` need your own JSONL files in `scam_detector/data/`. The
format is in `BUILDING_A_CORPUS.md`.

## Where the rules come from

The rules and checking code are the same ones the NoleCareerShield job board
uses. The version shown in the page header is the rulepack it was built from.

## Limits

A match is a reason to slow down, not proof, and a clean result can still be a
scam. Always confirm the job on the employer's own website before you share
personal details. Report job scams at https://reportfraud.ftc.gov.
