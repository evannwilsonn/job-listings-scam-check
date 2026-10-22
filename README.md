# LureCheck

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

**The learned second look runs in the page too.** When the rules aren't sure, the
same model the Python engine uses (`scam_detector/models/scam_model.json`) reads
the text again. If it rates the text likely to be a scam, the result moves up to
"Be careful" with the wording that drove it. It never adds points or calls
anything a scam on its own.

The page is set up for one school (FSU by default) for its look-alike and
spoofing checks. Another school's copy sets `window.LURECHECK_SCHOOL` before
the detector script, for example
`{short: "UF", name: "University of Florida", domain: "ufl.edu", lookalikes: ["ufl", "gators"], career: "UF Career Connections Center"}`.

## The Python detector

`scam_detector/` is the full engine the browser page is ported from. It covers
the rules, the scorer, lead-gen detection, enrichment (domain age, MX records,
pay vs. BLS medians, link structure), the learned second-look model (rules,
wording, spelling and the shape of the text; adversarially trained; see
`scam_detector/MODEL.md`), a template memory of confirmed scams, and an HTTP
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

## Keeping the page in step with the engine

The page carries its own copy of the rulepack and the model, written by
`scripts/build_page.py` from the files in `scam_detector/`. After changing a
rule or retraining, run:

```bash
python scripts/build_page.py
```

The page header and footer show the rulepack and model versions it is running.
`tests/test_page.py` fails if the page's copy is out of date, if its JavaScript
model gives a different score from `ml.py`, or if its rules fire differently
from `rules.py` (the last two run the page's script in Node). CI runs the whole
suite on every push and pull request.

The rules and checking code are the same ones the LureCheck review board uses.

## Limits

A match is a reason to slow down, not proof, and a clean result can still be a
scam. Always confirm the job on the employer's own website before you share
personal details. Report job scams at https://reportfraud.ftc.gov.
