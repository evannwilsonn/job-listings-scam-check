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

The main API routes:

- `POST /analyze` scores a posting or message. Give `sender`, `sender_name` and
  `reply_to` when it came by email, and it also checks who sent it: free-mail
  "recruiters", replies that go to another domain (the hacked-.edu pattern),
  a sender domain that doesn't match the company, and look-alike or blocklisted
  links (`scam_detector/identity.py`, `scam_detector/intel/`).
- `POST /analyze-thread` reads a whole conversation and reports where it is in
  the scam playbook and the likely next ask (`scam_detector/conversation.py`).
- `POST /report` takes an anonymous report. It queues a masked copy for a
  reviewer (contacts hashed, no name or IP) and returns a summary to paste into
  reportfraud.ftc.gov plus a next step for what already happened
  (`scam_detector/reports.py`). Nothing reported reaches training or the
  cross-school network until a reviewer confirms it.

- `POST /verify-job` checks whether the job is open on the company's own job
  board (Greenhouse, Lever or Ashby), whether the recruiter's address fits the
  company, and returns a script for calling the company on a number the student
  finds themselves (`scam_detector/employer.py`). A job missing from the board
  is a note for a reviewer, never a verdict.
- `POST /recovery` turns what already happened ("I deposited the check") into
  ordered steps, most urgent first (`scam_detector/recovery.py`).
- `/analyze` with `follow_up: true` returns a case code; `POST /outcome` records
  what happened later. Only the verdict and rule ids are kept, never the text.
  `tools/outcome_report.py` reports misses and false alarms from those answers
  (`scam_detector/followup.py`).

## Database

Postgres on Neon (project `lurecheck`, AWS us-east-1, branch `production`, database `lurecheck`). The schema is in
`db/migrations/`; apply new files in order and record each in `schema_migrations`. It enforces the privacy rules
itself: email addresses and phone numbers can only be stored as hashes, report text expires
(`purge_expired_text()`, run daily), and an indicator can't be marked confirmed without a reviewer.

The app connects as a login role that is a member of `lurecheck_app` (read, insert, update; no delete, no schema
changes). Create one in the Neon console, run `GRANT lurecheck_app TO <role>;`, and put its connection string in
the server's `DATABASE_URL`, using the **pooled** string (host ends in `-pooler`). Run migrations over the
**direct** string instead (no `-pooler`), since the pooler doesn't keep session state. Never commit either. With it set, `/report`, the follow-up and the reviewer tools use
Postgres (`scam_detector/store.py`); without it they fall back to JSONL files in `scam_detector/data/` for development.
Confirming a report there also confirms its indicators and adds it to `labels` for the next retrain. Use a Neon branch to test a migration or a retrain against a copy of
production.

- The learning loop (`scam_detector/learning.py`): confirming a report adds it to the training labels and to the
  template memory, so the next copy of that script is flagged on the next check; `review_queue --set N dismissed --real`
  records a real job. `python -m scam_detector.tools.learn tick`, scheduled every 30 minutes where `DATABASE_URL` and
  the labeled corpora (`LURECHECK_DATA`) are available, retrains when the evidence calls for it and moves a new model
  through shadow, staged rollout and watch, rolling back on its own. `learn status` shows where it stands. Model files
  live in the database (migration 003), so the API always serves the active one. See `scam_detector/MODEL.md`.
- A career center's own lists (`scam_detector/guardrails.py`, `tools/school_rules.py`, migration 004): `trust` an
  employer domain it has verified, and warnings about that domain's infrastructure (new, unregistered, no mail,
  look-alike) stop counting while look-alikes of it start being flagged; `block` a domain and any check that uses it gets
  a critical finding. Trust never overrides scam evidence (text rules, confirmed contacts, partner reports, template
  matches, blocklists). Entries cover the host and its subdomains, never its parent. `/analyze` applies the list for the
  `school` it's given; `schools.json` `employer_domains` count as trusted.
- `python -m scam_detector.tools.trends --school fsu` writes the monthly trends report for a career center
  (`scam_detector/trends.py`): confirmed scams by scheme against last month, how many today's detector catches on its
  own and the scripts it still misses, how scammers made contact, confirmed domains and how many schools saw them, what
  students told the follow-up happened, and what the detector learned. Markdown, ready to forward; `--json` for a
  dashboard. Counts only reviewer-confirmed scams and names no student.
- `POST /lookup` answers "has this phone number, email, website or wallet been confirmed as a scam?" across every
  LureCheck school, and `/analyze` adds a critical finding when a message contains one
  (`scam_detector/network.py`). Only reviewer-confirmed indicators ever match.
- Employers can tell LureCheck how they recruit (`tools/attest.py`, after a reviewer confirms it with the employer).
  A message naming that employer from another domain, on a chat app it doesn't use, or asking for a check or fee it
  never asks for, gets a warning (`scam_detector/attestations.py`).
- `POST /screen-employer` gives a career-center reviewer one recommendation (hold, check, ok) when approving an
  employer, e.g. on Handshake. It never approves or rejects on its own.

- `web/embed.js` puts the checker on a career center's own site with one script tag
  (`data-api`, `data-school`). Results are tiered (clear, caution, review, block); likely scams get "I already
  replied" (recovery steps) and "Report it". The API must list that site in `ALLOWED_ORIGINS`; cross-origin access is
  off by default.
- Rules marked `"private": true` run only in the API and are left out of the public page, so a scammer testing
  scripts against the page can't see them. `tools/tuning_watch.py` reports how often they were the only reason a
  scam was flagged; a jump means someone is tuning against the page.
- `tools/abuse_reports.py` drafts takedown emails per registrar (RDAP lookup) for confirmed scam domains. It never
  sends anything.

Reports go to a reviewer before they go anywhere: `tools/review_queue.py` marks
each one confirmed or dismissed, and `tools/export_evidence.py` packages the
confirmed indicators (domains and wallets in the clear, contacts hashed) with a
plain-text summary for abuse desks, a campus bank or IC3.

`.github/workflows/ct-watch.yml` runs `scam_detector/tools/ct_watch_run.py` every
Monday for the schools in `scam_detector/schools.json` and keeps the look-alike
domain report as a downloadable artifact. `scam_detector/tools/import_reports.py`
turns public scam reports you've saved into rows for `mine_candidates.py`.

The labeled evaluation sets are not in this public repo, because they contain
real people's contact details. So `scam_detector/tools/regress.py`,
`scam_detector/tools/evaluate.py` and `scam_detector/tools/train_model.py` need
your own JSONL files in `scam_detector/data/`. The format is in
`BUILDING_A_CORPUS.md`.

## How the browser page stays in sync

Python is the engine of record: the ML model, the evaluation tooling and the
network enrichment only exist there. The browser page is a second
implementation of the rule matcher, scorer and lead-gen heuristics, kept
because it lets the page run with nothing leaving the browser. Two things stop
the two from drifting apart:

- `index.html` is a build output. `tools/build_web.py` assembles it from
  `web/page.html` (markup and UI), `web/engine.js` (the matcher, scorer and
  lead-gen port) and `scam_detector/rulepack/core.json` (the rules). Edit those
  and rebuild; never edit `index.html` by hand. `--check` fails when the built
  file is stale, and CI runs it.
- `tools/parity.py` runs every case in `tests/fixtures/parity_cases.jsonl`
  through both engines (Node for the JS side) and diffs score, band, findings
  and lead-gen output. The fixtures must hit every active rule, so a rule with
  no parity case fails the test suite. Add a fixture with every new rule.

```bash
python tools/build_web.py        # rebuild index.html
python tools/parity.py           # diff Python vs browser engine (needs node)
python tools/parity.py --show fake_check_mule
```

Message-mode checks on the page (sender and link findings) have no Python twin
yet, so they are browser-only and sit outside the parity gate.

## Keeping the page in step with the engine

The page carries its own copy of the rulepack and the model. `tools/build_web.py`
assembles `index.html` from `web/page.html`, `web/engine.js`, the rulepack and the
model (`scripts/build_page.py` is an alias for it). After changing a rule,
the engine or the page, or retraining, run:

```bash
python tools/build_web.py
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
