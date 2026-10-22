# The learned layer

The rules (`rulepack/`, `rules.py`, `scorer.py`) are still the detector. On top of them sits a small
machine-learning model that reads the same evidence a reviewer would and asks: does this look like the
scams we've labeled?

## How it works

- **Model (format 2):** logistic regression over four kinds of input:
  1. which rules fired, plus their total score, so it learns how much each rule should really count;
  2. the words and two-word phrases in the posting (TF-IDF), so it picks up wording no rule covers yet;
  3. pieces of each word, 3 to 5 letters (TF-IDF), so `ch3que`, `whats app` and `cheque` still look like what they are
     after the normalizer has done what it can;
  4. the shape of the text, 24 traits a reviewer notices before reading a rule: how much it talks to "you", whether it
     lists requirements and benefits, shouting, emoji, money mentions, pay talk with no amount, a free-mail address, a
     named legal entity, and so on (`ml.SHAPE`). The largest learned weights are *lists requirements* (toward legit) and
     *written at "you"* (toward scam).
  Format-1 files (rules + words) still load.
- **Adversarial training:** every training scam is also seen rewritten the way a filter-dodging scammer would (the
  offline tricks in `tools/redteam.py`: synonyms, leetspeak, zero-width characters, a polite tone, no dollar amounts),
  at 0.3 of the original's weight. The copies are made from training rows only, inside each cross-validation fold, so
  the frozen holdouts and `data/redteam_eval.jsonl` stay unseen.
- **Training:** `python -m scam_detector.tools.train_model`. It needs scikit-learn (`requirements-dev.txt`).
  The site itself doesn't: `ml.py` does the inference in plain Python from one JSON file,
  `models/scam_model.json`. The static page in this repo (`index.html`) runs the rules only, not the model;
  the model is served through the HTTP API.
- **Data:** every labeled corpus in `data/` except the frozen holdout, plus the synthetic scams at half
  weight, plus reviewer decisions: `python export_labeled.py --db jobs.db -o labeled.jsonl`, then
  `train_model --extra labeled.jsonl`. Near-copies of the same template share one example's weight.
- **Explanations:** a finding names the rules, phrases and traits that pushed the score up; the many tiny word-piece
  contributions are rolled into one line, "spelling of the words".

## What it is allowed to do

It only escalates, and only when the rules were quiet (band `clear` or `caution`):

| Where | What the model can do |
|---|---|
| A listing submitted to the board | Status `clear` → `flagged`, with the note "Worth a second look" |
| Public listing check | "No known scam signs" → "Be careful" |

It never lowers a rule verdict, never rejects or blocks anything, and always says why: the rules and
phrases that pushed it up. Switch it off with `SCAM_MODEL=off`. With no model file, the site runs on rules
alone.

**Messages are out of scope for now.** Every legit example it has learned from is a job listing, so it has
never seen a real recruiter email. The message check stays rules-only until legit messages are labeled.

**Collection leftovers are stripped** before any text reaches it: redaction placeholders, email header
labels like "From:" and "Subject:", and URL schemes. Otherwise it learns "archived email = scam".

## When a model ships

A model now reaches students in stages (`release.py`, see "Releases" below). The first stage is `train_model`'s own gate:
it writes a candidate only if all of these hold:

1. On the frozen holdouts (`data/field_2026_09_holdout.jsonl` and `field_2026_10_holdout.jsonl`, never trained on), rules + model catch more
   scams than the rules alone, and no fewer than the model currently shipped.
2. There are no new false alarms: no legit listing the rules leave alone gets flagged, on the holdout or on
   the hard-legit set (`data/stress_legit.jsonl`, also never trained on).

The threshold comes from cross-validation on the training rows: the lowest value that flags no rules-quiet legit row, plus a
0.1 margin because those rows are few, and never below 0.5. Every run writes `models/TRAINING_REPORT.md`.

## How it keeps learning (learning.py)

The loop runs on the live site. Nobody has to remember to retrain.

1. **Labels:**
   - Reviewers label board listings when they approve or reject them.
   - Anything sent in from the scam check ("Send this to our reviewers") lands in the **label queue**
     (`/admin/checks`). A reviewer confirms Scam, Real, Lead-gen or Skip there.
   - A visitor's answer is shown but never used on its own, so nobody can poison the model by spamming
     "not a scam".
2. **Scam waves:** a sent-in item that near-copies one from the last 30 days joins its wave. The reviewer sees
   "Wave: N near-copies", and one click labels the whole wave. Earlier decisions on the same wave are shown.
3. **New patterns:** when the AI second opinion is confident it's a scam but the rules were quiet, the student
   is asked to send it in (nothing is saved without that click). It reaches the queue tagged "AI flagged a
   pattern the rules missed".
4. **Rolling holdout:** the first time a confirmed label is used, about 1 in 3 go to the live holdout (whole
   waves together) and the rest to training. A label never moves after that. Every retrain is tested on
   the repo holdouts and on this live holdout, so a model has to handle this month's scams, not only
   September's.
5. **Retrain triggers:** monthly once `RETRAIN_MIN_NEW` (20) distinct new labels exist; early when
   `RETRAIN_EVIDENCE_MIN` (30) distinct new labels arrive or a reviewer confirms an investigation case with at
   least 3 distinct reports; never more often than `RETRAIN_MIN_GAP_DAYS` (3), and not while a release is in
   progress. "Distinct" means a scam wave counts once, and a wave adds at most `RETRAIN_WAVE_CAP` (3) training rows,
   so label-all on a big wave can't dominate. Exported rows carry who labeled them and why.
   - A retrain produces a candidate (`learning/models/candidate.json`); the active model keeps serving.
   - The active model is `learning/models/scam_model.json` next to the database; it takes over from the repo model
     once a candidate completes a release.
   - Every run, with its full report, is on `/admin/model`, which also has a "Retrain now" button.
   - A full retrain takes about 20 seconds.

`export_labeled.py` includes confirmed label-queue items, with email addresses and phone numbers masked.

## Releases (release.py)

1. **Release gate**, against the active model, on data the candidate never trained on:
   - recent confirmed scams (the live holdout, last 120 days): catches more, or all of them if the active model does;
   - false alarms over every legitimate item: at most `RELEASE_FP_MAX_RATE` (2%) and none the active model doesn't make;
   - older techniques (the frozen holdouts): loses nothing;
   - legitimate but unusual employers (`stress_legit.jsonl`): no new flags;
   - held-out scam campaigns (whole waves are held out together): loses no campaign the active model catches;
   - red-team regression variants (`redteam_regression.jsonl`): catches at least as many.
2. **Shadow** (`RELEASE_SHADOW_DAYS`, 7): scores every listing check alongside the active model; nothing it says is shown.
3. **Rollout** (`RELEASE_STAGES` 10,50,100 percent, `RELEASE_STAGE_DAYS` 3 each): a stable slice of listings (by text hash)
   is served by the candidate.
4. **Watch** (`RELEASE_WATCH_DAYS`, 14): the old model is kept and restored automatically if the new one does worse.

Every step needs at least `RELEASE_FRESH_MIN` (5) labels confirmed after the candidate was built (so it never saw
them) showing it isn't worse, and in shadow at least `RELEASE_TRAFFIC_MIN` (30) listing checks compared. It stops
and rolls back as soon as it catches fewer fresh confirmed scams, flags more fresh confirmed-real items, or flags
real traffic far more often than the active model (over twice its rate and 5 points above it).
`MODEL_AUTO_RELEASE=0` makes each step wait for a reviewer; rollback is always automatic. Every step is in
`release_log` and on `/admin/model`.

## Uncertainty (conformal prediction)

Training also stores class-conditional conformal values (`"conformal"` in the model file), computed from the
cross-validation probabilities so each class keeps about 90% coverage on its own. `predict()` returns the set of
labels that can't be ruled out, and `uncertain` when that set disagrees with the threshold (a scam it can't rule
out while the threshold says no flag). Uncertain cases don't change any verdict; they go first in the label queue
and count toward the drift alert on `/admin/intel`.

## Red team

`python -m scam_detector.tools.redteam` rewrites the holdout and archive scams the way a scammer dodging filters
would (synonyms, leetspeak, zero-width characters, a friendly tone, no dollar amounts; `--ai` adds AI paraphrases)
and writes `models/REDTEAM_REPORT.md`. The variants in `data/redteam_eval.jsonl` are an evaluation set only and are
never trained on. First run: leetspeak and zero-width tricks are all still caught; removing dollar amounts and
"every 7 days" instead of "weekly" slip past rules that catch the original.

## Template memory (memory.py): learning in minutes, not months

Retraining is monthly, but a reviewer's decision protects the next student at once. Every scam a reviewer confirms is
kept as a sketch of its wording (128 hashed word-trigrams; the text itself is not stored). A new check whose wording
matches a remembered scam at 60% or more gets `confirmed_scam_template` (warning, 20 points: sent to a person), and at
90% or more `confirmed_scam_copy` (critical, 30 points). A "legit" label or an undo on the same text forgets it, so a
mistaken label cannot keep flagging real listings. The store is `learning/templates.jsonl` next to the database
(`SCAM_MEMORY_PATH`), and the identifier memory in `defense.py` works the same way for emails, numbers and wallets.

## Drift (drift.py): noticing when the world moved

For every listing check the site records the model's probability and the share of the text's words the model has
never seen (novelty), never the text. The model file carries the same two distributions over its training rows
(`drift_ref`, out-of-fold). Each week's traffic is compared with them as a Population Stability Index; a PSI of 0.25
or more, or mean novelty 15 points above training, raises a drift alert on `/admin/intel`, shows on `/admin/model`,
and brings the next retrain forward (`learning.due_detail`, trigger `drift`, still subject to the minimum gap and
`RETRAIN_MIN_NEW` new labels). Drift never ships a model by itself; the release gate still decides.

## From model to rules

Every training run ends with a "Learned, not yet a rule" table: wording the model weighs toward scam that no rule fires
on by itself, with how many labeled scams and legit rows contain it. `train_model --propose proposed.json` writes those
as a rulepack fragment with status `proposed` (inert), for the same review and regression gate as
`tools/mine_candidates.py`: `python -m scam_detector.tools.regress --candidate proposed.json`, then `--promote`
after a person marks each rule reviewed. The model finds the wording; a person decides what becomes a rule.

## Status (Oct 22, 2026): shipped, version in models/scam_model.json

| Run | Training rows | Holdout scams caught (rules alone: 17/28) | New false alarms | Gate |
|---|---|---|---|---|
| 1 | 115 | 13/14 on the Sept holdout | camp counselor job | refused |
| 2 | 207 (+ October field batch) | 19/28 | none | shipped |
| 3 | 306 (+ 99 LinkedIn/Indeed/ZipRecruiter/Glassdoor listings) | 19/28 | none | shipped |
| 4 | 306 + 528 adversarial copies, format 2 | **21/28** | none | **shipped (current)** |

- **Run 1** had learned "weekly pay alone = scam". It was fixed with 29 real weekly-pay jobs; see
  `data/FIELD_TEST_2026_10.md`.
- **Run 3** first raised its threshold to 0.90 and caught fewer scams, so the gate refused it. The cause
  was a real rule bug: `personal_channel` fired on an Indeed employer's anti-scam disclaimer, and the
  model learned to distrust the rule. After the rule fix (see `data/BOARDS_2026_10.md`) it passed at
  threshold 0.70.
- **Run 4** (format 2) was first refused: at the lowest cross-validated threshold (0.68) it flagged the camp counselor
  job in the hard-legit set, which the gate exists to catch. The threshold now carries a 0.1 margin above the lowest
  safe value (0.73); at that setting it catches all 14 September holdout scams and 7/14 October ones, with no new false
  alarm. In grouped cross-validation the shape and word-piece features lifted the model-only catches from 7 to 16 of
  the 88 training scams, and red-team variants caught from 418 to 477 of 528. Red-team on the holdouts: originals
  caught 26/33 (was 24/33); rewrites 25 to 27/33 per trick (was 24 to 25).

Where the gain comes from: learned weights on the rules, and now the shape of the text. Combinations of weak signals
that add up to less than the rules' review threshold are still scams. The phrase features count for little until there
are a few hundred more scam rows. Live job boards yield almost no scams (they're removed fast), so
reviewer decisions from the board and scam archives stay the main scam sources.
