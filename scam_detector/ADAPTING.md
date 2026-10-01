# Keeping the detector current

Scam techniques change faster than any fixed rule list. This is the loop that
lets the detector change with them, and the guardrails that stop the loop from
making it worse or from being steered by attackers.

```
  reviewers decide           export             mine             gate            promote
 (approve / reject:     labeled.jsonl  -->  proposed.json  -->  regress.py  -->  core.json
  scam, aggregator,          |                  |                   |               |
  other; remove)            mask PII         status: proposed    zero new false    version bump,
                                             (inert)             positives, no     baseline
                                                                 recall drops      re-recorded
```

## The routine

1. **Review as normal.** On the job board, rejecting or removing a listing asks
   *why*: scam, aggregator, or other. Approving records "legit". Those choices are
   the labels. The queue header shows how often the detector agreed with you and how
   many it missed.
2. **Export monthly** (rejected and removed rows are purged after 90 days). Do this in your working copy with a copy of the database, not inside the deployed container, and redeploy after committing changes to `core.json`:

   ```bash
   python export_labeled.py --db /data/jobs.db -o labeled.jsonl
   ```

   Employer contact fields are never exported; emails and phone numbers in the
   text are masked.
3. **Mine the misses:**

   ```bash
   python -m scam_detector.tools.mine_candidates labeled.jsonl scam_detector/data/*.jsonl -o proposed.json
   ```

   It proposes phrases that appear in at least two missed bad postings and in no
   legitimate posting. With few labels it proposes little; that is correct.
4. **Read and edit every proposal.** Related phrases from the same postings arrive
   grouped as one rule. Delete any phrase that could appear in an honest posting
   (the gate only knows the honest postings in the corpora, so it cannot catch a
   phrase like "complete identity verification" that honest onboarding emails also
   use). Prefer replacing phrases with a regex that captures the *behavior* (see
   `task_scam` and `advance_fee` in `rulepack/core.json`), because scammers reword
   phrases but not the ask. Then set the weight yourself: the default of 20 only
   yields `caution`, which the job board treats as clear. A technique that is only
   ever a scam should be weight 36+ (or critical). Finally set `"reviewed": true` on
   each rule you approve; `--promote` refuses rules without it.
5. **Gate it:**

   ```bash
   python -m scam_detector.tools.regress --candidate proposed.json
   ```

   It fails if the candidate flags any legitimate posting in any corpus or lowers
   scam recall on any of them.
6. **Promote it** once you have read it: `--candidate proposed.json --promote`.
   That appends the rules to `core.json`, bumps the version, and re-records the
   baseline. Commit the change.

To hotfix without editing the package, drop a rules file next to the app and set
`SCAM_RULEPACK_EXTRA=/path/to/extra.json`. Extra rules can only add detections
(they cannot replace or weaken core rules), are capped in weight, and are
validated on load (bad or catastrophic regexes are refused).

## Add the new example to the corpus, too

When a reviewer catches something new, also add it to a corpus file (with the
`notes` and `context_flags` fields, never inside `description`) so the gate
protects that detection forever. `real_corpus_clean.jsonl` is the right home for
real examples; keep synthetic ones in `synthetic_scams.jsonl`.

## Guardrails, and why

* **Human promotion only.** The text being mined was written by scammers. A loop
  that promoted its own rules could be steered by someone who submits crafted
  postings. Only reviewer-labeled rows (never raw public submissions) feed the
  miner, and nothing goes live without a person.
* **The gate favors precision.** A false alarm costs a student an opportunity and
  teaches reviewers to ignore the queue. Recall gains that come with new false
  positives are rejected.
* **Every decision is traceable.** Each stored listing records the `ruleset_version`
  that scored it, so you can tell which rules were live when a miss happened.
* **Negation is a known evasion.** A scammer can write "there is no fee ... you must
  pay a fee". The engine refuses to honor a negation when a requirement verb
  ("must", "need to") follows it, and other rules stack independently, but assume
  determined attackers will find more. Watch the "missed" count in the queue header.

## What a statistical model would need before it earns a place

It is tempting to train a classifier and let it adapt on its own. Not yet. It
needs a few hundred real, reviewer-labeled postings before it can be measured, and
it would have to beat the rules on a held-out set the rules never saw. Until then
it would learn the quirks of a tiny sample and the number you report would be
fiction. When the export shows several hundred labels, add a model as a *second
opinion* alongside the rules, never as a replacement, and gate it the same way.

## Sources worth watching for new techniques

The FTC's consumer alerts on job scams and task scams, university career-center
and IT-security alerts (they often quote the actual messages), the BBB Scam
Tracker, and your own reviewers. When one describes a new pattern, write the rule
from the *behavior* it describes, add a synthetic example to the corpus, and run
the gate.
