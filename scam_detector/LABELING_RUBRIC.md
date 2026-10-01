# Labeling rubric: scam vs. legit job postings

The point of this document is consistency. When you label 300 postings over
several days, your own judgment drifts — you get stricter, you get tired, you
start overthinking the ambiguous ones. This rubric fixes the standard in place so
label #300 is decided the same way as label #1. It's also the document you'd hand
a second person to check whether they'd label the same way you did (inter-rater
agreement), which is how you know your labels mean something.

Read this once before you start, and keep it open while you label.

---

## The labels

Every posting gets exactly one: `scam`, `lead_gen` or `legit`. `lead_gen` is a
listing that is not fraudulent but is an aggregator or lead-generation wrapper:
forced signup, affiliate or tracking redirects, or an employer that is never
named. It is scored on its own axis and never counts as "scam". There is no "unsure" label —
see the tie-breaker rules below for how to force a decision. If you truly cannot
decide even after those, **drop the posting from the corpus** rather than guess.
A wrong label is worse than a missing one, because the detector learns from it.

---

## What makes a posting `scam`

Label `scam` if the posting, taken as a whole, is trying to defraud the
applicant. You are labeling the *posting's intent*, not whether it happens to
contain a suspicious word. Concrete markers, strongest first:

**Definitive (any one of these alone is enough):**
- Asks the applicant to pay anything to get or keep the job (fees, deposits,
  "equipment you buy," training costs), refundable or not.
- Describes work that is money laundering or its logistics: depositing checks and
  forwarding funds, receiving and reshipping packages, "payment processing" into
  a personal account.
- Asks for banking details, SSN, or ID images during screening, before any real
  offer.
- Directs payment or "salary" through irreversible channels: gift cards, crypto,
  Zelle/CashApp/Venmo, wire services.

**Strong (two or more together = scam):**
- Hire with no interview, or an offer within hours of first contact.
- Insists the whole process happen on Telegram/WhatsApp/Signal from the start.
- Pay far above market for low-skill remote work, paired with "no experience."
- A named employer contacted from a free email address (gmail, etc.).
- Heavy urgency ("respond within the hour," "limited slots") with no real detail
  about the role.

**Weak (context only, never decisive alone):**
- Vague employer, generic duties, minor grammar oddities. Real postings have
  these too. Never label `scam` on weak markers alone.

---

## What makes a posting `legit`

Label `legit` if it's a genuine attempt to hire, even if imperfect. Genuine
postings can look rough — small companies write bad job ads, staffing agencies
are vague on purpose, and some real remote roles pay well. Markers:

- Names a real, checkable company and a plausible role.
- Compensation in a believable range for the work and location.
- Describes an actual process (interviews, assessments, references).
- Asks for nothing of value up front; any banking/ID request is explicitly
  post-offer through a normal system.
- Contact through the company's own domain or the job board's messaging.

**Do not label `legit` as scam just because it's a good deal.** A real remote job
at $40/hr exists. The scam signal is high pay *plus* low skill *plus* other
markers, not high pay alone.

---

## Tie-breaker procedure (use this when you're stuck)

Go in order. Stop at the first rule that resolves it.

1. **Any one definitive marker present?** → `scam`. Done. (These essentially never
   appear in real postings.)
2. **Zero strong markers and zero definitive?** → `legit`. Weak markers alone
   don't make a scam.
3. **Exactly one strong marker, nothing definitive?** → `legit`. One strong
   marker is suspicious but not enough; real postings trip one sometimes (a real
   urgent hire, a real high-paying remote role). Labeling these `scam` is how you
   poison precision.
4. **Two or more strong markers?** → `scam`.
5. **Still genuinely tied?** → drop it from the corpus. Don't guess.

The asymmetry is deliberate. A false "scam" label teaches the detector to flag
real jobs, which costs a job seeker an opportunity. When in doubt, lean `legit`
and protect precision.

---

## Rules to keep labels clean

- **Label the text you have, not the company you googled.** If you look up the
  company to decide, that's fine for your judgment, but the detector only sees the
  text — so if the text alone is indistinguishable from a scam, that's a hard case
  worth keeping, labeled by ground truth.
- **Redact personal data as you go.** Strip real victim names, personal emails,
  and phone numbers from scam examples before saving. Keep scammer-side handles/
  domains only if they're part of the tactic and already public.
- **Match your legit distribution to your scam distribution.** If a third of your
  scams are "remote data entry," get real remote-data-entry postings too.
  Otherwise the detector just learns "data entry = scam," which is useless.
- **Include hard legit cases on purpose.** Legitimate remote roles, above-average
  pay, staffing agencies, brief postings. These are where false positives come
  from; you want them in the corpus so your measured precision is honest.
- **Keep the corpus fixed while you tune.** Label first, then tune rules against
  the frozen set. If you edit labels while adjusting weights, you're fitting to
  noise and your F1 means nothing.

---

## Format reminder

One JSON object per line in your `.jsonl`:

```json
{"label": "scam", "title": "...", "company": "...", "description": "posting text ONLY",
 "url": "optional a -> b", "context_flags": [], "notes": "your observations go here"}
```

Never put your own observations in `description`; the detector must only see what
a user would paste. Then measure:

```bash
python -m scam_detector.tools.evaluate data/your_corpus.jsonl --threshold review
```

Read every misclassification it prints. A false positive is a rule that's too
aggressive. A false negative is a tactic you're missing. That loop — label,
measure, read the misses, adjust, re-run — is the entire job.
