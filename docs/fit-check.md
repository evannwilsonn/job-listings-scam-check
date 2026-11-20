# Fit Check (feature spec)

Status: proposed. Nothing in this document is built yet.

## What it is

The scam check answers "is this job real?" The fit check answers "is this job
right for me?"

A person gives it a job posting. It reads the posting against that person's
profile and their own rules, then returns an apply-or-skip verdict with a short
reason for every rule, a match score, and recommendations.

## What it takes in

1. **The posting.** Pasted text or a link.
2. **The person's profile.** Resume, LinkedIn, skills, experience, strengths,
   and anything they have said they cannot claim.
3. **The person's own rules.** Collected by asking them (see Setup). Nothing is
   assumed and no rule ships with a preset number.

## Setup: the person fills in the blanks

The first time someone uses the fit check, it asks a short set of questions and
saves the answers as their rules. Every answer is optional and can be changed
later. A rule left blank is not checked.

| Rule | Question asked |
|---|---|
| Hours | Do you want part time, full time, or either? |
| Level | What level are you looking for (intern, entry, junior, mid, senior)? |
| Pay | What is the lowest hourly pay or salary you would accept? Is there a range just under it you would still consider? |
| Location | Where will you be living, and do you want on-site, hybrid, remote, or any? How far will you commute? |
| Schedule and commitment | Which days and hours are you free? Is there a date you need the job to start by or end by (for example, graduation)? |
| Pay type and costs | Will you take contract or per-job work? Are you willing to supply your own tools or vehicle? |
| Posting age | How old can a posting be before you would rather skip it? |
| Anything else | Is there anything that would make a job an automatic skip for you? |

## What it checks

Each check returns **pass**, **fail**, or **unknown**, with a one-line reason.
"Unknown" is used when the posting does not say; the fit check never guesses.

1. **Hours.** Does the job match the hours the person wants?
2. **Level.** Is the role at the level they are looking for?
3. **Pay.** Does the stated pay meet their minimum? Pay inside their
   "still consider" range is flagged, not failed.
4. **Qualification.** Does the person seriously not qualify? Required
   qualifications are weighed separately from preferred ones.
5. **Worth their time.** Would applying be a waste of time, given everything
   else?
6. **Match score.** A 1 to 10 rating of how well the person matches the
   posting's qualifications, with the reasons it is not higher.
7. **Posting age.** Is the posting older than the person's cutoff?
8. **Location.** Is the workplace type acceptable and reachable from where the
   person will be?
9. **Schedule and commitment.** Do the required days, dates and length of
   commitment fit the person's availability?
10. **Pay type and costs.** Is it hourly or salaried employment, or contract or
    per-job pay? Does the person have to supply tools or a vehicle?
11. **Scam check.** The existing LureCheck verdict for the posting.

## What it gives back

- A pass, fail or unknown on each check, with a short reason.
- A 1 to 10 match score against the posting's qualifications.
- A skip-or-apply verdict.
- What to confirm before applying (every "unknown" becomes a question to ask).
- The scam check result.
- Recommendations (below).

## Recommendations

The fit check should give advice, not only a verdict. Recommendations are
built from the person's profile (experience, strengths, skills), the rules
they set, and the posting's description and qualifications.

- **What to lead with.** Which of the person's experiences and projects best
  match this posting, in order.
- **Gaps to address.** Required or preferred qualifications the profile does
  not show, split into "you may have this but have not listed it" and "you
  would need to learn this".
- **What not to claim.** Skills the posting asks for that the person has said
  they cannot claim.
- **Whether a near-miss is still worth it.** For example, pay slightly under
  the minimum on a role that otherwise fits well.
- **Better-fit suggestions.** When the verdict is skip, what kind of role would
  pass the person's rules.

Recommendations must be traceable. Each one names the line in the profile or
the posting it is based on, the same way every scam warning shows the exact
words that triggered it.

## Rules for the feature itself

- Never invent facts about the person. If the profile does not show something,
  say so and ask.
- Never fill in a missing detail from the posting. Report it as unknown.
- The person's rules and profile are private to them. They are not shared with
  staff dashboards or other users.
- The scam check stays independent. A posting that fails the scam check is
  reported as a scam regardless of how well it fits.

## Open question

LureCheck is currently a staff-facing tool that runs inside a school's job
board. The fit check is student-facing by nature, because it runs on one
student's profile and rules. It needs a decision: ship it as a student-facing
companion, or as a separate product that reuses the scam check.
