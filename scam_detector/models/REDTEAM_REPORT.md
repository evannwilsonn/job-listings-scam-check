# Red-team report

33 scam seeds from the holdouts and archives; the originals are caught 26/33.
Each seed is rewritten with the tricks below. A variant counts as caught when the rules send it to a person or the model flags it. Run seed 815538435: every run makes new variants, so fixes are never graded on the variants they were built from.

| Trick | Variants caught |
|---|---|
| leetspeak | 26/33 |
| no_dollar_amounts | 25/33 |
| polite_tone | 27/33 |
| synonyms | 25/33 |
| synonyms+polite_tone | 26/33 |
| zero_width | 26/33 |

## Slipped through (4): the original was caught, the rewrite wasn't

- **no_dollar_amounts** (seed u05): Cornell University, Sibley School of Mechanical and Aerospace Engineering is currently seeking the services of Research Assistants to work remotely or in person with our research team to support ongoing data collection a
- **synonyms** (seed u14): Some departments are currently hiring individuals who can assist some of their visiting professors by providing basic admin duties remotely.

The successful candidate will Liaise with staff, other departments, or externa
- **no_dollar_amounts** (seed u14): Some departments are currently hiring individuals who can assist some of their visiting professors by providing basic admin duties remotely.

The successful candidate will Liaise with staff, other departments, or externa
- **synonyms+polite_tone** (seed u14): Hope your semester is going well! Some departments are currently hiring individuals who can assist some of their visiting professors by providing basic admin duties remotely.

The successful candidate will Liaise with st

## Regression set: 8/8 still caught
Variants saved after a fix was made for them (`--save-regression`). The release gate requires every new model to catch at least as many as the active one.

These are for a person to read and turn into rules or normalization. They are never trained on.
