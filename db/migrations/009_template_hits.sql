-- 009: how many later checks each confirmed scam script flagged (counts.py, template memory).
-- Keyed by the script's hash (templates.text_key), never its text; a count per day. Shown to reviewers as the
-- effect of their confirmations, and to the school as the number of copies caught.
BEGIN;

CREATE TABLE template_hits (
    text_key text NOT NULL CHECK (char_length(text_key) BETWEEN 1 AND 64),
    day      date NOT NULL,
    n        integer NOT NULL CHECK (n >= 0),
    PRIMARY KEY (text_key, day)
);

GRANT SELECT, INSERT, UPDATE ON template_hits TO lurecheck_app;

INSERT INTO schema_migrations (version) VALUES ('009_template_hits');

COMMIT;
