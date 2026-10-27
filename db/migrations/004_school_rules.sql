-- Migration 004: a career center's own allow and block lists (scam_detector/guardrails.py).
--
-- trusted_domain: an employer domain the career center has verified (e.g. a local credit union whose name looks like the
--   school's). It quiets warnings about that domain's infrastructure (new, unregistered, no mail, look-alike) and protects
--   it from look-alikes. It never overrides evidence: text rules, confirmed scam contacts, partner reports, template
--   matches and outside blocklists still count, because real accounts get compromised.
-- blocked_domain: a domain the career center has seen target its students. A message that uses it gets a critical finding.
--
-- Each entry names who added it and why; removing one keeps the row (status 'removed') so there is a record.

BEGIN;

CREATE TABLE school_rules (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    school_id  text NOT NULL REFERENCES schools (id),
    kind       text NOT NULL CHECK (kind IN ('trusted_domain', 'blocked_domain')),
    value      text NOT NULL CHECK (value ~ '^[a-z0-9.-]+\.[a-z]{2,}$'),
    reason     text NOT NULL DEFAULT '',
    added_by   text NOT NULL CHECK (added_by <> ''),
    added_at   timestamptz NOT NULL DEFAULT now(),
    status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'removed')),
    removed_by text,
    removed_at timestamptz
);
CREATE UNIQUE INDEX school_rules_active ON school_rules (school_id, kind, value) WHERE status = 'active';

GRANT SELECT, INSERT, UPDATE ON school_rules TO lurecheck_app;

INSERT INTO schema_migrations (version) VALUES ('004_school_rules');

COMMIT;
