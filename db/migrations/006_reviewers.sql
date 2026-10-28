-- 006: reviewer accounts for the review page (scam_detector/review_web.py).
--
-- A reviewer belongs to one school and only sees that school's reports; school_id NULL means every school (the
-- LureCheck operator). Accounts are created with tools/reviewers.py, never from the web. Passwords are scrypt hashes and
-- sessions are stored only as SHA-256 hashes of the cookie, so a copy of this database can't be used to log in.
BEGIN;

CREATE TABLE reviewers (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    school_id   text REFERENCES schools (id),
    email       text NOT NULL UNIQUE CHECK (email = lower(email) AND email LIKE '%_@_%'),
    name        text NOT NULL CHECK (name <> ''),
    pw_hash     text NOT NULL,
    active      boolean NOT NULL DEFAULT true,
    created_at  timestamptz NOT NULL DEFAULT now(),
    last_login  timestamptz
);

CREATE TABLE reviewer_sessions (
    token_hash  char(64) PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    reviewer_id bigint NOT NULL REFERENCES reviewers (id) ON DELETE CASCADE,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);
CREATE INDEX reviewer_sessions_expires ON reviewer_sessions (expires_at);

GRANT SELECT, INSERT, UPDATE ON reviewers TO lurecheck_app;
GRANT SELECT, INSERT, DELETE ON reviewer_sessions TO lurecheck_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO lurecheck_app;

INSERT INTO schema_migrations (version) VALUES ('006_reviewers');

COMMIT;
