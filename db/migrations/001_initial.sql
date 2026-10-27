-- LureCheck schema, migration 001. Postgres 17 (Neon project "lurecheck", branch "production").
--
-- One database for every school. Tenancy is a school_id column on everything a school owns (reports, cases);
-- confirmed indicators are shared across schools, because that sharing is the product.
--
-- Privacy rules the schema enforces:
--   * no student names, accounts, IP addresses or devices anywhere;
--   * email addresses and phone numbers are stored only as salted SHA-256 hashes (indicators.hashed = true);
--     domains, wallets and chat handles are stored in the clear (they are the scammer's, not the student's);
--   * report text is masked before it arrives and expires (text_expires_at); purge_expired_text() clears it once
--     a reviewer has decided, after the masked copy has gone to labels;
--   * the follow-up case code is never stored, only its hash.
--
-- Nothing a student submits reaches the shared network until a reviewer confirms it: indicators start as
-- 'reported' and only 'confirmed' ones are served to other schools.

BEGIN;

CREATE TABLE schools (
    id          text PRIMARY KEY CHECK (id ~ '^[a-z0-9_-]{2,40}$'),
    name        text NOT NULL,
    domain      text,                                   -- e.g. fsu.edu
    lookalike_terms text[] NOT NULL DEFAULT '{}',       -- for the CT watch
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TYPE indicator_kind AS ENUM ('domain', 'email', 'phone', 'wallet', 'handle');

CREATE TABLE indicators (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind         indicator_kind NOT NULL,
    value        text NOT NULL,                         -- hash for email/phone, clear text otherwise
    hashed       boolean NOT NULL,
    status       text NOT NULL DEFAULT 'reported' CHECK (status IN ('reported', 'confirmed', 'retired')),
    first_seen   timestamptz NOT NULL DEFAULT now(),
    last_seen    timestamptz NOT NULL DEFAULT now(),
    confirmed_by text,
    confirmed_at timestamptz,
    note         text,
    UNIQUE (kind, value),
    CHECK ((kind IN ('email', 'phone')) = hashed),
    CHECK (NOT hashed OR value ~ '^[0-9a-f]{64}$'),
    CHECK (status <> 'confirmed' OR (confirmed_by IS NOT NULL AND confirmed_at IS NOT NULL))
);
CREATE INDEX indicators_confirmed ON indicators (kind, value) WHERE status = 'confirmed';

CREATE TABLE reports (
    id              bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    school_id       text REFERENCES schools (id),
    received_at     timestamptz NOT NULL DEFAULT now(),
    outcome         text,                               -- recovery.HAPPENED key or 'not_replied'
    text_masked     text,                               -- NULL once purged
    text_expires_at timestamptz NOT NULL DEFAULT now() + interval '30 days',
    status          text NOT NULL DEFAULT 'reported' CHECK (status IN ('reported', 'confirmed', 'dismissed')),
    reviewer        text,
    reviewed_at     timestamptz,
    note            text,
    CHECK (status = 'reported' OR (reviewer IS NOT NULL AND reviewed_at IS NOT NULL))
);
CREATE INDEX reports_queue ON reports (school_id, received_at) WHERE status = 'reported';

-- Which indicators a report named. Confirming a report confirms these.
CREATE TABLE report_indicators (
    report_id    bigint NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
    indicator_id bigint NOT NULL REFERENCES indicators (id),
    PRIMARY KEY (report_id, indicator_id)
);

-- Every time a school sees an indicator: "seen at 4 schools this week" is a count over this table.
CREATE TABLE sightings (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    indicator_id bigint NOT NULL REFERENCES indicators (id),
    school_id    text NOT NULL REFERENCES schools (id),
    seen_at      timestamptz NOT NULL DEFAULT now(),
    report_id    bigint REFERENCES reports (id) ON DELETE SET NULL
);
CREATE INDEX sightings_recent ON sightings (indicator_id, seen_at DESC);
CREATE INDEX sightings_school ON sightings (school_id, seen_at DESC);

-- Template memory: a bottom-k sketch (128 word-trigram hashes) per confirmed scam; the text isn't kept.
-- memory.py hashes are unsigned 64-bit; the app stores them as signed bigint (x - 2^64 when x >= 2^63).
CREATE TABLE templates (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    report_id   bigint REFERENCES reports (id) ON DELETE SET NULL,
    school_id   text REFERENCES schools (id),
    title       text,
    sketch      bigint[] NOT NULL CHECK (cardinality(sketch) BETWEEN 1 AND 128),
    status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'forgotten')),
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Outcome follow-up (followup.py). The case code itself is never stored.
CREATE TABLE cases (
    case_hash  char(64) PRIMARY KEY CHECK (case_hash ~ '^[0-9a-f]{64}$'),
    school_id  text REFERENCES schools (id),
    opened_on  date NOT NULL DEFAULT current_date,
    band       text NOT NULL CHECK (band IN ('clear', 'caution', 'review', 'block')),
    score      smallint NOT NULL CHECK (score BETWEEN 0 AND 100),
    rules      text[] NOT NULL DEFAULT '{}',
    model_flag boolean NOT NULL DEFAULT false
);

CREATE TABLE outcomes (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    case_hash   char(64) NOT NULL REFERENCES cases (case_hash) ON DELETE CASCADE,
    answered_on date NOT NULL DEFAULT current_date,
    happened    text[] NOT NULL CHECK (cardinality(happened) >= 1),
    verified    text NOT NULL DEFAULT '' CHECK (verified IN ('job_real', 'job_fake', 'unsure', ''))
);
CREATE INDEX outcomes_case ON outcomes (case_hash, answered_on DESC);

-- Reviewer-labeled rows for training (what export_labeled.py produced). Masked text only.
CREATE TABLE labels (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    label       text NOT NULL CHECK (label IN ('scam', 'legit', 'lead_gen')),
    title       text NOT NULL DEFAULT '',
    company     text NOT NULL DEFAULT '',
    description text NOT NULL,                          -- masked
    source      text NOT NULL,                          -- 'report', 'board_review', 'public_report', ...
    report_id   bigint REFERENCES reports (id) ON DELETE SET NULL,
    school_id   text REFERENCES schools (id),
    reviewer    text NOT NULL,
    holdout     boolean NOT NULL DEFAULT false,         -- fixed when first used; never moves after that
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE model_runs (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    version      text NOT NULL UNIQUE,
    trained_at   timestamptz NOT NULL DEFAULT now(),
    rows         integer NOT NULL,
    threshold    real NOT NULL,
    holdout      jsonb NOT NULL DEFAULT '{}',           -- scams caught, legit flagged, per set
    gate_passed  boolean NOT NULL,
    stage        text NOT NULL DEFAULT 'candidate' CHECK (stage IN ('candidate', 'shadow', 'rollout', 'active', 'retired', 'rolled_back')),
    report       text
);

-- Clear masked report text once a reviewer has decided and the retention window has passed. Run daily.
CREATE FUNCTION purge_expired_text() RETURNS integer
LANGUAGE sql AS $$
    WITH purged AS (
        UPDATE reports SET text_masked = NULL
        WHERE text_masked IS NOT NULL AND status <> 'reported' AND text_expires_at < now()
        RETURNING 1
    )
    SELECT count(*)::integer FROM purged
$$;

-- The application's role: read and write rows, no schema changes, no deletes outside the purge.
-- Give a login role this membership in the Neon console: GRANT lurecheck_app TO <login role>;
-- Roles are per server, not per database, so this tolerates a second database (test, CI) on the same server.
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'lurecheck_app') THEN
        CREATE ROLE lurecheck_app NOLOGIN;
    END IF;
END $$;
GRANT USAGE ON SCHEMA public TO lurecheck_app;
GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO lurecheck_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO lurecheck_app;
GRANT EXECUTE ON FUNCTION purge_expired_text() TO lurecheck_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE ON TABLES TO lurecheck_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE ON SEQUENCES TO lurecheck_app;

INSERT INTO schools (id, name, domain, lookalike_terms)
VALUES ('fsu', 'Florida State University', 'fsu.edu', ARRAY['fsu', 'floridastate', 'seminole']);

CREATE TABLE schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
INSERT INTO schema_migrations (version) VALUES ('001_initial');

COMMIT;
