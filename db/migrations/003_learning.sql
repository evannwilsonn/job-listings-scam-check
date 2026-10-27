-- Migration 003: the learning loop (scam_detector/learning.py).
--
-- Model files live here, not on a server's disk, so the API and the retrain job (which may run on different machines)
-- serve and compare the same models. A retrained candidate reaches students in stages: shadow (scored, never shown),
-- rollout (a stable slice of checks), then active, with the previous model kept for an automatic rollback.
--
-- model_traffic is what the drift monitor and the shadow comparison read: the model's probability, whether it flagged,
-- and how much of the text it had never seen. The posting's text is never stored, only a hash of its words.

BEGIN;

CREATE TABLE models (
    version    text PRIMARY KEY,
    spec       jsonb NOT NULL,                          -- what tools/train_model.py writes (scam_model.json)
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Every retrain attempt, shipped or not: the schedule ("never more often than ...") is measured from these.
CREATE TABLE retrain_runs (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    started_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz,
    trigger     text NOT NULL,
    status      text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'candidate', 'refused', 'error', 'unavailable')),
    version     text,
    live_labels integer NOT NULL DEFAULT 0,
    train_rows  integer NOT NULL DEFAULT 0,
    report      text NOT NULL DEFAULT ''
);

-- One row: where the current release stands.
CREATE TABLE model_release (
    id                smallint PRIMARY KEY CHECK (id = 1),
    stage             text NOT NULL DEFAULT 'none' CHECK (stage IN ('none', 'shadow', 'rollout', 'watch')),
    lane              text NOT NULL DEFAULT 'full' CHECK (lane IN ('full', 'fast')),
    candidate_version text REFERENCES models (version),
    active_version    text REFERENCES models (version),  -- NULL: the model shipped with the code
    previous_version  text REFERENCES models (version),
    run_id            bigint REFERENCES retrain_runs (id),
    pct               smallint NOT NULL DEFAULT 0 CHECK (pct BETWEEN 0 AND 100),
    created_at        timestamptz,
    stage_started     timestamptz,
    note              text NOT NULL DEFAULT ''
);
INSERT INTO model_release (id) VALUES (1);

CREATE TABLE release_log (
    id      bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at      timestamptz NOT NULL DEFAULT now(),
    event   text NOT NULL,
    version text,
    detail  text NOT NULL DEFAULT ''
);

CREATE TABLE model_traffic (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at         timestamptz NOT NULL DEFAULT now(),
    key        char(64) NOT NULL CHECK (key ~ '^[0-9a-f]{64}$'),
    served     text NOT NULL,
    p          real NOT NULL,
    flag       boolean NOT NULL,
    novelty    real NOT NULL,
    other      text,
    other_p    real,
    other_flag boolean
);
CREATE INDEX model_traffic_at ON model_traffic (at);

-- A label's permanent place, set the first time a retrain uses it. Copies of the same script share one place, so a scam
-- wave is either trained on or held out, never split (which would make the trainer drop the training copies as leaks).
ALTER TABLE labels ADD COLUMN split text CHECK (split IN ('train', 'holdout'));

-- Template memory: which hash key made a sketch (so a school can read a partner's), and a key of the text it came from
-- (so labeling the same text real forgets it).
ALTER TABLE templates ADD COLUMN kid text NOT NULL DEFAULT '0';
ALTER TABLE templates ADD COLUMN text_key text;
CREATE INDEX templates_text_key ON templates (text_key);

GRANT SELECT, INSERT, UPDATE ON models, retrain_runs, model_release, release_log, model_traffic TO lurecheck_app;
GRANT DELETE ON model_traffic TO lurecheck_app;            -- traffic older than 120 days is pruned
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO lurecheck_app;

INSERT INTO schema_migrations (version) VALUES ('003_learning');

COMMIT;
