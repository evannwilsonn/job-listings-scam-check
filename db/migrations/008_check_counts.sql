-- 008: how many checks students ran, per school, day and verdict band (scam_detector/counts.py).
-- Numbers only: no text, no sender, nothing that identifies a student or a message. Shown to the school's own staff
-- on the review page and in the monthly trends report.
BEGIN;

CREATE TABLE check_counts (
    school_id text NOT NULL REFERENCES schools (id),
    day       date NOT NULL,
    band      text NOT NULL CHECK (band IN ('clear', 'caution', 'review', 'block')),
    n         integer NOT NULL CHECK (n >= 0),
    PRIMARY KEY (school_id, day, band)
);

GRANT SELECT, INSERT, UPDATE ON check_counts TO lurecheck_app;

INSERT INTO schema_migrations (version) VALUES ('008_check_counts');

COMMIT;
