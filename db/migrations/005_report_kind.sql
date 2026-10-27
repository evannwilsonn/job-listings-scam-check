-- 005: where a report came from.
--   report      the student thinks it's a scam (the one-tap report)
--   borderline  the detector called it a close call and the student agreed to let a reviewer see it (api.py ask_review).
-- A reviewer's label on a close call is the most useful kind for the next retrain (active learning). Labels written
-- from these carry source borderline / borderline_real instead of report / report_real.
ALTER TABLE reports ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'report'
    CHECK (kind IN ('report', 'borderline'));
