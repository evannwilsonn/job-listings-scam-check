-- 007: a reviewer can undo a decision for a short while after making it (review_web.py, store.undo_decision).
-- Undo removes the training label that decision wrote, so the app role may remove labels. Nothing else is removable.
BEGIN;

GRANT DELETE ON labels TO lurecheck_app;

INSERT INTO schema_migrations (version) VALUES ('007_undo');

COMMIT;
