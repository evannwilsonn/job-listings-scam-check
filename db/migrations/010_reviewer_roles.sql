-- 010: staff roles and job titles for the review page.
--
-- An admin can add colleagues at their own school, reset their passwords and turn accounts off from the Team page
-- (/review/team), so a career center doesn't need the LureCheck operator for routine staffing. A reviewer decides
-- reports and nothing else. The title is shown next to the name ("Assistant Director, Career Center").
BEGIN;

ALTER TABLE reviewers
    ADD COLUMN role  text NOT NULL DEFAULT 'reviewer' CHECK (role IN ('reviewer', 'admin')),
    ADD COLUMN title text NOT NULL DEFAULT '' CHECK (length(title) <= 80);

INSERT INTO schema_migrations (version) VALUES ('010_reviewer_roles');

COMMIT;
