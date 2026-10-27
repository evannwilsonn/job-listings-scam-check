-- Migration 002: employer attestations (plan item 16).
--
-- A real employer tells LureCheck how it recruits: the email domains it sends from, and the channels it never uses.
-- Then a message that says it's from that employer but breaks those rules gets a warning that no text rule could
-- give: "Acme has told us it never recruits by text." An attestation counts only once a reviewer has verified it
-- came from the employer (verified_by), so a scammer can't register "we recruit on Telegram" for a real company.

BEGIN;

CREATE TABLE employer_attestations (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    company          text NOT NULL,
    company_key      text NOT NULL UNIQUE CHECK (company_key ~ '^[a-z0-9]+$'),   -- lowercased name, letters and digits
    email_domains    text[] NOT NULL CHECK (cardinality(email_domains) >= 1),
    careers_url      text,
    never_text       boolean NOT NULL DEFAULT false,      -- never recruits by SMS
    never_chat_apps  boolean NOT NULL DEFAULT false,      -- never WhatsApp, Telegram, Signal, ...
    never_checks     boolean NOT NULL DEFAULT true,       -- never sends checks or asks for equipment money
    never_fees       boolean NOT NULL DEFAULT true,       -- never charges applicants
    contact          text,                                -- who at the employer confirmed it (not shown publicly)
    verified_by      text NOT NULL,
    verified_at      timestamptz NOT NULL DEFAULT now(),
    status           text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'withdrawn'))
);

INSERT INTO schema_migrations (version) VALUES ('002_attestations');

COMMIT;
