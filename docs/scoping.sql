-- Credential scoping: what the customer's DBA creates.
--
-- The enclave never holds a credential that can read the whole database. It
-- holds one role per scope, each able to SELECT from the views that scope is
-- allowed and nothing else. That is the answer to "how does the system know
-- which data is sensitive": it does not, and it does not need to, because data
-- out of scope is unreachable rather than merely unrequested.
--
-- This matters most because of a limitation Sentinel publishes rather than
-- hides: the launch measurement covers what booted, not the application
-- afterwards, so an operator with root on their own machine can modify a
-- running miner and still attest cleanly. Scoping does not close that. It
-- changes the consequence from "reads your database" to "reads these views".

-- 1. A view per scope. Project only the columns that scope needs, and filter
--    the rows it is entitled to. A view is the boundary, not a convenience.

CREATE VIEW analytics_customers AS
SELECT
    id,
    plan,
    created_at,
    -- The agent needs to group by domain, never to contact anyone.
    split_part(email, '@', 2) AS email_domain
FROM customers
WHERE deleted_at IS NULL;

CREATE VIEW support_tickets AS
SELECT id, customer_id, status, opened_at, subject
FROM tickets
WHERE status <> 'legal-hold';

-- 2. A role per scope. NOLOGIN on the group, login on the role the enclave
--    actually uses, so the grant set is reviewable on its own.

CREATE ROLE sentinel_analytics LOGIN PASSWORD 'rotate-me';
CREATE ROLE sentinel_support   LOGIN PASSWORD 'rotate-me';

-- 3. Grant the view and nothing else. No table grants, and explicitly revoke
--    the public schema default, or every role can see every table by accident.

REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO sentinel_analytics, sentinel_support;

GRANT SELECT ON analytics_customers TO sentinel_analytics;
GRANT SELECT ON support_tickets     TO sentinel_support;

-- 4. Belt and braces. Sentinel already opens read-only connections, but a role
--    that cannot write is a property of the database rather than of our code.

ALTER ROLE sentinel_analytics SET default_transaction_read_only = on;
ALTER ROLE sentinel_support   SET default_transaction_read_only = on;

-- 5. Verify, rather than assume. Run as each role:
--
--     SELECT * FROM customers;            -- must fail: permission denied
--     SELECT * FROM analytics_customers;  -- must succeed
--     CREATE TABLE t (x int);             -- must fail
--
-- Then start the miner with one credential per scope:
--
--     python scripts/run_miner.py \
--       --scope analytics=postgresql://sentinel_analytics:...@host/db \
--       --scope support=postgresql://sentinel_support:...@host/db \
--       --api-keys /etc/sentinel/api-keys.json
--
-- Each scope is a separate attestation. A report obtained to unlock the
-- analytics credential cannot be replayed to unlock support, because the
-- scope name is bound into the report the chip signs.
