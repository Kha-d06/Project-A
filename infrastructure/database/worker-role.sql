-- Least-privilege role for SENTINEL scan workers.
--
-- Workers parse untrusted files and fetch untrusted URLs. If one were ever
-- compromised, this role limits it to scan jobs, their findings and the threat
-- indicator tables: it cannot read users, sessions, API keys or audit logs.
--
-- Run as the database owner after migrations, then set
-- SENTINEL_WORKER_DATABASE_URL for the worker service:
--   psql "$DATABASE_URL" -v worker_password="'…'" -f worker-role.sql

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sentinel_worker') THEN
    CREATE ROLE sentinel_worker LOGIN;
  END IF;
END
$$;

ALTER ROLE sentinel_worker WITH PASSWORD :worker_password;

REVOKE ALL ON ALL TABLES IN SCHEMA public FROM sentinel_worker;
GRANT USAGE ON SCHEMA public TO sentinel_worker;

GRANT SELECT, UPDATE ON scan_jobs TO sentinel_worker;
GRANT SELECT, INSERT, DELETE ON findings TO sentinel_worker;
GRANT SELECT ON threat_indicators, threat_sources TO sentinel_worker;

-- Security assessments of owned domains also run in the isolated worker: it
-- re-checks ownership and writes findings about the owner's own site. It still
-- cannot read users, sessions, API keys or audit logs.
GRANT SELECT, UPDATE ON assessments TO sentinel_worker;
GRANT SELECT, UPDATE ON verified_domains TO sentinel_worker;
