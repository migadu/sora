-- Hosts in maintenance lose their mark. Builds that predate the table never consulted it
-- and route to every configured backend; a host still draining uploads should finish (or
-- be stopped deliberately) before rolling back.
DROP TABLE IF EXISTS backend_maintenance;
