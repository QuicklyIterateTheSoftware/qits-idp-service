-- Keep accepting the environment secret of a client that already had a database row (qits-163 fix).
--
-- WHY. Before the environment registry was retired, an id with BOTH an environment secret and an
-- idp_service_client row authenticated with either. V10's adoption left such a row as it was, so the
-- environment secret its caller still holds (dev-qits-edge's, live) stopped working the moment the
-- registry went: invalid_client, and the platform's sessions through the edge with it.
--
-- WHAT. legacy_secret_hash holds the hash of that environment secret, for exactly the ids whose
-- environment secret matched neither of the row's own hashes. It is accepted beside secret_hash and
-- a live previous_secret_hash. A rotation clears it: the caller then holds a database secret, so the
-- old one has nothing left to keep working.
--
-- legacy_adopted_at marks that pass as done, separately from adopted_at, because live installations
-- already carry the V10 marker row: the pass must still run once there, and never again after.
alter table idp_service_client add column legacy_secret_hash varchar(255);

alter table idp_adoption add column legacy_adopted_at timestamptz;
