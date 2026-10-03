-- The environment client registry is retired (qits-163). Its clients move into idp_service_client
-- once, at the first start that runs this code, and this table is the marker that the move ran.
--
-- WHAT THE MOVE DOES. For every id on qits.idp.clients that has a non-blank
-- qits.idp.client.<id>.secret and no idp_service_client row, EnvironmentClientAdoption inserts a row
-- holding the hash of that secret, created_by = 'adopted'. An id that already has a row keeps it as
-- it is. An id with no secret is skipped: it could never authenticate, so there is nothing to move.
--
-- ONE ROW, EVER, LIKE idp_seed. id is pinned to 1 by the check constraint. The rows and this marker
-- are written in one transaction, so the move happened completely or not at all. Once the row exists
-- nothing reads qits.idp.clients or a qits.idp.client.<id>.secret again, even if a later boot still
-- sets them.
create table idp_adoption (
  id         smallint primary key check (id = 1),
  adopted_at timestamptz not null
);
