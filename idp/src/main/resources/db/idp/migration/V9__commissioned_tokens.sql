-- Commissioned tokens: an opaque bearer a service client commissions for one dynamic context, and
-- that the idp verifies on every use (the token-auth epic, qits-448).
--
-- WHY A NEW TABLE AND NOT A KIND COLUMN ON idp_client. A commissioned client is an id and a secret
-- that mints JWTs at /idp/token; a token is a single value that is introspected. The shapes differ
-- where it matters: a token row is looked up by the HASH of what a caller presents (so token_hash is
-- unique and the lookup key), it has a generated uuid rather than a readable id as its key, and its
-- readable name is a separate `subject`. Folding it into idp_client would make secret_hash mean two
-- different things by row and give every reader of that table a branch it does not need today —
-- the same argument V8 made for idp_service_client.
--
-- WHY NO EXPIRY COLUMN. A token lives exactly as long as its row. Every use is an introspection
-- against this table, so deleting the row is the whole revocation, and it is immediate for the next
-- call — there is no `exp` to wait out, which is the property a JWT cannot have and the reason this
-- credential exists. A deadline would be a second way to end a token that buys nothing the delete
-- does not already give, and a column nobody enforces is a trap for whoever reads it first.
--
-- claims and git_refs are the same two columns, in the same formats, as idp_client's (V5, V7):
-- `name=value` lines, and one ref per line where NULL is "no list stated" and '' is the empty list.

create table idp_token (
  id           uuid          primary key,
  subject      varchar(128)  not null,
  token_hash   varchar(255)  not null,
  owner        varchar(128)  not null,
  context_kind varchar(32)   not null,
  context_id   varchar(256)  not null,
  claims       varchar(1024),
  git_refs     text,
  created_at   timestamptz   not null
);

-- The lookup key: introspection hashes the presented value and reads by this.
create unique index idp_token_token_hash_uq on idp_token (token_hash);

-- The subject is a token's identity in every JWT minted for it; two rows must never share one.
create unique index idp_token_subject_uq on idp_token (subject);

-- The reconciliation read: one owner's live tokens.
create index idp_token_owner_idx on idp_token (owner);
