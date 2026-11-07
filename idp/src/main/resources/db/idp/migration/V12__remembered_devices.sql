-- Remembered devices (qits-1944). A login may ask to be remembered; the browser then holds a second,
-- long-lived opaque cookie, `qits-device`, beside the twelve-hour `qits-session`, and spends it at
-- POST /idp/api/auth/resume for a fresh session once the old one has died. Two tables and one
-- column, and the reasoning for each is beside it. The class that reads and writes all of it is
-- `Devices`.
--
-- WHY A DEVICE IS NOT A LONGER SESSION. A session is what the edge introspects on every request, so
-- its lifetime is the window a stolen cookie works in at every service. A device is presented to the
-- idp alone (the cookie's Path is /idp/api/auth), only to open a session, and it ROTATES on every
-- use — so a copy of it is spent the moment either holder uses it, and the second presentation is a
-- replay the store can see. A thirty-day session would have none of that.
--
-- THE SAME SECRET SCHEME AS A SESSION. The cookie carries 256 random bits; this store holds their
-- `sha-256:` fingerprint, so a dump of the idp's database resumes nobody — the argument is V3's and
-- ClientSecret's.
--
-- CAUSATION: no causation columns, for V3's reason — this context depends on no other qits module.

-- One remembered browser. `label` is the User-Agent the login arrived with, truncated, so the
-- account page can say which browser a row is; it is the caller's string and is shown, never parsed.
--
-- FOUR COLUMNS DECIDE WHETHER A DEVICE IS LIVE, and none is a constraint — a reader compares them
-- against the clock, exactly as for a session. `expires_at` is the IDLE deadline: every resume moves
-- it to now + qits.idp.device.idle-ttl, never past `absolute_expires_at`, which is stamped once at
-- creation (qits.idp.device.absolute-ttl) and never moves, so a device that is used every day still
-- dies on a fixed date. `revoked_at` is the account revoking it, a logout, or a replay; set rather
-- than deleted, so a device that ended is distinguishable from one that never existed.
--
-- `user_id` REFERENCES idp_user WITHOUT A CASCADE, like every other user table here (V3, V4):
-- Users.delete removes an account's children explicitly, children first, and this table is one of
-- them.
create table idp_device (
    id uuid not null primary key,
    user_id uuid not null references idp_user (id),
    label varchar(200) not null,
    created_at timestamp(6) with time zone not null,
    last_used_at timestamp(6) with time zone not null,
    expires_at timestamp(6) with time zone not null,
    absolute_expires_at timestamp(6) with time zone not null,
    revoked_at timestamp(6) with time zone
);

-- "Which devices does this account have", for the account page that lists and revokes them.
create index idx_idp_device_user on idp_device (user_id);

-- Every secret a device has ever been given, by fingerprint. The CURRENT one is the row whose
-- `superseded_at` is null — exactly one per live device, written in the same transaction that
-- supersedes its predecessor.
--
-- SPENT SECRETS ARE KEPT, and that is what they are for: a spent secret presented again is either
-- two tabs of the same browser resuming at once (superseded seconds ago — within
-- qits.idp.device.reuse-grace, answered with a session and no rotation) or a copy somebody else
-- holds (older — the whole device is revoked). Without the row the second case would look like an
-- unknown value, and a stolen cookie would be refused without the theft ever being noticed.
--
-- `device_id` CASCADES: a secret means nothing without its device, and Users.delete then needs only
-- to delete the device rows.
create table idp_device_secret (
    token_hash varchar(255) not null primary key,
    device_id uuid not null references idp_device (id) on delete cascade,
    created_at timestamp(6) with time zone not null,
    superseded_at timestamp(6) with time zone
);

create index idx_idp_device_secret_device on idp_device_secret (device_id);

-- The device a session was opened through, or null for a session from an ordinary login. It is
-- what lets revoking a device end the sessions it opened, and what lets logout forget the device
-- behind the session it ends. ON DELETE SET NULL: deleting a device row (Users.delete does, after
-- the sessions) must never take a session row with it implicitly.
alter table idp_session add column device_id uuid references idp_device (id) on delete set null;

create index idx_idp_session_device on idp_session (device_id);
