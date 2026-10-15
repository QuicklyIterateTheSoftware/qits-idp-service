package eu.wohlben.qits.idp.control;

import eu.wohlben.qits.db.DbRetry;
import eu.wohlben.qits.idp.entity.IdpUser;
import eu.wohlben.qits.idp.entity.IdpUserRole;
import eu.wohlben.qits.idp.entity.IdpWebAuthnCredential;
import eu.wohlben.qits.idp.error.AuthException;
import eu.wohlben.qits.idp.persistence.IdpAuthorizationCodeRepository;
import eu.wohlben.qits.idp.persistence.IdpRegisterTokenRepository;
import eu.wohlben.qits.idp.persistence.IdpSessionRepository;
import eu.wohlben.qits.idp.persistence.IdpUserRepository;
import eu.wohlben.qits.idp.persistence.IdpUserRoleRepository;
import eu.wohlben.qits.idp.persistence.IdpWebAuthnCredentialRepository;
import eu.wohlben.qits.idp.persistence.IdpWorkstationRefreshTokenRepository;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * The account store: users, their roles, their authenticators and their optional password.
 *
 * <p>This class does one thing at a time. The <b>registration</b> — create the account, store the
 * factor, spend the token, grant the roles, open the session, all or nothing — is {@link
 * Registrations}, which is the only class that knows this one, {@link RegisterTokens} and {@link
 * Sessions} all exist. That split is the same one {@link ClientRegistry} makes over the two halves
 * of the client registry, and for the same reason: the composite operation is where the interesting
 * decisions are, so it gets a name.
 *
 * <p><b>Every public method owns its transaction</b> through {@link DbRetry}, which is what holds a
 * login through a postgres cutover. The package-private {@code …Row} methods beside them do the
 * same work <b>inside the caller's</b> transaction, and exist only so {@link Registrations} can put
 * one boundary around the five writes a registration is.
 */
@ApplicationScoped
public class Users {

  /**
   * What a bootstrap registration grants, and the only thing that writes {@code idp_user_role}
   * today. Namespaced {@code $app:$resource:$role} with the resource segment omitted while unused.
   *
   * <p>These two are the plan's decision rather than a config key on purpose. A deployment that
   * could choose them could bootstrap an installation whose first account administers nothing, and
   * there is no second operator to fix it — the register token is one-time. Roles are inert today
   * anyway: nothing enforces one, and the enforcement plan is where a roster becomes a question
   * worth configuring.
   */
  public static final List<String> BOOTSTRAP_ROLES = List.of("qits:admin");

  /** As long as the column allows. A name is an identity, not a document. */
  private static final int USERNAME_LENGTH = 128;

  /** One account, as everything outside persistence sees it — a record, so nothing holds an entity. */
  public record Account(UUID id, String username, List<String> roles) {}

  /**
   * One account as the admin listing shows it (qits-1260): its name, when it was made, its roles.
   * Never a hash and never a credential — there is no field here that could carry one.
   */
  public record Summary(String username, Instant createdAt, List<String> roles) {}

  /**
   * One stored authenticator, in the shape quarkus-security-webauthn needs it back in. It carries
   * the username as well as the user id because the extension's own credential record is keyed by
   * name.
   */
  public record Credential(
      String credentialId,
      UUID userId,
      String username,
      UUID aaguid,
      byte[] publicKey,
      long publicKeyAlgorithm,
      long counter) {}

  /**
   * An authenticator a ceremony has just verified, on its way in. It is {@link Credential} minus
   * the account, because at registration time the account may not exist yet — these six fields are
   * exactly what {@code WebAuthnCredentialRecord.RequiredPersistedData} carries, minus the username
   * the join provides.
   */
  public record NewAuthenticator(
      String credentialId,
      UUID aaguid,
      byte[] publicKey,
      long publicKeyAlgorithm,
      long counter) {}

  @Inject IdpUserRepository users;

  @Inject IdpUserRoleRepository roles;

  @Inject IdpWebAuthnCredentialRepository credentials;

  @Inject IdpSessionRepository sessions;

  @Inject IdpAuthorizationCodeRepository authorizationCodes;

  @Inject IdpWorkstationRefreshTokenRepository refreshTokens;

  @Inject IdpRegisterTokenRepository registerTokens;

  /** The account with this login name, or empty. */
  public Optional<Account> byUsername(String username) {
    return DbRetry.inNewTx(
        "load an idp user by name", () -> Optional.ofNullable(accountOf(users.findByUsername(username))));
  }

  /** The account with this id, or empty. */
  public Optional<Account> byId(UUID userId) {
    return DbRetry.inNewTx(
        "load an idp user", () -> Optional.ofNullable(accountOf(users.findById(userId))));
  }

  /**
   * Every account, sorted by username in Java's natural string order — the same reason {@link
   * IdpUserRoleRepository#rolesOf} sorts in memory: a postgres collation would order punctuation
   * differently per installation, and this list leaves the service.
   *
   * <p>Two reads, the users and every role row, rather than one role read per user: an
   * installation's accounts are a handful, and this keeps it a handful of rows either way.
   */
  public List<Summary> list() {
    return DbRetry.inNewTx(
        "list idp users",
        () -> {
          Map<UUID, List<String>> rolesByUser =
              roles.listAll().stream()
                  .collect(
                      Collectors.groupingBy(
                          row -> row.userId,
                          Collectors.mapping(row -> row.role, Collectors.toList())));
          return users.listAll().stream()
              .map(
                  user ->
                      new Summary(
                          user.username,
                          user.createdAt,
                          rolesByUser.getOrDefault(user.id, List.of()).stream().sorted().toList()))
              .sorted(Comparator.comparing(Summary::username))
              .toList();
        });
  }

  /**
   * Remove an account and everything keyed to it (qits-1260): its roles, its passkeys, its password
   * (a column of the row itself), its sessions, its authorization codes and its workstation/CLI
   * refresh tokens. One transaction, so a half-deleted account — a session that still introspects
   * for a user who is gone, or a user with no way in and no way out — is unreachable.
   *
   * <p><b>This owns its transaction and touches the other user tables through their repositories
   * directly</b>, not through {@link Sessions}' or {@link RegisterTokens}' {@code …Row} methods: it
   * is a public method of this class, so it is the "owns its boundary" half of the two shapes, and
   * nothing it writes needs the logic those classes keep (a session row is deleted, not revoked —
   * there is no account left for an audit of it to belong to).
   *
   * <p><b>A register token the account was made from keeps its {@code consumed_at}</b> and loses
   * only its {@code created_user_id} link: the token stays spent, which is what matters, and V3's
   * foreign key leaves no other way to let the user row go short of a migration. Register tokens
   * the account itself <i>minted</i> are untouched: an outstanding invite is for somebody else.
   *
   * <p>None of the foreign keys cascade (V3, V4), which is why the order below is children first.
   * Deleted sessions stop introspecting on the next call; the edge's own cache is the only lag.
   *
   * @return false when no account has this name
   */
  public boolean delete(String username) {
    return DbRetry.inNewTx(
        "delete an idp user",
        () -> {
          IdpUser user = users.findByUsername(username);
          if (user == null) {
            return false;
          }
          UUID id = user.id;
          registerTokens.update("createdUserId = null where createdUserId = ?1", id);
          sessions.delete("userId", id);
          authorizationCodes.delete("userId", id);
          refreshTokens.delete("userId", id);
          credentials.delete("userId", id);
          roles.delete("userId", id);
          users.delete("id", id);
          return true;
        });
  }

  /** Every authenticator registered under this login name. Empty for an unknown name. */
  public List<Credential> credentialsOf(String username) {
    return DbRetry.inNewTx(
        "list a user's webauthn credentials",
        () -> {
          IdpUser user = users.findByUsername(username);
          if (user == null) {
            return List.of();
          }
          return credentials.listForUser(user.id).stream()
              .map(row -> toCredential(row, user.username))
              .toList();
        });
  }

  /** The authenticator with this credential id, or empty. */
  public Optional<Credential> credentialById(String credentialId) {
    return DbRetry.inNewTx(
        "load a webauthn credential",
        () -> {
          IdpWebAuthnCredential row = credentials.findById(credentialId);
          if (row == null) {
            return Optional.empty();
          }
          IdpUser user = users.findById(row.userId);
          return user == null ? Optional.empty() : Optional.of(toCredential(row, user.username));
        });
  }

  /**
   * Write back an authenticator's signature counter after a successful login.
   *
   * <p><b>This is not bookkeeping.</b> The counter only ever increases, so a login presenting one
   * that did not move forward is a cloned authenticator and webauthn4j refuses it — a check that
   * only works while the newest value is stored, which is what this does.
   */
  public void recordCounter(String credentialId, long counter) {
    DbRetry.runInNewTx(
        "update a webauthn credential's counter",
        () -> {
          IdpWebAuthnCredential row = credentials.findById(credentialId);
          if (row != null) {
            row.counter = counter;
          }
        });
  }

  /** Add an authenticator to an existing account — a second passkey, added from a live session. */
  public void addCredential(UUID userId, NewAuthenticator authenticator) {
    DbRetry.runInNewTx("store a webauthn credential", () -> addCredentialRow(userId, authenticator));
  }

  /**
   * Set or replace this account's password.
   *
   * <p>Non-empty is the whole rule, and there is deliberately no second one — see {@link
   * PasswordHash}. Replacing is the same call as setting: an account that had none simply had a
   * null column.
   */
  public void setPassword(UUID userId, String password) {
    String hash = PasswordHash.of(requirePassword(password));
    DbRetry.runInNewTx(
        "set an idp user's password",
        () -> {
          IdpUser user = users.findById(userId);
          if (user == null) {
            throw AuthException.invalidCredentials("no such user");
          }
          user.passwordHash = hash;
        });
  }

  /**
   * The account this name and password belong to, or empty.
   *
   * <p>Empty for an unknown name, for an account with no password factor, and for a wrong password
   * alike. The caller answers all three the same way, which is what keeps this endpoint from being
   * a "does this username exist" oracle.
   */
  public Optional<Account> authenticate(String username, String password) {
    if (username == null || password == null || password.isEmpty()) {
      return Optional.empty();
    }
    return DbRetry.inNewTx(
        "authenticate an idp user by password",
        () -> {
          IdpUser user = users.findByUsername(username);
          if (user == null || !PasswordHash.matches(user.passwordHash, password)) {
            return Optional.empty();
          }
          return Optional.of(accountOf(user));
        });
  }

  /**
   * A login name reduced to what may be stored, or a refusal.
   *
   * <p>Trimmed, non-empty, and at most {@value #USERNAME_LENGTH} characters. The one restriction
   * that is not about the column: <b>no control characters</b>. A username leaves this service as
   * the value of the {@code X-Qits-User} header the edge injects and five services already read, so
   * a name carrying a carriage return would be a header-splitting hole in every one of them. Beyond
   * that the name is the user's own — no case folding, no character class, no reserved words.
   */
  public static String normaliseUsername(String username) {
    String name = username == null ? "" : username.trim();
    if (name.isEmpty()) {
      throw AuthException.invalidRequest("a username is required");
    }
    if (name.length() > USERNAME_LENGTH) {
      throw AuthException.invalidRequest(
          "a username may be at most " + USERNAME_LENGTH + " characters");
    }
    for (int i = 0; i < name.length(); i++) {
      if (Character.isISOControl(name.charAt(i))) {
        throw AuthException.invalidRequest("a username may not contain control characters");
      }
    }
    return name;
  }

  /** A password as it may be stored, or a refusal. Non-empty is the whole rule. */
  public static String requirePassword(String password) {
    if (password == null || password.isEmpty()) {
      throw AuthException.invalidRequest("a password must not be empty");
    }
    return password;
  }

  // --- inside the caller's transaction, for Registrations ------------------------------------

  /**
   * Create the account. Runs in the caller's transaction — {@link Registrations} is holding one
   * around the whole registration, because a token spent against a user that was not created is the
   * one state this must not be able to reach.
   */
  IdpUser createRow(String username, String password) {
    if (users.findByUsername(username) != null) {
      throw AuthException.invalidRequest("that username is taken");
    }
    IdpUser user = new IdpUser();
    user.id = UUID.randomUUID();
    user.username = username;
    user.passwordHash = password == null ? null : PasswordHash.of(password);
    user.createdAt = Instant.now();
    users.persist(user);
    return user;
  }

  /** Grant roles, in the caller's transaction. Granting one twice would violate the pair key. */
  void grantRows(UUID userId, List<String> granted) {
    for (String role : granted) {
      IdpUserRole row = new IdpUserRole();
      row.userId = userId;
      row.role = role;
      row.createdAt = Instant.now();
      roles.persist(row);
    }
  }

  /** Store an authenticator, in the caller's transaction. */
  void addCredentialRow(UUID userId, NewAuthenticator authenticator) {
    IdpWebAuthnCredential row = new IdpWebAuthnCredential();
    row.credentialId = authenticator.credentialId();
    row.userId = userId;
    row.aaguid = authenticator.aaguid();
    row.publicKey = authenticator.publicKey();
    row.publicKeyAlgorithm = authenticator.publicKeyAlgorithm();
    row.counter = authenticator.counter();
    row.createdAt = Instant.now();
    credentials.persist(row);
  }

  /** One account with its roles, in the caller's transaction. */
  Account accountOf(IdpUser user) {
    return user == null ? null : new Account(user.id, user.username, roles.rolesOf(user.id));
  }

  private static Credential toCredential(IdpWebAuthnCredential row, String username) {
    return new Credential(
        row.credentialId,
        row.userId,
        username,
        row.aaguid,
        row.publicKey,
        row.publicKeyAlgorithm,
        row.counter);
  }
}
