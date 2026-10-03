package eu.wohlben.qits.idp.control;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * A client's shared secret, and the one operation anything here needs from it: does a presented
 * value match.
 *
 * <p>Every secret here is <b>stored as a hash</b> — a commissioned client's in {@code
 * idp_client.secret_hash}, a service client's in {@code idp_service_client.secret_hash}. <b>The
 * plaintext exists once</b>, in the commission or create/rotate response, and is never written down
 * here. A dump of the idp's database therefore mints nothing. (There used to be a second kind, a
 * plaintext secret read from configuration for an environment client. qits-163 retired it: those
 * secrets were hashed into {@code idp_service_client} once, by {@link EnvironmentClientAdoption}.)
 *
 * <p><b>A service client during a rotation carries two hashes.</b> {@code ServiceClients.rotate}
 * keeps the previous hash live for fifteen minutes (D4 of epic qits-540, dossier page "Plan (as of
 * 2026-09-13)"), so a start-first rollback to the predecessor container — still holding the old
 * secret — is not locked out. {@link #serviceClient} is where both hashes are tried: the current
 * hash, then the previous hash while it is still live. The expiry is checked at {@link #matches},
 * not at construction, because a resolved client can sit in a request-scoped lookup for longer than
 * an instant.
 *
 * <p>The comparison uses {@link MessageDigest#isEqual}, never {@code String.equals}: it is against
 * a value a caller may retry freely.
 *
 * <p><b>Why a plain SHA-256 and not bcrypt/argon2.</b> Those exist to make guessing a
 * human-chosen password expensive. A commissioned or a service client's secret is 256 bits from
 * {@link java.security.SecureRandom} and is never chosen by anyone, so there is no guessing to slow
 * down — only a cost on the token path, which is the platform's whole call graph. A one-way
 * function is what the row needs and all it needs.
 *
 * <p><b>Which hash matched is reported, not just whether one did</b> (qits-880, release 1):
 * {@link #match} names the {@link Source}, so {@link ClientRegistry} can log it.
 *
 * <p><b>There used to be a third hash, and qits-880's release 2 retired it.</b> qits-163's hotfix
 * kept an environment client's old environment secret as {@code legacy_secret_hash} on its row and
 * accepted it here with no expiry. Release 1 logged which source each service client
 * authenticated with, to show nothing still presented that kept secret; release 2 stopped reading
 * the column. The column and its data stay — V11 is applied, and a rollback to release 1 must find
 * them intact to accept the kept secret again — but nothing here trusts them any more.
 */
public final class ClientSecret {

  /** Names the scheme in the stored value, so a second one can be added without a migration. */
  private static final String SHA256_PREFIX = "sha-256:";

  /** Which of a service client's up-to-two hashes matched, and the label a log line uses for it. */
  public enum Source {
    CURRENT("current"),
    PREVIOUS("previous");

    private final String label;

    Source(String label) {
      this.label = label;
    }

    /** The word {@code <current|previous>} takes in the log line. */
    public String label() {
      return label;
    }
  }

  /** One hash this secret accepts, and until when — null means no expiry. */
  private record Hash(String value, Instant validUntil, Source source) {
    boolean live(Instant now) {
      return validUntil == null || validUntil.isAfter(now);
    }
  }

  private final List<Hash> hashes;

  private ClientSecret(List<Hash> hashes) {
    this.hashes = hashes;
  }

  /** A commissioned client's secret, as the row holds it. No previous hash: commissions never rotate. */
  public static ClientSecret stored(String hash) {
    return new ClientSecret(
        hash == null ? List.of() : List.of(new Hash(hash, null, Source.CURRENT)));
  }

  /**
   * A service client's secret: the row's current hash, and its previous hash while it stays live —
   * either authenticates.
   *
   * @param currentHash the row's current hash
   * @param previousHash the row's previous hash after a rotation, or null when it never rotated or
   *     the grace has already been dropped from the row
   * @param previousValidUntil when {@code previousHash} stops being accepted; ignored when {@code
   *     previousHash} is null
   */
  public static ClientSecret serviceClient(
      String currentHash, String previousHash, Instant previousValidUntil) {
    List<Hash> hashes = new ArrayList<>(2);
    if (currentHash != null && !currentHash.isBlank()) {
      hashes.add(new Hash(currentHash, null, Source.CURRENT));
    }
    if (previousHash != null && !previousHash.isBlank() && previousValidUntil != null) {
      hashes.add(new Hash(previousHash, previousValidUntil, Source.PREVIOUS));
    }
    return new ClientSecret(List.copyOf(hashes));
  }

  /** What goes in a {@code secret_hash} column for this plaintext. */
  public static String hash(String plaintext) {
    return SHA256_PREFIX
        + Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString(sha256(plaintext.getBytes(StandardCharsets.UTF_8)));
  }

  /** Whether this secret can authenticate anything at all, right now. One with no live hash cannot. */
  public boolean usable() {
    Instant now = Instant.now();
    return hashes.stream().anyMatch(hash -> hash.live(now));
  }

  /** Whether {@code candidate} is this secret, by any live source. False when {@link #usable()} is false. */
  public boolean matches(String candidate) {
    return match(candidate).isPresent();
  }

  /**
   * Which live source {@code candidate} matched, or empty when none did — unknown, wrong, or a
   * hash whose grace has expired. Constant-time per hash, via {@link #equal}.
   */
  public Optional<Source> match(String candidate) {
    if (candidate == null || hashes.isEmpty()) {
      return Optional.empty();
    }
    String candidateHash = hash(candidate);
    Instant now = Instant.now();
    for (Hash hash : hashes) {
      if (hash.live(now) && equal(hash.value(), candidateHash)) {
        return Optional.of(hash.source());
      }
    }
    return Optional.empty();
  }

  private static boolean equal(String one, String other) {
    return MessageDigest.isEqual(
        one.getBytes(StandardCharsets.UTF_8), other.getBytes(StandardCharsets.UTF_8));
  }

  private static byte[] sha256(byte[] input) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(input);
    } catch (NoSuchAlgorithmException e) {
      // SHA-256 is required of every JVM. Reachable only in a native image that lost the provider,
      // which is the class of failure IdpPackagedSurfaceIT exists to catch.
      throw new IllegalStateException("SHA-256 is unavailable in this runtime", e);
    }
  }
}
