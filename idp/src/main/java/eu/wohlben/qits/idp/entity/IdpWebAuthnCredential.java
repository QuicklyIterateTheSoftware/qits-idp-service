package eu.wohlben.qits.idp.entity;

import io.quarkus.hibernate.orm.panache.PanacheEntityBase;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/**
 * One registered authenticator — a passkey.
 *
 * <p><b>These fields are not a design.</b> They are exactly {@code
 * WebAuthnCredentialRecord.RequiredPersistedData} from quarkus-security-webauthn 3.34.6, read off
 * the extension's own source: that record is what {@code fromRequiredPersistedData} reassembles a
 * usable credential out of when a login arrives, so anything missing here is a login that cannot be
 * verified. The record's own {@code username} member is the one thing not stored — the join to
 * {@link IdpUser} carries it, and a second copy would be a second spelling of the same account.
 *
 * <p>{@link #counter} is the part that is not merely storage: an authenticator's signature counter
 * only ever increases, so a login presenting a counter that did not move forward is a cloned
 * authenticator and webauthn4j refuses it. That check only works if the new value is written back
 * on every successful login, which is why this column is updated rather than written once.
 *
 * <p>Many rows per user is the intended shape: a second authenticator is added from a logged-in
 * session, and removing one is a delete here — its owner's, through {@code DELETE
 * /idp/api/passkeys/{credentialId}} ({@code Users.removePasskey}, qits-1953), which refuses the
 * last one of an account that has no password.
 */
@Entity
@Table(name = "idp_webauthn_credential")
public class IdpWebAuthnCredential extends PanacheEntityBase {

  /**
   * The credential id, base64url. Unique by the WebAuthn spec, and the only thing a login names, so
   * it is the row's identity. The width is the spec's own bound — a credential id is at most 1023
   * bytes, and base64url of 1023 bytes is 1364 characters.
   */
  @Id
  @Column(name = "credential_id", length = 1364)
  public String credentialId;

  /** The account this authenticator logs in. */
  @Column(name = "user_id", nullable = false)
  public UUID userId;

  /** The authenticator model's identity. All zeroes for the software ones, which is normal. */
  @Column(name = "aaguid", nullable = false)
  public UUID aaguid;

  /** X.509 SubjectPublicKeyInfo. Bytes, because that is what the extension hands over and back. */
  @Column(name = "public_key", nullable = false)
  public byte[] publicKey;

  /**
   * The COSE algorithm identifier of {@link #publicKey}. <b>Negative</b> — -7 is ES256, -257 is
   * RS256 — which is why this is a signed number and not an enum of our own.
   */
  @Column(name = "public_key_algorithm", nullable = false)
  public long publicKeyAlgorithm;

  /** The signature counter, as of the last successful login. See the class comment. */
  @Column(name = "counter", nullable = false)
  public long counter;

  @Column(name = "created_at", nullable = false)
  public Instant createdAt;
}
