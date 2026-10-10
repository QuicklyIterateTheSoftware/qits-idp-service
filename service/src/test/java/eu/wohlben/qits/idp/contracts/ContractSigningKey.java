package eu.wohlben.qits.idp.contracts;

/**
 * The signing key the {@value ProviderStates#A_PUBLISHED_SIGNING_KEY} state installs: a fixed RSA
 * pair, so the recorded JWKS carries a real, stable {@code kid}, {@code n} and {@code e}. A
 * consumer's JWT library parses the modulus, and drops a key whose {@code n} does not parse — so
 * it cannot be recorded as opaque.
 *
 * <p>A TEST KEY, generated for this suite and published here on purpose. It signs only inside the
 * test application; nothing outside it trusts this key.
 */
final class ContractSigningKey {

  /** The {@code kid} it is published under. */
  static final String KID = "contract-signing-key";

  /** PKCS#8 DER, base64. */
  static final String PRIVATE_KEY =
      "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDDbY785uCWc0brQ+95o2gNi6tX"
          + "ZSHC+Aycv3W0TjAG5YVjXJoS6Mh6OOrZDL7O867BibZAq8dT4qFDiddYYnwj6VdFoI+WagVhcVd6"
          + "UEyntptKR6s2oF/8Glz9mP9xbuvh7r2AOQr7dwKE5OmxSFfPK41qcqH6HzjRiqEA+V32XPYCSvhP"
          + "mFMyWCOM5qBZpf8GQgw+a52IxDxS/mmlHakRNwBSLYPfkvY7BUwHOqNDLKQFwghmAcz2o1RJCYnL"
          + "42N1Izgwl+OC7FHbdifgOmnkeScZuFM5D5n3T+d5TxRU4qGHMOX+1RulP1D2KGomZGZewjJLHaFc"
          + "QKYKEsig6oyXAgMBAAECggEAMf2qGJaEt+e4KgGAVljPCrwCMgJ8PvAN5eDyHpPrpC/9TZwIC7NB"
          + "aUZ7CNfCTZU3TGnKVcO7YwFzqB+wFvtmbxdHDFgUsvDe/HyuWGsHGNXU5ozrxrcCpq4lwHdtTJqH"
          + "u41DK3QsE4RvgAhAoWl0kNm+vI6jUaS/95YjNmkTuKu/i3Xz0tzfqb3yguwzTSLa3/kYqO6t+zal"
          + "9jboO39K85/OhNS1IKxaz0cIYC26tTC1awEe110J6mvOkbOBz7tJlktUsyhyhIyR7kteUM2ptQc+"
          + "KArQoTzXzEwjiGZ/C15HM4L8KCNkqS6aQtxk1xqR11Fj200yH/azfb65MziDTQKBgQDbMqpXyFu1"
          + "soBFuuMFdrRBdvdEw2v+ZppC6lJqlQ/Ez7Y4SzEw+Z+IW4U1inihv4B8kI9sEuOQ90RV8RortaIP"
          + "dQq37kc6SIP0fnQcOSuz1Q54w+cU18w1eDAac3hAmQ++wrlObmLu3bgABxrw1DDc0STVSZxx/PS4"
          + "1BKa/XhKswKBgQDkPTz35JDz+zfru9C8bDb/wHKl6m+69Sr4xvnaZHQDUSqfsEMEwvlyK21PguMk"
          + "81C8iA5Wl8KdlVppnh/ESa8rrX/jm7Kp3pvJt1uwQb8fM44HcOpA/3zO/2GG8FpzaQnIHcH8l1Eg"
          + "EsTu1HT5LgzT6fdhIjKa2asVpc6Yo4T4jQKBgQDHvta9oaX44E3FvTUtgGtokIlpjw91R3hha/ho"
          + "iadR+NobWGHeOEspTgUIskOVWdYzLOSVXm0jaEBMdKYdmKmynjyDOc6MjRI6FZWnNm3dtVQ3toV4"
          + "V+IOA5UKNZkqfJB9jCKjFzJua3tGAzOIrEROpQOEnUzEDvfPCepedIZOwwKBgFCEig2pxLlN1tyC"
          + "1ZCjXIO9ELUXj3MVKqO5DkvNRGAnMjJDrGDxp65vQ5DZS+itLb5VATnrL+0H022PKwXEONffzU4u"
          + "j0j+D1eKJ/52M0Z+mYxmeT2U5CLiVTWVdVNhquG+HcFOYIBAHtlieiGt7TiVQYAy4EdgospwRAH1"
          + "LePBAoGAH14blBOnHV6WFZyhaep92iM7BxRMfY4c10Bib299QvRaLVX57skwNMhPohYp7L+864AF"
          + "AOYaWLhdTLYLsfBoMfzzWeYk+vsDspPGGeHDJI16OPYQL3iKv/cBV3LArC38TyLmJOSyutCpTiZM"
          + "dDCSezbwKn5Pk0sb60q0wdJfM1I=";

  /** X.509 SubjectPublicKeyInfo DER, base64. */
  static final String PUBLIC_KEY =
      "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAw22O/ObglnNG60PveaNoDYurV2UhwvgM"
          + "nL91tE4wBuWFY1yaEujIejjq2Qy+zvOuwYm2QKvHU+KhQ4nXWGJ8I+lXRaCPlmoFYXFXelBMp7ab"
          + "SkerNqBf/Bpc/Zj/cW7r4e69gDkK+3cChOTpsUhXzyuNanKh+h840YqhAPld9lz2Akr4T5hTMlgj"
          + "jOagWaX/BkIMPmudiMQ8Uv5ppR2pETcAUi2D35L2OwVMBzqjQyykBcIIZgHM9qNUSQmJy+NjdSM4"
          + "MJfjguxR23Yn4Dpp5HknGbhTOQ+Z90/neU8UVOKhhzDl/tUbpT9Q9ihqJmRmXsIySx2hXECmChLI"
          + "oOqMlwIDAQAB";

  private ContractSigningKey() {}
}
