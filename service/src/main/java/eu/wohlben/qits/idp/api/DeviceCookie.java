package eu.wohlben.qits.idp.api;

import java.time.Duration;

/**
 * The {@code qits-device} cookie (qits-1944): a remembered browser's rotating credential, which
 * {@code POST /idp/api/auth/resume} spends for a fresh {@link SessionCookie}. Built by hand for the
 * reason {@link SessionCookie} gives. What goes on the wire is:
 *
 * <pre>qits-device=&lt;value&gt;; Path=/idp/api/auth; Max-Age=7776000; HttpOnly; SameSite=Lax</pre>
 *
 * <p>with {@code ; Secure} appended over https, by {@link SessionCookie#isSecure}. Where it differs
 * from the session cookie, and why:
 *
 * <ul>
 *   <li><b>Path=/idp/api/auth</b> — the edge never needs this cookie and no other service should
 *       ever see it. It travels only to login, resume and logout, the three routes that read or
 *       clear it; every other request leaves it in the jar.
 *   <li><b>No Domain, ever</b> — host-only, on the idp's own host. A session is shared across the
 *       platform's browser-facing hosts by its parent domain; a device is a credential for exactly
 *       one door, and a sibling host has no business being offered it.
 *   <li><b>Max-Age</b> — the time left until the device's fixed deadline, so a browser never holds
 *       a device cookie the store has stopped honouring.
 * </ul>
 *
 * <p>HttpOnly and SameSite=Lax for the session cookie's reasons.
 */
public final class DeviceCookie {

  /** The cookie's name, as resume reads it and every test asserts it. */
  public static final String NAME = "qits-device";

  /** The one path the cookie is scoped to: the user surface's own routes. */
  public static final String PATH = "/idp/api/auth";

  private DeviceCookie() {}

  /** The {@code Set-Cookie} line that remembers a device, or rotates its secret. */
  public static String set(String value, Duration ttl, boolean secure) {
    return line(value, Math.max(0, ttl.toSeconds()), secure);
  }

  /**
   * The line that forgets one: the same name and path, an empty value, {@code Max-Age=0}. The path
   * has to match, or the browser keeps the old cookie beside a new empty one.
   */
  public static String clear(boolean secure) {
    return line("", 0, secure);
  }

  private static String line(String value, long maxAgeSeconds, boolean secure) {
    StringBuilder cookie = new StringBuilder(NAME).append('=').append(value);
    cookie.append("; Path=").append(PATH);
    cookie.append("; Max-Age=").append(maxAgeSeconds);
    cookie.append("; HttpOnly");
    cookie.append("; SameSite=Lax");
    if (secure) {
      cookie.append("; Secure");
    }
    return cookie.toString();
  }
}
