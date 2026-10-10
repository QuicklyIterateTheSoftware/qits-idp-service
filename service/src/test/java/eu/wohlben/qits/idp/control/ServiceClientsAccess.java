package eu.wohlben.qits.idp.control;

/**
 * Test access to {@link ServiceClients#load()}, which is package-visible: a contract state that
 * rewrites rows directly reloads the cache through this.
 */
public final class ServiceClientsAccess {

  private ServiceClientsAccess() {}

  public static void reload(ServiceClients serviceClients) {
    serviceClients.load();
  }
}
