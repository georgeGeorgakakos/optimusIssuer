import Keycloak from "keycloak-js";

// The people using this interface are operators approving issuance, and a
// browser login suits them better than a key file. The machine identities in
// this system are DIDs; this is the one place a human logs in.
let keycloak = null;
let enabled = Boolean(import.meta.env.VITE_KEYCLOAK_URL);

export async function initAuth() {
  if (!enabled) {
    console.warn("Keycloak is not configured; running without operator authentication.");
    return;
  }
  keycloak = new Keycloak({
    url: import.meta.env.VITE_KEYCLOAK_URL,
    realm: import.meta.env.VITE_KEYCLOAK_REALM,
    clientId: import.meta.env.VITE_KEYCLOAK_CLIENT,
  });
  await keycloak.init({ onLoad: "login-required", pkceMethod: "S256" });

  // Refresh well before expiry so a long approval session never fails midway.
  setInterval(() => {
    keycloak.updateToken(60).catch(() => keycloak.login());
  }, 30000);
}

export function token() {
  return keycloak?.token ?? null;
}

export function operator() {
  if (!keycloak?.tokenParsed) return { name: "local operator", roles: ["issuer:admin"] };
  const t = keycloak.tokenParsed;
  return {
    name: t.preferred_username || t.sub,
    email: t.email,
    roles: t.realm_access?.roles ?? [],
  };
}

export function hasRole(role) {
  return operator().roles.includes(role);
}

export function logout() {
  if (keycloak) keycloak.logout();
}
