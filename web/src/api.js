import { token } from "./auth.js";

const BASE = import.meta.env.VITE_API_BASE || "/api/v1/issuer";

async function call(path, { method = "GET", body } = {}) {
  const headers = { "Content-Type": "application/json" };
  const t = token();
  if (t) headers.Authorization = `Bearer ${t}`;

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  let payload = null;
  try {
    payload = await res.json();
  } catch {
    payload = null;
  }
  if (!res.ok) {
    const message = payload?.error || `HTTP ${res.status}`;
    const err = new Error(message);
    err.status = res.status;
    err.payload = payload;
    throw err;
  }
  return payload;
}

export const api = {
  info: () => call("/info"),
  health: () => call("/health"),

  listRequests: (status) =>
    call(`/requests${status ? `?status=${encodeURIComponent(status)}` : ""}`),
  submitRequest: (body) => call("/requests", { method: "POST", body }),
  approve: (id, body) => call(`/requests/${id}/approve`, { method: "POST", body }),
  reject: (id, reason) =>
    call(`/requests/${id}/reject`, { method: "POST", body: { reason } }),

  issue: (body) => call("/credentials", { method: "POST", body }),
  listCredentials: () => call("/credentials"),
  revoke: (id, body) => call(`/credentials/${id}/revoke`, { method: "POST", body }),

  listTrust: () => call("/trust"),
  upsertTrust: (body) => call("/trust", { method: "POST", body }),

  audit: () => call("/audit"),
};

// A credential is handed back as a file. It is not a secret — without the
// holder's private key it grants nothing — so a plain download is appropriate.
export function downloadCredential(vc) {
  const blob = new Blob([JSON.stringify(vc, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${vc.credentialSubject?.name || "credential"}.vc.json`
    .replace(/[^a-zA-Z0-9._-]/g, "_");
  a.click();
  URL.revokeObjectURL(url);
}
