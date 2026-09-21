import { useEffect, useState } from "react";
import { api } from "../api.js";

function daysLeft(iso) {
  if (!iso) return null;
  return Math.round((new Date(iso) - Date.now()) / 86400000);
}

export default function Credentials() {
  const [rows, setRows] = useState([]);
  const [filter, setFilter] = useState("");
  const [error, setError] = useState(null);

  async function load() {
    try {
      const r = await api.listCredentials();
      setRows(r.credentials || []);
    } catch (e) {
      setError(e.message);
    }
  }
  useEffect(() => { load(); }, []);

  async function revoke(row) {
    const reason = prompt(`Revoke ${row._id}?\n\nReason:`);
    if (reason === null) return;
    await api.revoke(row._id, { subject_did: row.subject_did, reason });
    alert(
      "Revocation recorded. It takes effect as the record replicates to each agent; " +
      "until then the credential remains usable."
    );
    load();
  }

  const shown = rows.filter((r) =>
    !filter ||
    (r.subject_name || "").toLowerCase().includes(filter.toLowerCase()) ||
    (r.subject_did || "").includes(filter)
  );

  return (
    <div className="page">
      <h1>Issued credentials</h1>
      {error && <p className="error">{error}</p>}

      <input className="filter" placeholder="filter by name or DID"
             value={filter} onChange={(e) => setFilter(e.target.value)} />

      <table>
        <thead>
          <tr>
            <th>Subject</th><th>DID</th><th>Capabilities</th>
            <th>Expires</th><th>Status</th><th></th>
          </tr>
        </thead>
        <tbody>
          {shown.map((r) => {
            const left = daysLeft(r.expires_at);
            return (
              <tr key={r._id} className={r.status === "revoked" ? "dim" : ""}>
                <td>{r.subject_name || "—"}</td>
                <td><code className="did">{r.subject_did}</code></td>
                <td>{(r.capabilities || []).length}</td>
                <td className={left !== null && left < 14 ? "warn-cell" : ""}>
                  {(r.expires_at || "—").slice(0, 10)}
                  {left !== null && <span className="muted"> ({left}d)</span>}
                </td>
                <td>{r.status}</td>
                <td>
                  {r.status !== "revoked" && (
                    <button className="danger" onClick={() => revoke(r)}>revoke</button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>

      <p className="muted">
        Credentials expiring within two weeks are highlighted. Reissue before expiry
        rather than relying on revocation, which is not immediate.
      </p>
    </div>
  );
}
