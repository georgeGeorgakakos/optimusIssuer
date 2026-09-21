import { useEffect, useState } from "react";
import { api } from "../api.js";
import { hasRole } from "../auth.js";

export default function Trust() {
  const [issuers, setIssuers] = useState([]);
  const [did, setDid] = useState("");
  const [name, setName] = useState("");
  const [error, setError] = useState(null);
  const admin = hasRole("issuer:admin");

  async function load() {
    try {
      const r = await api.listTrust();
      setIssuers(r.issuers || []);
    } catch (e) {
      setError(e.message);
    }
  }
  useEffect(() => { load(); }, []);

  async function add(e) {
    e.preventDefault();
    if (!confirm(
      `Add ${name} as a trusted issuer?\n\n` +
      "This delegates the ability to grant capabilities in this swarm. " +
      "Every agent will accept credentials signed by this DID."
    )) return;
    try {
      await api.upsertTrust({
        _id: did.trim(), name, may_issue: ["OptimusDBCapability"],
        max_delegation_depth: 2, status: "active",
      });
      setDid(""); setName(""); load();
    } catch (err) {
      setError(err.message);
    }
  }

  async function setStatus(iss, status) {
    if (!confirm(
      status === "inactive"
        ? `Deactivate ${iss.name}?\n\nEvery credential this issuer has signed will stop verifying.`
        : `Reactivate ${iss.name}?`
    )) return;
    await api.upsertTrust({ ...iss, status });
    load();
  }

  return (
    <div className="page">
      <h1>Trust list</h1>
      <p className="muted">
        The issuers this swarm accepts. Held in the kbtrust store and replicated to every
        agent, so this list is not served by any component — it is data each agent holds.
      </p>
      {error && <p className="error">{error}</p>}

      <table>
        <thead>
          <tr><th>Name</th><th>DID</th><th>May issue</th><th>Status</th><th></th></tr>
        </thead>
        <tbody>
          {issuers.map((i) => (
            <tr key={i._id} className={i.status !== "active" ? "dim" : ""}>
              <td>{i.name}</td>
              <td><code className="did">{i._id}</code></td>
              <td>{(i.may_issue || []).join(", ")}</td>
              <td>{i.status}</td>
              <td>
                {admin && i.status === "active" && (
                  <button className="danger" onClick={() => setStatus(i, "inactive")}>
                    deactivate
                  </button>
                )}
                {admin && i.status !== "active" && (
                  <button onClick={() => setStatus(i, "active")}>reactivate</button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {admin ? (
        <form onSubmit={add} className="panel">
          <h2>Add a trusted issuer</h2>
          <p className="warn">
            This is the most consequential action here. A party on this list can grant
            capabilities without asking anyone. Add only issuers you have verified
            out of band.
          </p>
          <label>
            Issuer DID
            <input value={did} onChange={(e) => setDid(e.target.value)}
                   placeholder="did:key:z6Mk..." spellCheck="false" />
          </label>
          <label>
            Name
            <input value={name} onChange={(e) => setName(e.target.value)}
                   placeholder="SZTAKI Issuing Authority" />
          </label>
          <button disabled={!did || !name}>add issuer</button>
        </form>
      ) : (
        <p className="muted">Modifying the trust list requires the issuer:admin role.</p>
      )}
    </div>
  );
}
