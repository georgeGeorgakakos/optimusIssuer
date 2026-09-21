import { useState } from "react";
import { api, downloadCredential } from "../api.js";
import CapabilityEditor from "../components/CapabilityEditor.jsx";

export default function Issue() {
  const [did, setDid] = useState("");
  const [name, setName] = useState("");
  const [org, setOrg] = useState("");
  const [caps, setCaps] = useState([]);
  const [days, setDays] = useState(90);
  const [issued, setIssued] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  const didLooksValid = /^did:key:z[1-9A-HJ-NP-Za-km-z]{40,}$/.test(did.trim());

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const vc = await api.issue({
        subject_did: did.trim(),
        name,
        organisation: org,
        capabilities: caps,
        validity_days: Number(days),
      });
      setIssued(vc);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="page">
      <h1>Issue a credential directly</h1>
      <p className="muted">
        Use this when a request did not come through the queue — for example when
        onboarding by hand, or reissuing after an expiry.
      </p>

      <form onSubmit={submit}>
        <label>
          Subject DID
          <input value={did} onChange={(e) => setDid(e.target.value)}
                 placeholder="did:key:z6Mk..." spellCheck="false" />
        </label>
        {did && !didLooksValid && (
          <p className="warn">That does not look like an Ed25519 did:key.</p>
        )}

        <label>
          Name
          <input value={name} onChange={(e) => setName(e.target.value)}
                 placeholder="Attica Solar Ingest" />
        </label>

        <label>
          Organisation
          <input value={org} onChange={(e) => setOrg(e.target.value)} placeholder="ICCS" />
        </label>

        <h3>Capabilities</h3>
        <CapabilityEditor value={caps} onChange={setCaps} />

        <label>
          Validity in days
          <input type="number" min="1" value={days}
                 onChange={(e) => setDays(e.target.value)} />
        </label>

        {error && <p className="error">{error}</p>}

        <button disabled={busy || !didLooksValid || caps.length === 0}>
          {busy ? "signing…" : "sign credential"}
        </button>
      </form>

      {issued && (
        <div className="issued">
          <h3>Credential signed</h3>
          <button onClick={() => downloadCredential(issued)}>download credential</button>
          <pre>{JSON.stringify(issued, null, 2)}</pre>
        </div>
      )}
    </div>
  );
}
