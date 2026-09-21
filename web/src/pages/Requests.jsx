import { useEffect, useState } from "react";
import { api, downloadCredential } from "../api.js";
import CapabilityEditor from "../components/CapabilityEditor.jsx";

export default function Requests() {
  const [requests, setRequests] = useState([]);
  const [open, setOpen] = useState(null);
  const [caps, setCaps] = useState([]);
  const [days, setDays] = useState(90);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [issued, setIssued] = useState(null);

  async function load() {
    try {
      const r = await api.listRequests("pending");
      setRequests(r.requests || []);
      setError(null);
    } catch (e) {
      setError(e.message);
    }
  }

  useEffect(() => { load(); }, []);

  function start(req) {
    setOpen(req);
    // Pre-fill with what was asked for; the operator narrows from here. The
    // request is a proposal, never an instruction.
    setCaps(req.requested_capabilities || []);
    setDays(req.requested_validity_days || 90);
    setIssued(null);
    setError(null);
  }

  async function approve() {
    setBusy(true);
    try {
      const vc = await api.approve(open.id, {
        subject_did: open.subject_did,
        name: open.name,
        organisation: open.organisation,
        capabilities: caps,
        validity_days: Number(days),
      });
      setIssued(vc);
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  }

  async function reject() {
    const reason = prompt("Reason for rejection:");
    if (reason === null) return;
    await api.reject(open.id, reason);
    setOpen(null);
    load();
  }

  return (
    <div className="page">
      <h1>Pending requests</h1>
      {error && <p className="error">{error}</p>}

      {requests.length === 0 && <p className="muted">Nothing awaiting approval.</p>}

      <table>
        <thead>
          <tr>
            <th>Requested</th><th>Name</th><th>Organisation</th>
            <th>DID</th><th>Asked for</th><th></th>
          </tr>
        </thead>
        <tbody>
          {requests.map((r) => (
            <tr key={r.id}>
              <td className="muted">{(r.requested_at || "").slice(0, 16).replace("T", " ")}</td>
              <td>{r.name}</td>
              <td>{r.organisation}</td>
              <td><code className="did">{r.subject_did}</code></td>
              <td>{(r.requested_capabilities || []).length} capabilities</td>
              <td><button onClick={() => start(r)}>review</button></td>
            </tr>
          ))}
        </tbody>
      </table>

      {open && (
        <div className="panel">
          <h2>Review request {open.id}</h2>

          <dl>
            <dt>Subject DID</dt><dd><code className="did">{open.subject_did}</code></dd>
            <dt>Name</dt><dd>{open.name}</dd>
            <dt>Contact</dt><dd>{open.contact || "—"}</dd>
            <dt>Deployment</dt><dd>{open.deployment || "—"}</dd>
            <dt>Justification</dt><dd>{open.justification || "—"}</dd>
          </dl>

          <p className="muted">
            Before approving, satisfy yourself that this DID belongs to the party named,
            and grant the narrowest capability set that lets them do their job.
          </p>

          <h3>Capabilities to grant</h3>
          <CapabilityEditor value={caps} onChange={setCaps} />

          <label>
            Validity in days
            <input type="number" min="1" value={days}
                   onChange={(e) => setDays(e.target.value)} />
          </label>

          <div className="actions">
            <button disabled={busy || caps.length === 0} onClick={approve}>
              {busy ? "signing…" : "approve and sign"}
            </button>
            <button className="secondary" onClick={reject}>reject</button>
            <button className="link" onClick={() => setOpen(null)}>close</button>
          </div>

          {issued && (
            <div className="issued">
              <h3>Credential signed</h3>
              <p>
                <code>{issued.id}</code> — expires {issued.expirationDate}
              </p>
              <button onClick={() => downloadCredential(issued)}>download credential</button>
              <p className="muted">
                Send this file to the requester. It is not a secret: without their private
                key it grants nothing.
              </p>
              <pre>{JSON.stringify(issued, null, 2)}</pre>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
