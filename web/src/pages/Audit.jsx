import { useEffect, useState } from "react";
import { api } from "../api.js";

export default function Audit() {
  const [entries, setEntries] = useState([]);

  useEffect(() => {
    api.audit().then((r) => setEntries(r.entries || [])).catch(() => {});
  }, []);

  return (
    <div className="page">
      <h1>Audit</h1>
      <p className="muted">
        Actions taken through this service since it last started. The durable record of
        issuance lives in the kbissuance store, which replicates and is captured by the
        OptimusDB export.
      </p>

      <table>
        <thead>
          <tr><th>When</th><th>Action</th><th>Operator</th><th>Subject</th><th>Detail</th></tr>
        </thead>
        <tbody>
          {entries.map((e, i) => (
            <tr key={i}>
              <td className="muted">{(e.at || "").slice(0, 19).replace("T", " ")}</td>
              <td><code>{e.action}</code></td>
              <td>{e.operator || "—"}</td>
              <td><code className="did">{e.subject || e.credential_id || "—"}</code></td>
              <td>{e.detail}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
