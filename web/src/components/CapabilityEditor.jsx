import { useState } from "react";

// Known actions, offered as a list so that an operator does not have to
// remember the exact strings the agents match on. Free text is still allowed,
// because a deployment may define its own actions.
const ACTIONS = [
  "crudget", "crudput", "crudupdate", "cruddelete",
  "stores:list", "stores:create", "stores:drop",
  "capacity:reserve", "capacity:release",
  "exchange:export", "exchange:import",
  "trust:admin", "*",
];

const STORES = [
  "kbmetadata", "kbdata", "dsswres", "dsswresaloc", "whoiswho", "validations",
  "tosca_imported", "tosca_adt", "tosca_capacities", "tosca_deploymentplan",
  "tosca_eventhistory", "kbtrust", "*",
];

export default function CapabilityEditor({ value, onChange }) {
  const [action, setAction] = useState("crudget");
  const [store, setStore] = useState("kbmetadata");

  function add() {
    if (!action || !store) return;
    if (value.some((c) => c.action === action && c.store === store)) return;
    onChange([...value, { action, store }]);
  }

  function remove(i) {
    onChange(value.filter((_, j) => j !== i));
  }

  const wildcards = value.filter((c) => c.action === "*" || c.store === "*").length;

  return (
    <div className="caps">
      <div className="cap-add">
        <input
          list="actions"
          value={action}
          onChange={(e) => setAction(e.target.value)}
          placeholder="action"
        />
        <datalist id="actions">
          {ACTIONS.map((a) => <option key={a} value={a} />)}
        </datalist>

        <input
          list="stores"
          value={store}
          onChange={(e) => setStore(e.target.value)}
          placeholder="store"
        />
        <datalist id="stores">
          {STORES.map((s) => <option key={s} value={s} />)}
        </datalist>

        <button type="button" onClick={add}>add</button>
      </div>

      {value.length === 0 && <p className="muted">No capabilities yet.</p>}

      <ul className="cap-list">
        {value.map((c, i) => (
          <li key={`${c.action}:${c.store}`}
              className={c.action === "*" || c.store === "*" ? "wild" : ""}>
            <code>{c.action}</code> on <code>{c.store}</code>
            <button type="button" className="link" onClick={() => remove(i)}>remove</button>
          </li>
        ))}
      </ul>

      {wildcards > 0 && (
        <p className="warn">
          {wildcards} capability{wildcards > 1 ? "s use" : " uses"} a wildcard. Wildcards are
          flagged in the audit log and may require a second operator to approve.
          Grant the narrowest set that works.
        </p>
      )}
    </div>
  );
}
