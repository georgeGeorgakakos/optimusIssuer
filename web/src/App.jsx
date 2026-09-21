import { NavLink, Route, Routes } from "react-router-dom";
import { operator, logout } from "./auth.js";
import { BRAND } from "./brand.js";
import Requests from "./pages/Requests.jsx";
import Issue from "./pages/Issue.jsx";
import Credentials from "./pages/Credentials.jsx";
import Trust from "./pages/Trust.jsx";
import Audit from "./pages/Audit.jsx";

const tabs = [
  { to: "/", label: "Requests", end: true },
  { to: "/issue", label: "Issue" },
  { to: "/credentials", label: "Credentials" },
  { to: "/trust", label: "Trust list" },
  { to: "/audit", label: "Audit" },
];

// The IMU crescent: a sky disc with a navy disc offset over it, leaving a
// bright arc on the right. Redrawn rather than cropped from the logo so it
// stays sharp at any size and follows the brand tokens.
function Crescent() {
  return (
    <svg className="crescent" viewBox="0 0 200 200" aria-hidden="true">
      <circle cx="112" cy="100" r="86" fill="var(--brand-sky)" />
      <circle cx="94" cy="100" r="84" fill="var(--brand-navy)" />
      <circle cx="94" cy="100" r="58" fill="none" stroke="#ffffff"
              strokeOpacity=".16" strokeWidth="8" />
    </svg>
  );
}

export default function App() {
  const op = operator();
  const initial = (op.name || "?").charAt(0).toUpperCase();

  return (
    <div className="app">
      <div className="strip">
        <div className="strip-inner">
          <img className="partner-primary" src={BRAND.primaryLogo.src} alt={BRAND.primaryLogo.alt} />
          <div className="product">
            <strong>{BRAND.product}</strong>
            <span>{BRAND.tagline}</span>
          </div>
          <div className="partner-disc">
            <img src={BRAND.partnerLogo.src} alt={BRAND.partnerLogo.alt} />
          </div>
        </div>
      </div>

      <div className="band">
        <Crescent />
        <div className="band-inner">
          <nav aria-label="Portal sections">
            {tabs.map((t) => (
              <NavLink key={t.to} to={t.to} end={t.end}>
                {t.label}
              </NavLink>
            ))}
          </nav>
          <div className="who">
            <span className="name">{op.name}</span>
            <span className="avatar" aria-hidden="true">{initial}</span>
            <button className="link on-band" onClick={logout}>Sign out</button>
          </div>
        </div>
      </div>

      <main>
        <Routes>
          <Route path="/" element={<Requests />} />
          <Route path="/issue" element={<Issue />} />
          <Route path="/credentials" element={<Credentials />} />
          <Route path="/trust" element={<Trust />} />
          <Route path="/audit" element={<Audit />} />
        </Routes>
      </main>

      <footer>
        <div className="footer-inner">
          <img className="em" src={BRAND.emblem.src} alt={BRAND.emblem.alt} />
          <span className="grow">{BRAND.footer}</span>
          <span>{BRAND.product} {BRAND.version}</span>
        </div>
      </footer>
    </div>
  );
}
