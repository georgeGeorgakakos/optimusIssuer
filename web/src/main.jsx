import React from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import App from "./App.jsx";
import { initAuth } from "./auth.js";
import "./styles.css";

// Authentication is resolved before the application renders, so no component
// ever has to handle the "not yet known" state.
initAuth().then(() => {
  createRoot(document.getElementById("root")).render(
    <React.StrictMode>
      <BrowserRouter>
        <App />
      </BrowserRouter>
    </React.StrictMode>
  );
});
