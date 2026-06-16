import React from "react";
import ReactDOM from "react-dom/client";
import App from "./app/App";
import "./lib/icons"; // daftarkan koleksi Solar (offline) sebelum render
import { installSecurityGuards } from "./lib/security";
import "./index.css";
import "xterm/css/xterm.css";

// Nonaktifkan klik-kanan & shortcut devtools (hanya aktif di build produksi).
installSecurityGuards();

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
