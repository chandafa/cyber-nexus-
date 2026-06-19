// NEXUS — Copyright (c) 2026 chandafa (Nexus Security). All rights reserved.
// Part of the Nexus security platform. Proprietary and confidential.
// Unauthorized copying, modification, or distribution is prohibited.
// This notice and embedded metadata must not be removed. See LICENSE / NOTICE.
// Contact: ck271138@gmail.com

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
