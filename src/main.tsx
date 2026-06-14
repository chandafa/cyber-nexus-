import React from "react";
import ReactDOM from "react-dom/client";
import App from "./app/App";
import "./lib/icons"; // daftarkan koleksi Solar (offline) sebelum render
import "./index.css";
import "xterm/css/xterm.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
