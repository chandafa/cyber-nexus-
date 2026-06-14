// src/app/App.tsx — komponen root (SDD struktur app/).
import React from "react";
import { RouterProvider } from "react-router-dom";
import { router } from "./router";

export const App: React.FC = () => <RouterProvider router={router} />;

export default App;
