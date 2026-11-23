import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./sidepanel.css";
import SidePanelApp from "./SidePanelApp.js";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <SidePanelApp />
  </StrictMode>
);
