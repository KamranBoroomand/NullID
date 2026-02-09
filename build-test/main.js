import { jsx as _jsx } from "react/jsx-runtime";
import { StrictMode } from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles/tokens.css";
import "./styles/global.css";
ReactDOM.createRoot(document.getElementById("root")).render(_jsx(StrictMode, { children: _jsx(App, {}) }));
