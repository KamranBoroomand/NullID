import { jsx as _jsx } from "react/jsx-runtime";
import { StrictMode } from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles/tokens.css";
import "./styles/global.css";
ReactDOM.createRoot(document.getElementById("root")).render(_jsx(StrictMode, { children: _jsx(App, {}) }));
if (import.meta.env.PROD && "serviceWorker" in navigator) {
    window.addEventListener("load", () => {
        const swUrl = `${import.meta.env.BASE_URL}sw.js`;
        navigator.serviceWorker.register(swUrl).catch((error) => {
            console.error("Service worker registration failed:", error);
        });
    });
}
