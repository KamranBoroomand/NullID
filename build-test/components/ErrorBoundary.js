import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { Component } from "react";
import { useI18n } from "../i18n";
export class ErrorBoundary extends Component {
    constructor(props) {
        super(props);
        this.state = { error: null };
    }
    static getDerivedStateFromError(error) {
        return { error };
    }
    componentDidCatch(error, info) {
        console.error("App crash captured", error, info);
        this.props.onError?.(error);
    }
    render() {
        if (this.state.error) {
            return _jsx(ErrorFallback, { error: this.state.error, onDismiss: () => this.setState({ error: null }) });
        }
        return this.props.children;
    }
}
function ErrorFallback({ error, onDismiss }) {
    const { t } = useI18n();
    return (_jsxs("div", { style: { padding: "1rem", fontFamily: "var(--font-sans)" }, children: [_jsx("h2", { children: t("error.title") }), _jsx("p", { children: t("error.body") }), _jsx("pre", { style: { whiteSpace: "pre-wrap" }, children: error.message }), _jsx("button", { type: "button", onClick: onDismiss, children: t("error.dismiss") })] }));
}
