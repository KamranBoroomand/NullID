import { jsx as _jsx, jsxs as _jsxs } from "react/jsx-runtime";
import { Component } from "react";
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
            return (_jsxs("div", { style: { padding: "1rem", fontFamily: "var(--font-sans)" }, children: [_jsx("h2", { children: "Something went wrong" }), _jsx("p", { children: "The UI recovered from an error. Please retry your last action." }), _jsx("pre", { style: { whiteSpace: "pre-wrap" }, children: this.state.error.message }), _jsx("button", { type: "button", onClick: () => this.setState({ error: null }), children: "Dismiss" })] }));
        }
        return this.props.children;
    }
}
