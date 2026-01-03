import { Component, ReactNode } from "react";

interface ErrorBoundaryProps {
  children: ReactNode;
  onError?: (error: Error) => void;
}

interface ErrorBoundaryState {
  error: Error | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  constructor(props: ErrorBoundaryProps) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: any) {
    console.error("App crash captured", error, info);
    this.props.onError?.(error);
  }

  render() {
    if (this.state.error) {
      return (
        <div style={{ padding: "1rem", fontFamily: "var(--font-sans)" }}>
          <h2>Something went wrong</h2>
          <p>The UI recovered from an error. Please retry your last action.</p>
          <pre style={{ whiteSpace: "pre-wrap" }}>{this.state.error.message}</pre>
          <button type="button" onClick={() => this.setState({ error: null })}>
            Dismiss
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
