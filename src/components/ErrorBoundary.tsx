import { Component, ReactNode } from "react";
import { useI18n } from "../i18n";

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
      return <ErrorFallback error={this.state.error} onDismiss={() => this.setState({ error: null })} />;
    }
    return this.props.children;
  }
}

function ErrorFallback({ error, onDismiss }: { error: Error; onDismiss: () => void }) {
  const { t } = useI18n();

  return (
    <div style={{ padding: "1rem", fontFamily: "var(--font-sans)" }}>
      <h2>{t("error.title")}</h2>
      <p>{t("error.body")}</p>
      <pre style={{ whiteSpace: "pre-wrap" }}>{error.message}</pre>
      <button type="button" onClick={onDismiss}>
        {t("error.dismiss")}
      </button>
    </div>
  );
}
