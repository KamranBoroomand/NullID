import { useRef, useState } from "react";
import "./styles.css";
import { Chip } from "../components/Chip";
import { useToast } from "../components/ToastHost";
import type { ModuleKey } from "../components/ModuleList";
import { useI18n } from "../i18n";
import { inspectReceivedArtifact, type ReceivedArtifactVerificationResult, type ReceivedVerificationState } from "../utils/packageVerification.js";

interface VerifyPackageViewProps {
  onOpenGuide?: (key?: ModuleKey) => void;
}

export function VerifyPackageView({ onOpenGuide }: VerifyPackageViewProps) {
  const { push } = useToast();
  const { t, tr } = useI18n();
  const [input, setInput] = useState("");
  const [sourceLabel, setSourceLabel] = useState("");
  const [envelopePassphrase, setEnvelopePassphrase] = useState("");
  const [verificationPassphrase, setVerificationPassphrase] = useState("");
  const [result, setResult] = useState<ReceivedArtifactVerificationResult | null>(null);
  const [isInspecting, setIsInspecting] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const inspectArtifact = async () => {
    setIsInspecting(true);
    try {
      const next = await inspectReceivedArtifact(input, {
        envelopePassphrase: envelopePassphrase.trim() || undefined,
        verificationPassphrase: verificationPassphrase.trim() || undefined,
        sourceLabel: sourceLabel || undefined,
      });
      setResult(next);
      push(`${tr("Verification summary")}: ${tr(next.verificationLabel)}`, toneForState(next.verificationState));
    } catch (error) {
      console.error(error);
      push("verify failed", "danger");
    } finally {
      setIsInspecting(false);
    }
  };

  const handleFile = async (file?: File | null) => {
    if (!file) return;
    try {
      setInput(await file.text());
      setSourceLabel(file.name);
      push(`${tr("Loaded file")}: ${file.name}`, "accent");
    } catch (error) {
      console.error(error);
      push(tr("file load failed"), "danger");
    }
  };

  const reset = () => {
    setInput("");
    setSourceLabel("");
    setEnvelopePassphrase("");
    setVerificationPassphrase("");
    setResult(null);
  };

  return (
    <div className="workspace-scroll">
      <div className="guide-link">
        <button type="button" className="guide-link-button" onClick={() => onOpenGuide?.("verify")}>
          {t("guide.link")}
        </button>
      </div>

      <div className="grid-two">
        <section className="panel" aria-label={tr("Verify package input")}>
          <div className="panel-heading">
            <span>{tr("Verify Package")}</span>
            <span className="panel-subtext">{tr("open received artifacts")}</span>
          </div>
          <div className="microcopy">
            {tr("Paste a JSON artifact or NULLID envelope, or load a local file. Verification stays local and explains what was checked versus what remains unproven.")}
          </div>
          <textarea
            className="textarea"
            aria-label={tr("Verification input")}
            placeholder={tr("Paste a workflow package, safe-share bundle, profile, policy pack, vault snapshot, or NULLID envelope")}
            value={input}
            onChange={(event) => setInput(event.target.value)}
          />
          <div className="controls-row">
            <input
              className="input"
              aria-label={tr("Envelope passphrase")}
              placeholder={tr("Envelope passphrase (optional)")}
              type="password"
              value={envelopePassphrase}
              onChange={(event) => setEnvelopePassphrase(event.target.value)}
            />
            <input
              className="input"
              aria-label={tr("Verification passphrase")}
              placeholder={tr("Verification passphrase (optional)")}
              type="password"
              value={verificationPassphrase}
              onChange={(event) => setVerificationPassphrase(event.target.value)}
            />
          </div>
          <div className="controls-row">
            <button className="button" type="button" onClick={inspectArtifact} disabled={isInspecting || !input.trim()}>
              {isInspecting ? tr("inspecting...") : tr("inspect artifact")}
            </button>
            <button className="button" type="button" onClick={() => fileRef.current?.click()}>
              {tr("load file")}
            </button>
            <button className="button" type="button" onClick={reset}>
              {tr("clear")}
            </button>
            <input
              ref={fileRef}
              hidden
              type="file"
              aria-label={tr("Verification file")}
              onChange={(event) => void handleFile(event.target.files?.[0] ?? null)}
            />
          </div>
          {sourceLabel ? <div className="microcopy">{tr("Loaded file")}: {sourceLabel}</div> : null}
        </section>

        <section className="panel" aria-label={tr("Verification summary")}>
          <div className="panel-heading">
            <span>{tr("Verification summary")}</span>
            <span className="panel-subtext">{tr("trust posture")}</span>
          </div>
          {result ? (
            <>
              <div className="controls-row" style={{ alignItems: "center" }}>
                <Chip label={tr(result.artifactKindLabel)} tone="muted" />
                <Chip label={tr(result.verificationLabel)} tone={chipToneForState(result.verificationState)} />
              </div>
              <div className="microcopy">{tr(result.title)}</div>
              {result.failure ? <div className="tag tag-danger">{tr(result.failure)}</div> : null}
              <table className="table">
                <tbody>
                  {result.facts.map((fact) => (
                    <tr key={`${fact.label}:${fact.value}`}>
                      <th>{tr(fact.label)}</th>
                      <td>{tr(fact.value)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          ) : (
            <div className="microcopy">{tr("Load an artifact and run inspect to see its trust basis, verification result, warnings, and included entries.")}</div>
          )}
        </section>
      </div>

      {result ? (
        <>
          <div className="grid-two">
            <section className="panel" aria-label={tr("Verified checks")}>
              <div className="panel-heading">
                <span>{tr("Verified")}</span>
                <span className="panel-subtext">{tr("what NullID checked")}</span>
              </div>
              <ul className="microcopy">
                {result.verifiedChecks.length > 0 ? result.verifiedChecks.map((line) => <li key={line}>{tr(line)}</li>) : <li>{tr("No checks completed.")}</li>}
              </ul>
            </section>
            <section className="panel" aria-label={tr("Not verified checks")}>
              <div className="panel-heading">
                <span>{tr("Not verified")}</span>
                <span className="panel-subtext">{tr("limits and unknowns")}</span>
              </div>
              <ul className="microcopy">
                {result.unverifiedChecks.length > 0 ? result.unverifiedChecks.map((line) => <li key={line}>{tr(line)}</li>) : <li>{tr("No unresolved verification gaps were reported.")}</li>}
              </ul>
            </section>
          </div>

          <div className="grid-two">
            <section className="panel" aria-label={tr("Trust basis")}>
              <div className="panel-heading">
                <span>{tr("Trust basis")}</span>
                <span className="panel-subtext">{tr("how the result was derived")}</span>
              </div>
              <ul className="microcopy">
                {result.trustBasis.map((line) => (
                  <li key={line}>{tr(line)}</li>
                ))}
              </ul>
            </section>
            <section className="panel" aria-label={tr("Warnings and limitations")}>
              <div className="panel-heading">
                <span>{tr("Warnings & limits")}</span>
                <span className="panel-subtext">{tr("what to keep in mind")}</span>
              </div>
              <ul className="microcopy">
                {[...result.warnings, ...result.limitations].length > 0
                  ? [...result.warnings, ...result.limitations].map((line) => <li key={line}>{tr(line)}</li>)
                  : <li>{tr("No additional warnings were reported.")}</li>}
              </ul>
            </section>
          </div>

          {result.descriptiveWorkflowMetadata ? (
            <section className="panel" aria-label={tr("Workflow metadata notice")}>
              <div className="panel-heading">
                <span>{tr("Package-declared workflow metadata")}</span>
                <span className="panel-subtext">{tr("descriptive only; not integrity-verified")}</span>
              </div>
              <div className="controls-row" style={{ alignItems: "center" }}>
                <Chip label={tr("Not integrity-verified")} tone="muted" />
              </div>
              <div className="microcopy">
                {tr("These workflow title, preset, policy, report, transform, warning, and limitation fields were parsed successfully, but the current workflow-package verifier does not authenticate them cryptographically.")}
              </div>
              {result.descriptiveWorkflowMetadata.title ? (
                <div className="microcopy">
                  {tr("Package-declared title")}: {result.descriptiveWorkflowMetadata.title}
                </div>
              ) : null}
              {result.descriptiveWorkflowMetadata.facts.length ? (
                <table className="table">
                  <tbody>
                    {result.descriptiveWorkflowMetadata.facts.map((fact) => (
                      <tr key={`${fact.label}:${fact.value}`}>
                        <th>{tr(fact.label)}</th>
                        <td>{tr(fact.value)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : null}
            </section>
          ) : null}

          {result.descriptiveWorkflowMetadata?.workflowReport ? (
            <div className="grid-two">
              <section className="panel" aria-label={tr("Package-declared workflow report")}>
                <div className="panel-heading">
                  <span>{tr("Package-declared workflow report")}</span>
                  <span className="panel-subtext">{tr("descriptive only; not integrity-verified")}</span>
                </div>
                <table className="table">
                  <tbody>
                    {result.descriptiveWorkflowMetadata.workflowReport.purpose ? (
                      <tr>
                        <th>{tr("Purpose")}</th>
                        <td>{tr(result.descriptiveWorkflowMetadata.workflowReport.purpose)}</td>
                      </tr>
                    ) : null}
                    {result.descriptiveWorkflowMetadata.workflowReport.audience ? (
                      <tr>
                        <th>{tr("Audience")}</th>
                        <td>{tr(result.descriptiveWorkflowMetadata.workflowReport.audience)}</td>
                      </tr>
                    ) : null}
                    <tr>
                      <th>{tr("Included")}</th>
                      <td>{result.descriptiveWorkflowMetadata.workflowReport.includedArtifacts.length}</td>
                    </tr>
                    <tr>
                      <th>{tr("Transformed")}</th>
                      <td>{result.descriptiveWorkflowMetadata.workflowReport.transformedArtifacts.length}</td>
                    </tr>
                    <tr>
                      <th>{tr("Preserved")}</th>
                      <td>{result.descriptiveWorkflowMetadata.workflowReport.preservedArtifacts.length}</td>
                    </tr>
                  </tbody>
                </table>
              </section>

              <section className="panel" aria-label={tr("Package-declared receiver explanation")}>
                <div className="panel-heading">
                  <span>{tr("Package-declared receiver explanation")}</span>
                  <span className="panel-subtext">{tr("descriptive only; not integrity-verified")}</span>
                </div>
                <div className="panel-subtext">{tr("Receiver can verify")}</div>
                <ul className="microcopy">
                  {result.descriptiveWorkflowMetadata.workflowReport.receiverCanVerify.length > 0
                    ? result.descriptiveWorkflowMetadata.workflowReport.receiverCanVerify.map((line) => <li key={line}>{tr(line)}</li>)
                    : <li>{tr("No receiver-verifiable checks were recorded.")}</li>}
                </ul>
                <div className="panel-subtext">{tr("Receiver cannot verify")}</div>
                <ul className="microcopy">
                  {result.descriptiveWorkflowMetadata.workflowReport.receiverCannotVerify.length > 0
                    ? result.descriptiveWorkflowMetadata.workflowReport.receiverCannotVerify.map((line) => <li key={line}>{tr(line)}</li>)
                    : <li>{tr("No additional receiver limits were recorded.")}</li>}
                </ul>
              </section>
            </div>
          ) : null}

          {result.descriptiveWorkflowMetadata?.workflowReport ? (
            <div className="grid-two">
              <section className="panel" aria-label={tr("Package-declared included and preserved items")}>
                <div className="panel-heading">
                  <span>{tr("Included & preserved")}</span>
                  <span className="panel-subtext">{tr("package-declared scope; not integrity-verified")}</span>
                </div>
                <div className="panel-subtext">{tr("Included artifacts")}</div>
                <ul className="microcopy">
                  {result.descriptiveWorkflowMetadata.workflowReport.includedArtifacts.length > 0
                    ? result.descriptiveWorkflowMetadata.workflowReport.includedArtifacts.map((line) => <li key={line}>{tr(line)}</li>)
                    : <li>{tr("No included artifacts were listed in the workflow report.")}</li>}
                </ul>
                <div className="panel-subtext">{tr("Preserved artifacts")}</div>
                <ul className="microcopy">
                  {result.descriptiveWorkflowMetadata.workflowReport.preservedArtifacts.length > 0
                    ? result.descriptiveWorkflowMetadata.workflowReport.preservedArtifacts.map((line) => <li key={line}>{tr(line)}</li>)
                    : <li>{tr("No preserved source context was listed.")}</li>}
                </ul>
              </section>

              <section className="panel" aria-label={tr("Package-declared reported transforms")}>
                <div className="panel-heading">
                  <span>{tr("Reported transforms")}</span>
                  <span className="panel-subtext">{tr("package-declared changes; not integrity-verified")}</span>
                </div>
                <ul className="microcopy">
                  {result.descriptiveWorkflowMetadata.workflowReport.transformedArtifacts.length > 0
                    ? result.descriptiveWorkflowMetadata.workflowReport.transformedArtifacts.map((line) => <li key={line}>{tr(line)}</li>)
                    : <li>{tr("No transform entries were recorded in the workflow report.")}</li>}
                </ul>
              </section>
            </div>
          ) : null}

          {result.envelope?.length ? (
            <section className="panel" aria-label={tr("Envelope metadata")}>
              <div className="panel-heading">
                <span>{tr("Envelope metadata")}</span>
                <span className="panel-subtext">{tr("inspectable without export")}</span>
              </div>
              <table className="table">
                <tbody>
                  {result.envelope.map((fact) => (
                    <tr key={`${fact.label}:${fact.value}`}>
                      <th>{tr(fact.label)}</th>
                      <td>{tr(fact.value)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          ) : null}

          {result.descriptiveWorkflowMetadata?.policySummary.length ? (
            <section className="panel" aria-label={tr("Policy metadata")}>
              <div className="panel-heading">
                <span>{tr("Package-declared policy metadata")}</span>
                <span className="panel-subtext">{tr("descriptive only; not integrity-verified")}</span>
              </div>
              <table className="table">
                <tbody>
                  {result.descriptiveWorkflowMetadata.policySummary.map((fact) => (
                    <tr key={`${fact.label}:${fact.value}`}>
                      <th>{tr(fact.label)}</th>
                      <td>{tr(fact.value)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          ) : null}

          {result.descriptiveWorkflowMetadata?.transforms.length ? (
            <section className="panel" aria-label={tr("Transform summary")}>
              <div className="panel-heading">
                <span>{tr("Package-declared transform summary")}</span>
                <span className="panel-subtext">{tr("descriptive only; not integrity-verified")}</span>
              </div>
              <table className="table">
                <tbody>
                  {result.descriptiveWorkflowMetadata.transforms.map((fact) => (
                    <tr key={`${fact.label}:${fact.value}`}>
                      <th>{tr(fact.label)}</th>
                      <td>{tr(fact.value)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          ) : null}

          {result.descriptiveWorkflowMetadata && [...result.descriptiveWorkflowMetadata.warnings, ...result.descriptiveWorkflowMetadata.limitations].length ? (
            <section className="panel" aria-label={tr("Package-declared warnings and limitations")}>
              <div className="panel-heading">
                <span>{tr("Package-declared warnings & limits")}</span>
                <span className="panel-subtext">{tr("descriptive only; not integrity-verified")}</span>
              </div>
              <ul className="microcopy">
                {[...result.descriptiveWorkflowMetadata.warnings, ...result.descriptiveWorkflowMetadata.limitations].map((line) => (
                  <li key={line}>{tr(line)}</li>
                ))}
              </ul>
            </section>
          ) : null}

          {result.artifacts.length ? (
            <section className="panel" aria-label={tr("Included artifacts")}>
              <div className="panel-heading">
                <span>{tr("Included artifacts")}</span>
                <span className="panel-subtext">{tr("files or logical entries")}</span>
              </div>
              <table className="table">
                <thead>
                  <tr>
                    <th>{tr("Label")}</th>
                    <th>{tr("Role")}</th>
                    <th>{tr("Status")}</th>
                    <th>{tr("Detail")}</th>
                  </tr>
                </thead>
                <tbody>
                  {result.artifacts.map((artifact) => (
                    <tr key={artifact.id}>
                      <td>{artifact.label}</td>
                      <td>{tr(artifact.role)}</td>
                      <td>
                        <Chip
                          label={tr(artifact.status)}
                          tone={artifact.status === "mismatch" ? "danger" : artifact.status === "verified" ? "accent" : "muted"}
                        />
                      </td>
                      <td>{tr(artifact.detail)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </section>
          ) : null}
        </>
      ) : null}
    </div>
  );
}

function chipToneForState(state: ReceivedVerificationState) {
  if (state === "verified" || state === "integrity-checked") return "accent";
  if (state === "mismatch" || state === "invalid" || state === "malformed") return "danger";
  return "muted";
}

function toneForState(state: ReceivedVerificationState) {
  if (state === "verified" || state === "integrity-checked") return "accent" as const;
  if (state === "mismatch" || state === "invalid" || state === "malformed") return "danger" as const;
  return "neutral" as const;
}
