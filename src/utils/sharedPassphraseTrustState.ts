export type SharedPassphraseTrustState = "unsigned" | "setup-required" | "pending" | "verified" | "failed";

const VERIFICATION_ERROR = /verification|signature|mismatch|integrity/i;

export function getSharedPassphraseExportTrustState(options: {
  signed: boolean;
  hasPassphrase: boolean;
}): SharedPassphraseTrustState {
  if (!options.signed) return "unsigned";
  if (!options.hasPassphrase) return "setup-required";
  return "pending";
}

export function getSharedPassphraseImportTrustState(options: {
  signed: boolean;
  hasPassphrase: boolean;
  verificationSucceeded?: boolean;
  error?: string | null;
}): SharedPassphraseTrustState {
  if (!options.signed) return "unsigned";
  if (options.verificationSucceeded) return "verified";
  if (options.error && VERIFICATION_ERROR.test(options.error)) return "failed";
  if (!options.hasPassphrase) return "setup-required";
  return "pending";
}

export function formatSharedPassphraseTrustState(state: SharedPassphraseTrustState): string {
  switch (state) {
    case "setup-required":
      return "passphrase required";
    case "pending":
      return "not yet verified";
    case "verified":
      return "verification succeeded";
    case "failed":
      return "verification failed";
    case "unsigned":
    default:
      return "unsigned";
  }
}

export function sharedPassphraseTrustTagClass(state: SharedPassphraseTrustState): string {
  if (state === "verified") return "tag tag-accent";
  if (state === "failed") return "tag tag-danger";
  return "tag";
}
