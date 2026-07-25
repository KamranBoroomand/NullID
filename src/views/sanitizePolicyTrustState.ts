export type PolicyPackTrustState = "unsigned" | "setup-required" | "pending" | "verified" | "failed";

const POLICY_PACK_VERIFICATION_ERROR = /verification|signature|mismatch|integrity/i;

export function getPolicyPackExportTrustState(options: { signed: boolean; hasPassphrase: boolean }): PolicyPackTrustState {
  if (!options.signed) return "unsigned";
  if (!options.hasPassphrase) return "setup-required";
  return "pending";
}

export function getPolicyPackImportTrustState(options: {
  signed: boolean;
  hasPassphrase: boolean;
  verificationSucceeded?: boolean;
  error?: string | null;
}): PolicyPackTrustState {
  if (!options.signed) return "unsigned";
  if (options.verificationSucceeded) return "verified";
  if (options.error && POLICY_PACK_VERIFICATION_ERROR.test(options.error)) return "failed";
  if (!options.hasPassphrase) return "setup-required";
  return "pending";
}

export function formatPolicyPackTrustState(state: PolicyPackTrustState): string {
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

export function policyPackTrustTagClass(state: PolicyPackTrustState): string {
  if (state === "verified") return "tag tag-accent";
  if (state === "failed") return "tag tag-danger";
  return "tag";
}
