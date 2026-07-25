const MACHINE_IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

export function normalizeMachineIdentifier(value: string, maxLength = 128) {
  const normalized = value.trim().normalize("NFKC");
  if (normalized.length < 1 || normalized.length > maxLength) return null;
  return MACHINE_IDENTIFIER_PATTERN.test(normalized) ? normalized : null;
}

export function canonicalMachineIdentifier(value: string, maxLength = 128) {
  const normalized = normalizeMachineIdentifier(value, maxLength);
  return normalized ? normalized.toLowerCase() : null;
}

// Display names intentionally use NFKC plus simple lowercase only. Machine
// identifiers carry the strict uniqueness and mutation semantics.
export function canonicalSemanticIdentity(value: string) {
  return value.trim().normalize("NFKC").toLowerCase();
}

export function normalizeSemanticDisplayText(value: string) {
  return value.trim().normalize("NFKC");
}
