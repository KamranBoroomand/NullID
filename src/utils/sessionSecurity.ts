const VAULT_SESSION_COOKIE = "nullid_vault_session";

export interface SessionCookieResult {
  active: boolean;
  secure: boolean;
  warning?: string;
}

function canUseSecureCookie(): boolean {
  if (typeof window === "undefined") return false;
  return window.isSecureContext || window.location.protocol === "https:";
}

function parseCookie(name: string): string | null {
  if (typeof document === "undefined") return null;
  const tokens = document.cookie.split(";").map((item) => item.trim());
  const target = `${name}=`;
  const match = tokens.find((token) => token.startsWith(target));
  return match ? decodeURIComponent(match.slice(target.length)) : null;
}

export function readVaultSessionCookie(): string | null {
  return parseCookie(VAULT_SESSION_COOKIE);
}

export function setVaultSessionCookie(maxAgeSeconds: number): SessionCookieResult {
  const secure = canUseSecureCookie();
  const token = typeof crypto.randomUUID === "function" ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const parts = [
    `${VAULT_SESSION_COOKIE}=${encodeURIComponent(token)}`,
    "Path=/",
    `Max-Age=${Math.max(30, Math.floor(maxAgeSeconds))}`,
    "SameSite=Strict",
  ];
  if (secure) {
    parts.push("Secure");
  }
  document.cookie = parts.join("; ");
  const warning = secure
    ? "HttpOnly cannot be set from browser JavaScript. Configure server/edge cookie headers for HttpOnly."
    : "Secure cookie flag is unavailable on this origin. Use HTTPS in production.";
  return { active: true, secure, warning };
}

export function clearVaultSessionCookie(): void {
  const parts = [`${VAULT_SESSION_COOKIE}=`, "Path=/", "Max-Age=0", "SameSite=Strict"];
  if (canUseSecureCookie()) parts.push("Secure");
  document.cookie = parts.join("; ");
}
