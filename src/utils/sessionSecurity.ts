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
  expireLegacyRootVaultSessionCookie();
  return parseCookie(VAULT_SESSION_COOKIE);
}

export function setVaultSessionCookie(maxAgeSeconds: number): SessionCookieResult {
  const secure = canUseSecureCookie();
  const token = typeof crypto.randomUUID === "function" ? crypto.randomUUID() : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const path = vaultSessionCookiePath();
  const parts = [
    `${VAULT_SESSION_COOKIE}=${encodeURIComponent(token)}`,
    `Path=${path}`,
    `Max-Age=${Math.max(30, Math.floor(maxAgeSeconds))}`,
    "SameSite=Strict",
  ];
  if (secure) {
    parts.push("Secure");
  }
  document.cookie = parts.join("; ");
  expireLegacyRootVaultSessionCookie(secure, path);
  const warning = secure
    ? "Browser-set cookie is a local presence hint only. HttpOnly and real auth cookies must be configured outside the browser."
    : "Browser-set cookie is a local presence hint only, and Secure is unavailable on this origin. Use HTTPS in production.";
  return { active: true, secure, warning };
}

export function clearVaultSessionCookie(): void {
  const secure = canUseSecureCookie();
  const path = vaultSessionCookiePath();
  const parts = [`${VAULT_SESSION_COOKIE}=`, `Path=${path}`, "Max-Age=0", "SameSite=Strict"];
  if (secure) parts.push("Secure");
  document.cookie = parts.join("; ");
  expireLegacyRootVaultSessionCookie(secure, path);
}

function expireLegacyRootVaultSessionCookie(secure = canUseSecureCookie(), scopedPath = vaultSessionCookiePath()): void {
  if (typeof document === "undefined" || scopedPath === "/") return;
  const parts = [`${VAULT_SESSION_COOKIE}=`, "Path=/", "Max-Age=0", "SameSite=Strict"];
  if (secure) parts.push("Secure");
  document.cookie = parts.join("; ");
}

function vaultSessionCookiePath(): string {
  const envBase = (import.meta as ImportMeta & { env?: { BASE_URL?: string } }).env?.BASE_URL;
  const basePath = normalizeCookiePath(envBase);
  if (basePath) return basePath;
  if (typeof window === "undefined") return "/";
  const pathname = window.location?.pathname || "/";
  const trimmed = pathname.replace(/\/+$/u, "");
  const parent = trimmed.includes("/") ? trimmed.slice(0, Math.max(1, trimmed.lastIndexOf("/"))) : "/";
  return normalizeCookiePath(parent) ?? "/";
}

function normalizeCookiePath(value: string | undefined): string | null {
  if (!value || value === "/") return null;
  let path = value.trim();
  if (!path.startsWith("/")) path = `/${path}`;
  path = path.replace(/\/+$/u, "");
  return path || null;
}
