import { useRef, useState } from "react";
import { Chip } from "./Chip";
import { Popover } from "./Overlay/Popover";
import { AppLocale, useI18n } from "../i18n";
import { BrandMark } from "./BrandMark";
import "./GlobalHeader.css";

type StatusTone = "neutral" | "accent" | "danger";
type ThemeMode = "light" | "dark";

interface GlobalHeaderProps {
  brand: string;
  pageTitle: string;
  pageSubtitle: string;
  pageToken: string;
  status?: { message: string; tone?: StatusTone };
  theme: ThemeMode;
  locale: AppLocale;
  compact?: boolean;
  showNavToggle?: boolean;
  navOpen?: boolean;
  onToggleTheme: () => void;
  onToggleNav?: () => void;
  onLocaleChange: (next: AppLocale) => void;
  onOpenCommands: () => void;
  onWipe: () => void;
}

export function GlobalHeader({
  brand,
  pageTitle,
  pageSubtitle,
  pageToken,
  status,
  theme,
  locale,
  compact = false,
  showNavToggle = false,
  navOpen = false,
  onToggleTheme,
  onToggleNav,
  onLocaleChange,
  onOpenCommands,
  onWipe,
}: GlobalHeaderProps) {
  const { t, tr, availableLocales, localeMeta } = useI18n();
  const chipTone = status?.tone === "danger" ? "danger" : status?.tone === "accent" ? "accent" : "muted";
  const [menuOpen, setMenuOpen] = useState(false);
  const actionButtonRef = useRef<HTMLButtonElement>(null);

  return (
    <header className={`global-header ${compact ? "is-compact" : ""}`}>
      <div className="header-cluster">
        {showNavToggle ? (
          <button
            type="button"
            className="ghost-button nav-toggle-button"
            onClick={onToggleNav}
            aria-expanded={navOpen}
            aria-label={t("app.moduleList")}
          >
            {t("app.tools")}
          </button>
        ) : null}
        <div className="brand-mark">
          <span className="brand-kicker">{tr("Local security workbench")}</span>
          <div className="brand-row">
            <BrandMark theme={theme} variant="wordmark" className="brand-mark-wordmark" decorative={false} label={brand} />
            <span className="page-token">{pageToken}</span>
          </div>
        </div>
        <div className="page-meta">
          <span className="page-title">{pageTitle}</span>
          <span className="page-subtitle">{pageSubtitle}</span>
        </div>
      </div>
      <div className="header-center">
        <div className="status-block">
          <span className="status-label">{t("app.status")}</span>
          <div className="status-row">
            {status?.message ? <Chip label={tr(status.message)} tone={chipTone} ariaLabel={t("app.status")} /> : null}
            <span className="status-copy">{tr("Local execution only")}</span>
            <div className="indicator-row" aria-label={t("app.connectionIndicators")}>
              <Chip label={t("app.local")} tone="muted" />
              <Chip label={t("app.offline")} tone="muted" />
              <Chip label={t("app.noNet")} tone="muted" />
            </div>
          </div>
        </div>
      </div>
      <div className="header-actions">
        {compact ? (
          <div className="compact-actions">
            <button
              type="button"
              className="ghost-button"
              ref={actionButtonRef}
              onClick={() => setMenuOpen((open) => !open)}
              aria-expanded={menuOpen}
              aria-haspopup="menu"
              aria-label={t("app.openQuickActions")}
            >
              {t("app.actions")}
            </button>
            <Popover
              anchorRef={actionButtonRef}
              align="end"
              className="compact-menu"
              open={menuOpen}
              onClose={() => setMenuOpen(false)}
              role="menu"
            >
              <button
                type="button"
                className="ghost-button"
                onClick={() => {
                  setMenuOpen(false);
                  onToggleTheme();
                }}
                aria-label={t("app.command.toggleTheme")}
                role="menuitem"
              >
                {t("app.themeLabel")}: {theme === "dark" ? t("app.theme.dark") : t("app.theme.light")}
              </button>
              <label className="header-locale-label">
                {t("app.language")}
                <select
                  className="header-locale-select"
                  value={locale}
                  onChange={(event) => {
                    onLocaleChange(event.target.value as AppLocale);
                    setMenuOpen(false);
                  }}
                  aria-label={t("app.language")}
                >
                  {availableLocales.map((entry) => (
                    <option key={entry} value={entry}>
                      {localeMeta[entry].label}
                    </option>
                  ))}
                </select>
              </label>
              <button
                type="button"
                className="ghost-button"
                onClick={() => {
                  setMenuOpen(false);
                  onWipe();
                }}
                aria-label={t("app.command.wipe")}
                role="menuitem"
              >
                {t("app.wipeData")}
              </button>
              <button
                type="button"
                className="command-button"
                onClick={() => {
                  setMenuOpen(false);
                  onOpenCommands();
                }}
                aria-label={t("app.commandPalette")}
                aria-keyshortcuts="/,Control+K,Meta+K"
                role="menuitem"
              >
                {t("app.commands")}
              </button>
            </Popover>
          </div>
        ) : (
          <div className="action-row">
            <button
              type="button"
              className="ghost-button"
              onClick={onToggleTheme}
              aria-label={t("app.command.toggleTheme")}
              aria-live="polite"
            >
              {theme === "dark" ? t("app.theme.dark") : t("app.theme.light")}
            </button>
            <label className="header-locale-label">
              <span className="visually-hidden">{t("app.language")}</span>
              <select
                className="header-locale-select"
                value={locale}
                onChange={(event) => onLocaleChange(event.target.value as AppLocale)}
                aria-label={t("app.language")}
              >
                {availableLocales.map((entry) => (
                  <option key={entry} value={entry}>
                    {localeMeta[entry].label}
                  </option>
                ))}
              </select>
            </label>
            <button type="button" className="ghost-button" onClick={onWipe} aria-label={t("app.command.wipe")}>
              {t("app.wipeData")}
            </button>
            <button
              type="button"
              className="command-button"
              onClick={onOpenCommands}
              aria-label={t("app.commandPalette")}
              aria-keyshortcuts="/,Control+K,Meta+K"
            >
              {t("app.commands")}
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
