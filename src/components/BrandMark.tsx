import type { ThemeMode } from "../theme/tokens";

interface BrandMarkProps {
  theme: ThemeMode;
  className?: string;
  decorative?: boolean;
  label?: string;
  variant?: "mark" | "wordmark";
}

export function BrandMark({ theme, className, decorative = true, label = "NullID", variant = "mark" }: BrandMarkProps) {
  const assetName = variant === "wordmark" ? "nullid-wordmark" : "nullid-mark";
  const src = `${import.meta.env.BASE_URL}brand/${assetName}-${theme}.svg`;

  return (
    <img
      className={className}
      src={src}
      alt={decorative ? "" : label}
      aria-hidden={decorative ? "true" : undefined}
      draggable="false"
      decoding="async"
    />
  );
}
