import "./Chip.css";

type ChipTone = "neutral" | "accent" | "muted" | "danger";

interface ChipProps {
  label: string;
  tone?: ChipTone;
  ariaLabel?: string;
}

export function Chip({ label, tone = "neutral", ariaLabel }: ChipProps) {
  return (
    <span className={`chip chip-${tone}`} aria-label={ariaLabel ?? label}>
      {label}
    </span>
  );
}
