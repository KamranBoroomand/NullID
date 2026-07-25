import { ReactNode, RefObject, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import "./Popover.css";

const VIEWPORT_PADDING = 12;

interface PopoverProps {
  anchorRef: RefObject<HTMLElement>;
  children: ReactNode;
  open: boolean;
  onClose: () => void;
  align?: "start" | "end";
  offset?: number;
  className?: string;
  role?: string;
}

type Position = {
  top: number;
  left: number;
  placement: "top" | "bottom";
};

export function Popover({
  anchorRef,
  children,
  open,
  onClose,
  align = "start",
  offset = 8,
  className,
  role,
}: PopoverProps) {
  const popoverRef = useRef<HTMLDivElement>(null);
  const [position, setPosition] = useState<Position>({ top: 0, left: 0, placement: "bottom" });

  const updatePosition = useCallback(() => {
    const anchor = anchorRef.current;
    const popover = popoverRef.current;
    if (!anchor || !popover) return;

    const triggerRect = anchor.getBoundingClientRect();
    const popRect = popover.getBoundingClientRect();
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;

    let top = triggerRect.bottom + offset;
    let placement: Position["placement"] = "bottom";

    if (top + popRect.height + VIEWPORT_PADDING > viewportHeight) {
      top = triggerRect.top - popRect.height - offset;
      placement = "top";
      if (top < VIEWPORT_PADDING) {
        top = Math.max(VIEWPORT_PADDING, viewportHeight - popRect.height - VIEWPORT_PADDING);
      }
    }

    let left = align === "end" ? triggerRect.right - popRect.width : triggerRect.left;
    left = Math.min(Math.max(left, VIEWPORT_PADDING), viewportWidth - popRect.width - VIEWPORT_PADDING);

    setPosition({
      top: Math.round(top),
      left: Math.round(left),
      placement,
    });
  }, [align, anchorRef, offset]);

  useLayoutEffect(() => {
    if (!open) return;

    updatePosition();

    const handleResize = () => updatePosition();
    const handleScroll = () => updatePosition();

    window.addEventListener("resize", handleResize);
    window.addEventListener("scroll", handleScroll, true);
    return () => {
      window.removeEventListener("resize", handleResize);
      window.removeEventListener("scroll", handleScroll, true);
    };
  }, [open, updatePosition]);

  useEffect(() => {
    if (!open) return;

    const handlePointerDown = (event: PointerEvent) => {
      const target = event.target as Node;
      if (popoverRef.current?.contains(target)) return;
      if (anchorRef.current?.contains(target)) return;
      onClose();
    };

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.stopPropagation();
        onClose();
      }
    };

    document.addEventListener("pointerdown", handlePointerDown, true);
    document.addEventListener("keydown", handleKeyDown);

    return () => {
      document.removeEventListener("pointerdown", handlePointerDown, true);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, [anchorRef, onClose, open]);

  useEffect(() => {
    if (!open) return;
    const focusable = popoverRef.current?.querySelector<HTMLElement>(
      "button, [href], input, select, textarea, [tabindex]:not([tabindex='-1'])",
    );
    focusable?.focus({ preventScroll: true });
  }, [open]);

  if (!open) return null;

  const classes = ["popover-surface", className].filter(Boolean).join(" ");

  return createPortal(
    <div
      className={classes}
      ref={popoverRef}
      role={role}
      data-placement={position.placement}
      style={{ top: `${position.top}px`, left: `${position.left}px` }}
    >
      {children}
    </div>,
    document.body,
  );
}
