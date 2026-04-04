export type ReportScalar = string | number | boolean | null;
export type ReportItemValue = ReportScalar | ReportScalar[] | Record<string, ReportScalar | ReportScalar[]>;

export interface ExportReportField {
  label: string;
  value: ReportItemValue;
}

export interface ExportReportSection {
  id: string;
  label: string;
  items: Array<string | ExportReportField | Record<string, ReportItemValue>>;
}

export interface ExportReportDocument {
  title: string;
  createdAt: string;
  summary?: ExportReportField[];
  sections: ExportReportSection[];
  notes?: string[];
}

export interface ExportReportTextOptions {
  translate?: (value: string) => string;
  formatDateTime?: (value: number | string | Date) => string;
}

export interface ReviewStatusBucketInput {
  verified?: Array<string | ExportReportField | Record<string, ReportItemValue>>;
  detected?: Array<string | ExportReportField | Record<string, ReportItemValue>>;
  removed?: Array<string | ExportReportField | Record<string, ReportItemValue>>;
  declaredOnly?: Array<string | ExportReportField | Record<string, ReportItemValue>>;
  notVerified?: Array<string | ExportReportField | Record<string, ReportItemValue>>;
  reviewRequired?: Array<string | ExportReportField | Record<string, ReportItemValue>>;
}

export function renderExportReportText(report: ExportReportDocument, options: ExportReportTextOptions = {}) {
  const translate = options.translate ?? ((value: string) => value);
  const formatDateTime = options.formatDateTime ?? ((value: number | string | Date) => String(value));
  const lines = [translate(report.title), `${translate("Created")}: ${formatDateTime(report.createdAt)}`];

  if (report.summary?.length) {
    lines.push("");
    lines.push(`${translate("Summary")}:`);
    report.summary.forEach((field) => {
      lines.push(`- ${field.label}: ${formatReportValue(field.value, translate)}`);
    });
  }

  report.sections.forEach((section) => {
    if (section.items.length === 0) return;
    lines.push("");
    lines.push(section.label);
    lines.push("-".repeat(section.label.length));
    section.items.forEach((item) => {
      if (typeof item === "string") {
        lines.push(`- ${item}`);
        return;
      }

      if ("label" in item && "value" in item) {
        lines.push(`- ${item.label}: ${formatReportValue(item.value, translate)}`);
        return;
      }

      const entries = Object.entries(item);
      if (entries.length === 0) return;
      if (entries.length === 1) {
        const [label, value] = entries[0];
        lines.push(`- ${label}: ${formatReportValue(value, translate)}`);
        return;
      }
      lines.push(`- ${entries.map(([label, value]) => `${label}: ${formatReportValue(value, translate)}`).join(" | ")}`);
    });
  });

  if (report.notes?.length) {
    lines.push("");
    lines.push(`${translate("Notes")}:`);
    report.notes.forEach((note) => {
      lines.push(`- ${note}`);
    });
  }

  return `${lines.join("\n")}\n`;
}

export function buildReviewStatusSections(input: ReviewStatusBucketInput): ExportReportSection[] {
  return [
    { id: "verified", label: "Verified", items: compactItems(input.verified) },
    { id: "detected", label: "Detected", items: compactItems(input.detected) },
    { id: "removed", label: "Removed", items: compactItems(input.removed) },
    { id: "declared-only", label: "Declared only", items: compactItems(input.declaredOnly) },
    { id: "not-verified", label: "Not verified", items: compactItems(input.notVerified) },
    { id: "review-required", label: "Review required", items: compactItems(input.reviewRequired) },
  ].filter((section) => section.items.length > 0);
}

export function localizeExportValue<T>(value: T, translate: (value: string) => string): T {
  if (typeof value === "string") return translate(value) as T;
  if (Array.isArray(value)) return value.map((item) => localizeExportValue(item, translate)) as T;
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [key, localizeExportValue(entry, translate)]),
  ) as T;
}

function formatReportValue(value: ReportItemValue, translate: (value: string) => string): string {
  if (Array.isArray(value)) return value.map((entry) => formatScalar(entry, translate)).join(", ");
  if (value && typeof value === "object") {
    return Object.entries(value)
      .map(([key, entry]) => `${key}=${Array.isArray(entry) ? entry.map((part) => formatScalar(part, translate)).join(", ") : formatScalar(entry, translate)}`)
      .join("; ");
  }
  return formatScalar(value, translate);
}

function formatScalar(value: ReportScalar, translate: (value: string) => string) {
  if (value === null) return translate("none");
  if (typeof value === "boolean") return value ? translate("yes") : translate("no");
  return String(value);
}

function compactItems(value?: Array<string | ExportReportField | Record<string, ReportItemValue>>) {
  return (value ?? []).filter(Boolean);
}
