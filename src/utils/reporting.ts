type ReportScalar = string | number | boolean | null;
export type ReportItemValue = ReportScalar | ReportScalar[] | Record<string, ReportScalar | ReportScalar[]>;

export interface ExportReportField {
  label: string;
  value: ReportItemValue;
}

interface ExportReportSection {
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

      if (isExportReportField(item)) {
        lines.push(`- ${item.label}: ${formatReportValue(item.value, translate)}`);
        return;
      }

      if ("label" in item && "value" in item) {
        const value = (item as Record<string, unknown>).value;
        lines.push(`- value: ${isReportItemValue(value) ? formatReportValue(value, translate) : translate("invalid")}`);
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

export function localizeExportValue<T>(value: T, translate: (value: string) => string): T {
  void translate;
  return value;
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

function isExportReportField(value: unknown): value is ExportReportField {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value) && typeof (value as ExportReportField).label === "string" && isReportItemValue((value as ExportReportField).value);
}

function isReportItemValue(value: unknown): value is ReportItemValue {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") return true;
  if (Array.isArray(value)) {
    return value.every((entry) => entry === null || typeof entry === "string" || typeof entry === "number" || typeof entry === "boolean");
  }
  if (!value || typeof value !== "object") return false;
  return Object.values(value).every(
    (entry) =>
      entry === null ||
      typeof entry === "string" ||
      typeof entry === "number" ||
      typeof entry === "boolean" ||
      (Array.isArray(entry) &&
        entry.every((part) => part === null || typeof part === "string" || typeof part === "number" || typeof part === "boolean")),
  );
}
