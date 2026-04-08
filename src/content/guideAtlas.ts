export type GuideQuickPath =
  | {
      kind: "entry";
      label: string;
      note: string;
      target: string;
    }
  | {
      kind: "atlas";
      label: string;
      note: string;
    };

export type GuideGroupDefinition = {
  label: string;
  description: string;
  keys: string[];
};

export const guideQuickPaths: GuideQuickPath[] = [
  {
    kind: "entry",
    label: "I need to verify something",
    note: "Open receiver-side package inspection and trust summaries first.",
    target: "verify",
  },
  {
    kind: "entry",
    label: "I need to review a mixed set of files",
    note: "Start with Batch Review when you need one workspace for text, files, archives, and handoff decisions.",
    target: "batch",
  },
  {
    kind: "entry",
    label: "I need to redact text",
    note: "Strip obvious sensitive strings and review the findings table.",
    target: "redact",
  },
  {
    kind: "entry",
    label: "I need to sanitize a file or log",
    note: "Apply policy packs, compare diffs, and export the cleaned bundle only.",
    target: "sanitize",
  },
  {
    kind: "entry",
    label: "I need to protect or share data",
    note: "Choose between guided export, incident packaging, encryption envelopes, and sealed local notes.",
    target: "share",
  },
  {
    kind: "entry",
    label: "I need to inspect metadata",
    note: "Open metadata inspection before publishing or handing off media.",
    target: "meta",
  },
  {
    kind: "atlas",
    label: "I need help choosing a tool",
    note: "Open the atlas dossier and choose the right working surface from there.",
  },
];

export const guideGroupDefinitions: GuideGroupDefinition[] = [
  {
    label: "Core tools",
    description: "Create, stage, review, and hand off artifacts under local control.",
    keys: ["hash", "batch", "share", "incident"],
  },
  {
    label: "Verification",
    description: "Inspect received material and report what can actually be verified.",
    keys: ["verify", "meta"],
  },
  {
    label: "Privacy / sanitization",
    description: "Remove residue, review likely secrets or identifiers, and prepare cleaner exports.",
    keys: ["redact", "sanitize", "secret", "analyze", "finance", "paths"],
  },
  {
    label: "Encryption / secrets",
    description: "Protect local secrets, envelopes, notes, and profile metadata.",
    keys: ["enc", "pw", "vault", "profiles"],
  },
  {
    label: "Diagnostics / operator aids",
    description: "Check local behavior, clipboard hygiene, and operating assumptions.",
    keys: ["selftest", "clipboard", "models"],
  },
];

export const guideAtlasRoutingNotes = [
  "Start from the artifact in front of you: received package, raw text, file, secret, note, or mixed review set.",
  "Use Verify first for material that came from someone else; use preparation tools before exporting anything outward.",
  "Pick Batch Review when you need one place to compare findings across notes, files, archives, and likely handoff candidates.",
  "Pick Redaction, Sanitizer, Secret Scanner, Structured Analyzer, Financial Review, or Filename Privacy when you need to remove or understand residue before sharing.",
  "Open any atlas card below to read the full dossier immediately without leaving your current position.",
];
