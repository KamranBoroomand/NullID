export type GuideToolContent = {
  key: string;
  title: string;
  whatItDoes: string;
  whatWhen: string[];
  howSteps: string[];
  limits: string[];
  privacyNotes?: string[];
};

export const guideTools: GuideToolContent[] = [
  {
    key: "hash",
    title: "Hash & Verify",
    whatItDoes:
      "Compute SHA-256 / SHA-512 / SHA-1 (legacy) for text or files, verify against expected digests, and export integrity manifests/batch hash reports.",
    whatWhen: ["Validate downloads or artifacts without leaving the browser", "Build line-by-line digest manifests for incident notes"],
    howSteps: [
      "Paste text or drop a file; hashing runs immediately.",
      "Pick the algorithm and format (hex/base64/sha256sum).",
      "Use verify to compare against an expected digest or a second file.",
      "Copy outputs with clipboard hygiene enabled for auto-clear.",
    ],
    limits: [
      "Huge files are limited by browser memory; cancel if it stalls.",
      "SHA-1 is insecure for collisions; only use when required for legacy.",
      "Clipboard auto-clear is best-effort; other apps may read it before clear.",
    ],
  },
  {
    key: "redact",
    title: "Text Redaction",
    whatItDoes:
      "Detects and masks PII/secrets (email, phone, IP/IPv6, IDs, IBAN, valid credit cards via Luhn, AWS keys/secrets, GitHub/Slack tokens, private key blocks, bearer tokens) with severity filtering and exportable risk reports.",
    whatWhen: ["Sanitize chat transcripts or documents before sharing", "Remove account numbers or tokens from support logs"],
    howSteps: [
      "Paste text and choose mask mode (full/partial).",
      "Toggle detectors; custom regex rules can be added locally.",
      "Preview highlights, then apply and copy/download the redacted text.",
      "Use auto-clearing clipboard to reduce residue.",
    ],
    limits: [
      "Credit cards are only flagged when they pass Luhn; spacing/punctuation is tolerated.",
      "IBAN and token patterns can still false-positive; review before sharing.",
      "Clipboard and downloads stay local; clearing the clipboard is best-effort.",
    ],
  },
  {
    key: "sanitize",
    title: "Log Sanitizer",
    whatItDoes:
      "Rule-based scrubbing for logs with diff preview, signed local policy packs, simulation matrix comparisons, rule-impact ranking, batch file sanitization, baseline policy merge, and safe-share bundle export (including GitHub/Slack token and private-key block stripping).",
    whatWhen: ["Share log snippets in tickets", "Normalize noisy logs for demos/docs", "Generate portable sanitized bundles with integrity metadata"],
    howSteps: [
      "Paste logs or load a preset, toggle rules, and enable JSON-aware cleaning if applicable.",
      "Save/import policy packs to reuse rule sets and custom regexes locally.",
      "Use signed exports for policy packs and verify signatures before import.",
      "Import `nullid.policy.json` workspace baseline files to apply deterministic merge rules.",
      "Review the before/after diff; enable wrap for narrow screens.",
      "Run batch mode for multiple files, then export outputs/report.",
      "Export a safe-share bundle (optionally encrypted) with policy + SHA-256 hashes.",
    ],
    limits: [
      "Regex operates per line; extremely unstructured logs may need custom rules.",
      "Bearer/token detection avoids short strings but still may miss exotic formats.",
      "JSON parsing is best-effort; invalid JSON falls back to plain text rules.",
      "Signing key hints are labels only; passphrases are never stored and must be re-entered.",
    ],
  },
  {
    key: "meta",
    title: "Metadata Inspector",
    whatItDoes:
      "Reads local image metadata (JPEG/TIFF EXIF, PNG/WebP/GIF hints), surfaces browser compatibility diagnostics, re-encodes images with configurable output codec/quality, and records before/after forensic SHA-256 fingerprints.",
    whatWhen: ["Clear camera/location data before sharing images", "Downsize images while removing EXIF/metadata"],
    howSteps: [
      "Drop an image (JPEG/PNG/WebP/AVIF/GIF/BMP/TIFF) and inspect parsed metadata fields.",
      "Review compatibility diagnostics (decode/encode/clean export) for your browser.",
      "Choose resize before exporting and download the cleaned output.",
    ],
    limits: [
      "HEIC/HEIF is usually unsupported in-browser and is explicitly blocked with remediation guidance.",
      "Canvas re-encode may change compression or flatten animation/transparency for some formats.",
      "Previews are contained; large images are scaled for display only.",
      "PDF/Office metadata cleaning is CLI-based (`pdf-clean`, `office-clean`) and best-effort for complex/encoded formats.",
    ],
  },
  {
    key: "enc",
    title: "Encrypt / Decrypt",
    whatItDoes:
      "NULLID envelope (PBKDF2 + AES-GCM) for sealing text or files; supports profile/custom KDF settings, envelope-header inspection, passphrase strength checks, encrypted download, and decrypt with AAD.",
    whatWhen: ["Send a sealed blob through untrusted channels", "Quickly encrypt a snippet without installing tools"],
    howSteps: [
      "Enter plaintext and passphrase; choose KDF profile (compat/strong/paranoid), then seal text or file. Downloads use .nullid.",
      "Decrypt by pasting the envelope or loading a file, then supply the passphrase.",
      "Use hygiene auto-clear timers to wipe plaintext after a delay.",
    ],
    limits: [
      "Passphrase strength matters; no recovery if lost.",
      "Auto-clear only wipes in-app state and clipboard; memory may still hold data temporarily.",
      "AES-GCM requires intact envelopes; corruption will fail integrity checks.",
    ],
  },
  {
    key: "pw",
    title: "Password & Passphrase",
    whatItDoes:
      "Local generator with advanced constraints, large virtual passphrase dictionaries, strength lab auditing, and batch candidate generation.",
    whatWhen: ["Create high-entropy secrets without cloud services", "Audit existing passwords/passphrases before adoption"],
    howSteps: [
      "Adjust length/character sets and hardening toggles (sequence/repeat blocking, min unique chars).",
      "Use passphrase dictionary profiles (balanced/extended/maximal) plus casing/number/symbol modes.",
      "Run Strength Lab to audit any secret and review effective entropy plus crack-time estimates.",
      "Generate a batch shortlist, then copy the candidate that fits your policy.",
    ],
    limits: [
      "Do not reuse generated passwords; store them in a secure manager.",
      "Clipboard auto-clear reduces exposure but is not foolproof.",
      "Entropy estimates are model-based; treat them as guidance rather than a formal guarantee.",
    ],
  },
  {
    key: "vault",
    title: "Secure Notes",
    whatItDoes:
      "IndexedDB-backed vault with AES-GCM per note, activity-based auto-lock countdown, note templates, analytics/report export, tab-hide lock, and panic hotkey (Ctrl+Shift+L).",
    whatWhen: ["Keep short secrets locally without syncing", "Store incident notes while offline"],
    howSteps: [
      "Unlock with a passphrase to derive the key; notes decrypt only in-memory.",
      "Activity resets the auto-lock timer; adjust seconds in the control.",
      "Use Ctrl+Shift+L to panic-lock immediately; tab switching also locks.",
      "Export/import (plain or encrypted) for offline backup; optional signed metadata verification is available.",
      "Wipe clears IndexedDB/localStorage vault stores.",
    ],
    limits: [
      "If idle beyond the timeout, the vault locks and clears decrypted data.",
      "Encrypted exports require the provided passphrase; losing it prevents restore.",
      "Signed exports require the same verification passphrase during import.",
      "Browser storage limits apply; keep backups externally.",
    ],
  },
];

export const guideExtras: GuideToolContent[] = [
  {
    key: "profiles",
    title: "Profiles (export / import)",
    whatItDoes:
      "Save or load preferences stored under the nullid:* keys in localStorage (not the vault DB), with integrity checks and optional signed metadata.",
    whatWhen: ["Migrate settings between browsers", "Back up preferences before wiping data"],
    howSteps: [
      "Use the command palette (System → Export profile) to download a JSON snapshot.",
      "Optionally sign profile metadata with a passphrase during export.",
      "Import via System → Import profile and choose the JSON file; signed profiles can be verified with a passphrase.",
      "Schema versioning and payload hashing guard incompatible or tampered snapshots; only keys under nullid:* are written back.",
    ],
    limits: [
      "Vault content lives in IndexedDB and is not included; export the vault separately.",
      "Signed imports without the correct verification passphrase are rejected.",
      "Only well-typed values are applied; malformed/tampered JSON is rejected.",
      "Imported values overwrite existing preferences for matching keys.",
    ],
  },
  {
    key: "clipboard",
    title: "Clipboard hygiene",
    whatItDoes: "Optional auto-clear for all copy actions using the shared clipboard helper.",
    whatWhen: ["Copy secrets, hashes, or outputs to the system clipboard", "Reduce clipboard residue on shared machines"],
    howSteps: [
      "Auto-clear is enabled by default for 30 seconds; adjust or disable in settings-aware components.",
      "All copy buttons route through the helper; best-effort overwrite clears after the timer.",
      "Status/toast messages surface copy failures (e.g., permission denied).",
    ],
    limits: [
      "Clipboard APIs require browser permission; blocked writes will be reported.",
      "Other apps may read the clipboard before the timer clears it.",
      "Auto-clear attempts to write an empty string; some platforms may retain history.",
    ],
  },
];
