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
      "Rule-based scrubbing for logs with diff preview, reusable local policy packs, optional shared-passphrase HMAC metadata, simulation matrix comparisons, rule-impact ranking, batch file sanitization, baseline policy merge, and safe-share bundle export (including GitHub/Slack token and private-key block stripping).",
    whatWhen: ["Share log snippets in tickets", "Normalize noisy logs for demos/docs", "Generate portable sanitized bundles with integrity metadata"],
    howSteps: [
      "Paste logs or load a preset, toggle rules, and enable JSON-aware cleaning if applicable.",
      "Save/import policy packs to reuse rule sets and custom regexes locally.",
      "Add HMAC metadata to policy exports when import-time authenticity checks matter.",
      "Import `nullid.policy.json` workspace baseline files to apply deterministic merge rules.",
      "Review the before/after diff; enable wrap for narrow screens.",
      "Run batch mode for multiple files, then export outputs/report.",
      "Export a safe-share bundle (optionally encrypted) with policy + SHA-256 hashes.",
    ],
    limits: [
      "Regex operates per line; extremely unstructured logs may need custom rules.",
      "Bearer/token detection avoids short strings but still may miss exotic formats.",
      "JSON parsing is best-effort; invalid JSON falls back to plain text rules.",
      "Verification key hints are labels only; HMAC passphrases are never stored and must be re-entered.",
    ],
  },
  {
    key: "batch",
    title: "Batch Review Workspace",
    whatItDoes:
      "Collect multiple text entries and files into one local review session, summarize findings per item, and hand selected items into sharing workflows only after review.",
    whatWhen: [
      "Review a mixed set of notes, logs, screenshots, archives, and office files in one sitting before controlled sharing",
      "Build a sender/receiver checklist from actual local analysis instead of generic reminders",
    ],
    howSteps: [
      "Add pasted text entries or local files into the session.",
      "Review per-item findings, metadata, redaction preview availability, and likely-secret summaries.",
      "Reorder or remove items until the session reflects what you actually want to hand off.",
      "Export a batch report or checklist, then send selected items into Safe Share or Incident Workflow.",
    ],
    limits: [
      "Batch review keeps all analysis local, but it does not prove completeness or sender identity.",
      "Optional regional detectors remain conservative and can still false-positive.",
      "Safe Share accepts one selected item at a time so the resulting package stays explicit.",
    ],
  },
  {
    key: "share",
    title: "Safe Share Assistant",
    whatItDoes:
      "Guided local workflow for preparing text snippets or files to share safely, with workflow presets, sanitize or metadata review, optional NULLID:ENC:1 wrapping, and receiver-friendly workflow package export.",
    whatWhen: [
      "Package a support snippet or screenshot for someone else without falling back to ad-hoc copy/paste",
      "Prepare a receiver-facing package with transforms, warnings, and honest trust labels already attached",
    ],
    howSteps: [
      "Choose text or a file, then let NullID classify what kind of share you are preparing.",
      "Pick a workflow preset such as support ticket, external minimum disclosure, or evidence archive.",
      "Review sanitize findings or metadata signals before exporting.",
      "Decide whether to include only a source reference, a locally cleaned file, or a context-preserving original payload when the preset allows it.",
      "Optionally wrap the exported workflow package in a NULLID:ENC:1 envelope before sending it onward.",
    ],
    limits: [
      "Workflow packages are still unsigned in this step; they do not prove sender identity.",
      "NULLID:ENC:1 adds confidentiality for the exported file, not public-key authenticity.",
      "Some file formats still require external offline cleanup before wider sharing.",
      "Lower-level tools remain available when you need direct control over sanitize, metadata, or envelope details.",
    ],
  },
  {
    key: "incident",
    title: "Incident Workflow",
    whatItDoes:
      "Guided local workflow for assembling incident notes, prepared text/file artifacts, hashes, transform summaries, and receiver-facing reporting into one incident package.",
    whatWhen: [
      "Hand off an incident to another responder without losing what was changed, preserved, or left unproven",
      "Assemble a local incident package with notes, metadata review, and honest trust language instead of juggling separate primitive exports",
    ],
    howSteps: [
      "Define the incident title, purpose, case reference, recipient scope, and a short summary.",
      "Prepare case notes with the same incident template headings used in Secure Notes, then review sanitize findings before export.",
      "Add extra text snippets or file artifacts; files are analyzed locally for metadata risk and cleaned in-browser when supported.",
      "Choose an incident mode such as handoff, evidence archive, minimal disclosure, or internal investigation.",
      "Review the final package summary, included artifacts, transform log, and what the receiver can and cannot verify before exporting.",
    ],
    limits: [
      "Incident packages are still unsigned in this step and do not prove sender identity.",
      "NULLID:ENC:1 only protects the exported file at rest/in transit for parties with the passphrase; it is not a sender signature.",
      "Some file formats still require external offline cleanup before they are safe for broader sharing.",
      "This workflow improves discipline and explainability, not legal/forensic chain-of-custody guarantees.",
    ],
  },
  {
    key: "secret",
    title: "Secret Scanner",
    whatItDoes:
      "Pattern-based local scanner for likely secrets such as JWTs, bearer tokens, private-key blocks, GitHub/Slack/AWS-style tokens, credential-like assignments, and high-entropy candidates.",
    whatWhen: [
      "Check pasted config, logs, headers, or snippets for likely secrets before sharing",
      "Export a local report that explains why a token was flagged without sending content anywhere",
    ],
    howSteps: [
      "Paste text or load a local text file.",
      "Review finding type, confidence, evidence mode, and reason for each match.",
      "Apply redaction locally or send the exact findings into :redact for broader editing control.",
      "Export a scan report if you need a local review artifact.",
    ],
    limits: [
      "This tool reports pattern-based / likely secret findings only; it does not prove a token is active or valid.",
      "Heuristic high-entropy candidates are useful for review but have a higher false-positive rate.",
      "The default report avoids full token dumps, but the input itself remains in your current local session until you clear it.",
    ],
  },
  {
    key: "analyze",
    title: "Structured Analyzer",
    whatItDoes:
      "Groups local text findings into emails, phones, URLs, IDs, likely secrets, and optional regional Iran/Russia patterns, then lets you export a clean version or analysis report.",
    whatWhen: [
      "Review sensitive text systematically before redaction or controlled sharing",
      "Summarize what kinds of sensitive content appear in a pasted message, export, or transcript without network calls",
    ],
    howSteps: [
      "Paste text or load a local text file.",
      "Enable optional Iran/Persian or Russia rule sets only when they fit the material you are reviewing.",
      "Review grouped findings by category and the separate regional summaries.",
      "Export clean text directly or send the exact findings into :redact for a fuller edit/review pass.",
    ],
    limits: [
      "Grouped counts help triage content, but they do not prove completeness or correctness.",
      "Optional regional detectors are conservative and still need human review for false positives.",
      "Secrets/tokens may be heuristic findings; treat them as leads for review rather than cryptographic certainty.",
    ],
  },
  {
    key: "finance",
    title: "Financial Identifier Review",
    whatItDoes:
      "Locally reviews bank-card numbers, IBAN/Sheba identifiers, account-like numbers, and invoice/reference-style numeric labels, then offers exportable findings and redaction preview.",
    whatWhen: [
      "Review payment-related text before sharing with internal or external recipients",
      "Check whether pasted invoices, payment notes, or support logs expose banking identifiers",
    ],
    howSteps: [
      "Paste text or load a local text file.",
      "Optionally enable Iran/Persian or Russia rules when they fit the material.",
      "Review pattern-based versus likely findings, then preview redaction locally.",
      "Export the review report or hand the exact matches into :redact.",
    ],
    limits: [
      "Pattern-based matches still do not prove a card, IBAN, or account is active or correctly attributed.",
      "Account/reference findings are context-driven and more false-positive prone than checksum-backed card/IBAN matches.",
      "This tool helps review and redaction; it does not validate ownership, balances, or payment status.",
    ],
  },
  {
    key: "paths",
    title: "Filename / Path Privacy",
    whatItDoes:
      "Reviews filenames and pasted paths for likely personal names, employee IDs, case/ticket IDs, project labels, usernames, and hostnames, then suggests preview-only safe renames.",
    whatWhen: [
      "Check whether file labels themselves leak identity or internal context before export",
      "Prepare a safer filename/path naming convention without silently renaming anything",
    ],
    howSteps: [
      "Paste one filename or path per line.",
      "Review which segments were flagged and why they may be sensitive.",
      "Compare the preview rename suggestion with the original label.",
      "Apply your own manual rename only after review; NullID does not rename files automatically here.",
    ],
    limits: [
      "Path findings are conservative hints, not proof that a segment is truly sensitive in context.",
      "Browser file pickers usually expose only the filename, so deeper path review may require pasting the path manually.",
      "Suggested replacements are previews only and are never auto-applied.",
    ],
  },
  {
    key: "verify",
    title: "Verify Package",
    whatItDoes:
      "Receiver-side inspection for workflow packages, safe-share bundles, policy packs, profile snapshots, vault snapshots, and NULLID:ENC:1 envelopes with honest trust labels.",
    whatWhen: [
      "Check what a received package really contains before opening or re-sharing it",
      "Differentiate unsigned, integrity-checked, HMAC-verified, mismatched, malformed, and unsupported artifacts locally",
    ],
    howSteps: [
      "Paste the artifact JSON or load a local file into the verifier.",
      "Provide an envelope passphrase only when the package is wrapped in NULLID:ENC:1.",
      "Provide a verification passphrase only for formats that explicitly use shared-secret HMAC metadata.",
      "Review the trust basis, verified checks, warnings, and transform summary before acting on the artifact.",
    ],
    limits: [
      "Unsigned workflow packages do not assert sender identity.",
      "Shared-secret HMAC only proves integrity to parties who already know the same passphrase.",
      "Decrypted envelopes can still contain unsupported payloads; successful decryption is not the same as package verification.",
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
      "Local password/passphrase generator, strength lab, batch candidate generation, and password storage hashing/verification with Argon2id, PBKDF2-SHA256, and legacy migration options.",
    whatWhen: [
      "Create high-entropy secrets without cloud services",
      "Audit existing passwords/passphrases before adoption",
      "Create or verify password storage records for apps and local auth prototypes",
    ],
    howSteps: [
      "Adjust length/character sets and hardening toggles (sequence/repeat blocking, min unique chars).",
      "Run Strength Lab to audit any secret and review effective entropy plus crack-time estimates.",
      "Use passphrase dictionary profiles (balanced/extended/maximal) plus casing/number/symbol modes.",
      "For stored passwords, choose Argon2id when available or PBKDF2-SHA256 for compatibility, then hash locally and save the full record.",
      "Verify later by re-entering a candidate password; NullID recomputes with the stored salt and cost settings instead of decrypting anything.",
    ],
    limits: [
      "Do not reuse generated passwords; store them in a secure manager.",
      "Password storage hashes are one-way records, not encrypted secrets; the original password cannot be recovered from the hash.",
      "Argon2id availability depends on the browser/runtime. If unsupported, use PBKDF2-SHA256 as the compatibility fallback.",
      "Legacy SHA-256/SHA-512 options are migration-only for password storage because they are fast digests, not slow password KDFs.",
      "Clipboard auto-clear reduces exposure but is not foolproof, and entropy estimates are still model-based guidance.",
    ],
    privacyNotes: [
      "Store the full password hash record, not just the digest. The record carries the algorithm, salt, cost factors, and derived hash needed for verification.",
      "Salt is random per record, so identical passwords produce different stored hashes.",
      "NullID password records are intended for NullID or tooling that deliberately supports this format. Argon2id output is PHC-like, while PBKDF2 and legacy SHA records are NullID-defined.",
    ],
  },
  {
    key: "vault",
    title: "Secure Notes",
    whatItDoes:
      "AES-GCM note vault with IndexedDB storage, localStorage fallback in restricted runtimes, activity-based auto-lock countdown, note templates, analytics/report export, tab-hide lock, and panic hotkey (Ctrl+Shift+L).",
    whatWhen: ["Keep short secrets locally without syncing", "Store incident notes while offline"],
    howSteps: [
      "Unlock with a passphrase to derive the key; notes decrypt only in-memory.",
      "Enable unlock rate limits, human checks, and optional WebAuthn MFA when local misuse resistance matters.",
      "Activity resets the auto-lock timer; adjust seconds in the control.",
      "Use Ctrl+Shift+L to panic-lock immediately; tab switching also locks.",
      "Export/import (plain or encrypted) for offline backup; optional shared-passphrase HMAC verification is available.",
      "Session-cookie signaling is a browser-visible presence hint only; it is not a server-side auth boundary.",
      "If IndexedDB is unavailable, NullID falls back to localStorage and surfaces the reason in the UI.",
      "Wipe clears IndexedDB/localStorage vault stores.",
    ],
    limits: [
      "If idle beyond the timeout, the vault locks and clears decrypted data.",
      "If IndexedDB is blocked, the vault falls back to localStorage for compatibility and reliability tradeoffs.",
      "Encrypted exports require the provided passphrase; losing it prevents restore.",
      "WebAuthn MFA is local/device-bound and is not a recovery system; keep backups before relying on it.",
      "HMAC-verified exports require the same verification passphrase during import.",
      "Browser storage limits apply; keep backups externally. localStorage fallback keeps encryption but inherits localStorage visibility and quota limits.",
    ],
    privacyNotes: [
      "Titles, bodies, tags, and note created timestamps are stored inside AES-GCM ciphertext and decrypt only after unlock.",
      "Note IDs, per-note updated timestamps, IVs, the vault canary, and vault KDF metadata (salt/iterations/version/lockedAt) remain visible as local browser data so the app can manage records.",
      "localStorage fallback keeps note contents encrypted, but ciphertext blobs and metadata keys still live in localStorage until wipe.",
      "Notes reports export plain JSON; including note bodies writes plaintext content into that report.",
    ],
  },
  {
    key: "selftest",
    title: "Self-test",
    whatItDoes:
      "Runs local runtime checks for crypto, storage, browser capability support, and responsiveness, and can export a diagnostic report.",
    whatWhen: [
      "Validate a browser/device before relying on NullID workflows",
      "Check why clipboard, vault, or media features are degraded in a restricted runtime",
    ],
    howSteps: [
      "Run all to probe crypto round-trips, storage backend health, capability support, and hash responsiveness.",
      "Review failed or warning checks; each row includes a remediation hint.",
      "Enable auto monitor for repeated checks in long-running sessions, then export a JSON report when you need to share local diagnostics.",
    ],
    limits: [
      "Self-test is a local environment diagnostic, not a security certification or cryptography audit.",
      "The runtime score is a convenience summary, not a security rating.",
      "The security-header check only inspects page-visible CSP/referrer markers; verify deployed response headers separately.",
      "Some checks are heuristics and may warn on hardened browsers even when a workflow still partially works.",
      "Clipboard, service worker, and browser-policy results reflect current runtime permissions and can change between sessions.",
    ],
  },
];

export const guideExtras: GuideToolContent[] = [
  {
    key: "profiles",
    title: "Profiles (export / import)",
    whatItDoes:
      "Save or load preferences stored under the nullid:* keys in localStorage, with integrity checks and optional shared-passphrase HMAC metadata.",
    whatWhen: ["Migrate settings between browsers", "Back up preferences before wiping data"],
    howSteps: [
      "Use the command palette (System → Export profile) to download a JSON snapshot.",
      "Optionally add HMAC metadata with a passphrase during export.",
      "Import via System → Import profile and choose the JSON file; HMAC-protected profiles can be verified with the same passphrase.",
      "Schema versioning and payload hashing guard incompatible or tampered snapshots; only keys under nullid:* are written back.",
    ],
    limits: [
      "Vault content lives outside profile snapshots; export the vault separately.",
      "Vault fallback blobs/metadata stored under nullid:vault:data:{store}:* are excluded from profile export/import; older nullid:vault:{store}:* fallback records are migrated locally and still ignored there.",
      "HMAC-protected imports without the correct verification passphrase are rejected.",
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
  {
    key: "models",
    title: "Integrity vs Password Hashing vs Encryption",
    whatItDoes:
      "Choose the right primitive: integrity hashes detect changes, password storage hashes verify a secret without storing it, and encryption keeps data reversible to authorized readers.",
    whatWhen: [
      "Decide whether you need change detection, one-way password verification, or reversible confidentiality",
      "Avoid mixing up digest tools, password storage records, and encrypted envelopes",
    ],
    howSteps: [
      "Use :hash or CLI hash when you only need to compare digests for files or text.",
      "Use Password Storage Hashing in :pw or CLI pw-hash / pw-verify when you must store a verifier for a user password.",
      "Use :enc, :vault, or CLI enc / dec when you need to recover plaintext later with a passphrase.",
      "Use export/profile/policy verification only for integrity/authenticity checks; HMAC metadata does not encrypt the payload.",
    ],
    limits: [
      "Integrity hashes are not salts or password KDFs; they do not slow offline guessing.",
      "Password hashes are not decryptable and should not be used to transport secret data.",
      "Encryption protects confidentiality, but it is a different workflow from password verification.",
    ],
  },
];
