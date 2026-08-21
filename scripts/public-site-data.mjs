export const PRODUCTION_ORIGIN = "https://nullid.kamranboroomand.ir";
export const SITE_NAME = "NullID";
export const SOCIAL_IMAGE_URL = `${PRODUCTION_ORIGIN}/nullid-preview.png`;
export const SOCIAL_IMAGE_ALT = "NullID application preview showing the Verify Package inspection workspace.";

export const rootPage = {
  path: "/",
  title: "NullID - Local Privacy and Security Workbench",
  description:
    "NullID is a local-first browser workbench for encryption, redaction, metadata privacy, hashing, verification, secret review, and password generation.",
  h1: "NullID",
};

export const publicPages = [
  {
    path: "/tools/",
    title: "Local-first privacy and security tools - NullID",
    description:
      "Browse NullID's local browser tools for encryption, redaction, metadata privacy, hashing, verification, safe sharing, secrets, and passwords.",
    h1: "Local-first privacy and security tools",
    intent: "local privacy tools",
    module: "tools hub",
    intro:
      "NullID groups browser-based privacy and security workflows into one workbench. Sensitive processing happens in your browser session; the application files are delivered from the NullID origin and can be cached for later PWA use.",
    sections: [
      {
        heading: "Encryption & secrets",
        body:
          "Use encryption, secret scanning, password generation, and Secure Notes when you need to prepare or protect sensitive material without a backend service.",
        links: ["/offline-file-encryption/", "/secret-scanner/", "/password-generator/"],
      },
      {
        heading: "Redaction & sanitization",
        body:
          "Use redaction for sensitive text spans and sanitization for repeatable log cleanup policies, diff review, batch text files, and safe-share bundle preparation.",
        links: ["/local-redaction/", "/file-sanitization/", "/safe-share/"],
      },
      {
        heading: "Metadata, integrity & verification",
        body:
          "Inspect image and document metadata, compute local checksums, and inspect NullID workflow packages with narrow trust labels.",
        links: ["/metadata-privacy/", "/hash-and-verify/", "/package-verification/"],
      },
    ],
    cards: [
      {
        title: "Encrypt files locally",
        body: "Create and decrypt NULLID:ENC:2 envelopes with PBKDF2-derived AES-GCM keys.",
        href: "/offline-file-encryption/",
      },
      {
        title: "Remove supported metadata",
        body: "Inspect image metadata in the browser and clean supported image/PDF metadata with format-specific warnings.",
        href: "/metadata-privacy/",
      },
      {
        title: "Redact sensitive text",
        body: "Mask emails, phones, IDs, likely secrets, tokens, and custom local regex matches before sharing text.",
        href: "/local-redaction/",
      },
      {
        title: "Sanitize logs",
        body: "Apply reusable local policy packs, diff previews, JSON-aware cleaning, and batch text-file sanitization.",
        href: "/file-sanitization/",
      },
      {
        title: "Hash and verify",
        body: "Compute SHA-256, SHA-512, and legacy SHA-1 digests for text or files and compare expected checksums.",
        href: "/hash-and-verify/",
      },
      {
        title: "Scan likely secrets",
        body: "Review logs, config snippets, and headers for pattern-based credential findings without uploading content.",
        href: "/secret-scanner/",
      },
      {
        title: "Generate passwords",
        body: "Generate passwords or passphrases locally and create one-way password storage records.",
        href: "/password-generator/",
      },
      {
        title: "Prepare safe-share packages",
        body: "Package reviewed text or files with warnings, transform history, and optional encryption.",
        href: "/safe-share/",
      },
      {
        title: "Verify packages",
        body: "Inspect received NullID packages, policy packs, snapshots, and envelopes with honest trust labels.",
        href: "/package-verification/",
      },
    ],
    cta: { label: "Open NullID workbench", href: "/" },
    related: ["/privacy/", "/faq/"],
  },
  {
    path: "/offline-file-encryption/",
    title: "Offline file encryption tool - NullID",
    description:
      "Encrypt files or text in the browser with NULLID:ENC:2 envelopes using PBKDF2-derived AES-GCM keys and local passphrases.",
    h1: "Offline file encryption in your browser",
    intent: "offline file encryption tool, local file encryption, browser file encryption",
    module: "enc",
    intro:
      "NullID's Encrypt / Decrypt workspace seals text snippets or files into portable NULLID:ENC:2 envelopes. The encryption and decryption operations run locally in the browser with WebCrypto.",
    sections: [
      {
        heading: "What it does",
        body:
          "The current envelope format uses PBKDF2 with SHA-256 or SHA-512 to derive an AES-GCM 256-bit key from your passphrase. Version 2 binds header metadata with authenticated additional data so filename and MIME fields are covered by the envelope integrity check.",
      },
      {
        heading: "How to use it",
        list: [
          "Open Encrypt / Decrypt in NullID.",
          "Enter text or choose a local file.",
          "Choose a KDF profile or custom PBKDF2 iteration/hash settings.",
          "Seal the payload and download the .nullid envelope.",
          "To decrypt, load or paste the envelope and enter the passphrase.",
        ],
      },
      {
        heading: "Privacy and offline behavior",
        body:
          "Payload bytes and passphrases are processed in the browser. The web application itself must first be loaded from nullid.kamranboroomand.ir; after the PWA runtime shell is cached, the root workbench can continue to load offline in supported browsers.",
      },
      {
        heading: "Limitations",
        list: [
          "A weak or lost passphrase cannot be recovered by NullID.",
          "Browser memory and configured input limits constrain very large files.",
          "AES-GCM integrity checks fail if the envelope is corrupted or the passphrase is wrong.",
          "Encryption protects envelope confidentiality; it does not prove sender identity.",
        ],
      },
    ],
    cta: { label: "Open Encryption in NullID", href: "/?tool=enc" },
    related: ["/password-generator/", "/package-verification/", "/safe-share/", "/privacy/"],
  },
  {
    path: "/metadata-privacy/",
    title: "Metadata privacy tool - NullID",
    description:
      "Inspect and clean supported image and document metadata locally with browser image re-encoding, PDF cleanup, hash comparison, and format warnings.",
    h1: "Metadata privacy before sharing files",
    intent: "metadata privacy, remove metadata locally, image metadata privacy",
    module: "meta",
    intro:
      "The Metadata Inspector helps you review what a local file exposes before you share it. It supports browser image inspection and cleaning, PDF metadata cleanup, archive inspection, and format-specific warnings.",
    sections: [
      {
        heading: "Supported browser image work",
        body:
          "NullID reads JPEG/TIFF EXIF and image metadata hints for common formats including PNG, WebP, GIF, AVIF, BMP, and TIFF where the browser can decode them. Clean image exports are created through browser image re-encoding with configurable output format, quality, and resizing.",
      },
      {
        heading: "Document and archive review",
        body:
          "Advanced metadata analysis can inspect PDF and ZIP-family archive signals. Browser PDF metadata cleanup targets visible PDF metadata fields. Office and more complex media cleanup remain format-dependent and may require external offline tooling.",
      },
      {
        heading: "How to use it",
        list: [
          "Open Metadata Inspector.",
          "Drop an image or file for local analysis.",
          "Review parsed fields, risk level, format diagnostics, and before SHA-256.",
          "Generate a cleaned output when the format supports it.",
          "Compare after SHA-256 and download the cleaned file.",
        ],
      },
      {
        heading: "Limitations",
        list: [
          "Metadata cleaning is best-effort and format-dependent.",
          "HEIC/HEIF is usually blocked by browser decode pipelines and is reported with remediation guidance.",
          "Canvas re-encoding can change compression, flatten animation, or affect transparency depending on format.",
          "Review outputs before sharing; NullID does not certify that every metadata field was removed.",
        ],
      },
    ],
    cta: { label: "Open Metadata in NullID", href: "/?tool=meta" },
    related: ["/file-sanitization/", "/safe-share/", "/hash-and-verify/", "/privacy/"],
  },
  {
    path: "/local-redaction/",
    title: "Local redaction tool - NullID",
    description:
      "Redact sensitive text locally with detectors for email, phone, IDs, tokens, private keys, financial identifiers, and custom regex rules.",
    h1: "Redact sensitive information locally",
    intent: "local redaction tool, offline text redaction, redact sensitive information locally",
    module: "redact",
    intro:
      "Text Redaction detects and masks sensitive spans in pasted text. It is meant for user-reviewed cleanup of logs, notes, snippets, and structured text before sharing.",
    sections: [
      {
        heading: "What it detects",
        body:
          "Built-in detectors cover email addresses, phone numbers, IP addresses, IDs, IBANs, Luhn-valid card numbers, AWS-style keys, GitHub and Slack tokens, bearer tokens, private key blocks, and optional regional identifier rule sets.",
      },
      {
        heading: "Workflow",
        list: [
          "Paste text into Redaction.",
          "Choose full or partial masking and severity filtering.",
          "Enable or disable detector groups and optional regional rules.",
          "Add local custom regex rules when the material has project-specific patterns.",
          "Review highlights, apply redaction, then copy or download the result.",
        ],
      },
      {
        heading: "How it differs from other tools",
        body:
          "Redaction changes sensitive spans in text. Sanitization applies repeatable cleanup policies for logs. Secret Scanner flags likely credentials and can send exact findings into Redaction.",
      },
      {
        heading: "Limitations",
        list: [
          "Pattern matching can miss unusual formats and can false-positive.",
          "Custom regex rules must complete safely before output is committed.",
          "Clipboard auto-clear is best-effort and cannot control other clipboard managers.",
          "Downloads and copied output remain on your device after export.",
        ],
      },
    ],
    cta: { label: "Open Redaction in NullID", href: "/?tool=redact" },
    related: ["/file-sanitization/", "/secret-scanner/", "/safe-share/", "/privacy/"],
  },
  {
    path: "/file-sanitization/",
    title: "File sanitization and log cleanup - NullID",
    description:
      "Sanitize logs and text files locally with reusable policy packs, JSON-aware rules, diff review, batch processing, and safe-share bundles.",
    h1: "Local file sanitization for logs and text",
    intent: "file sanitization tool, offline log sanitizer, local sanitization",
    module: "sanitize",
    intro:
      "The Log Sanitizer applies deterministic text cleanup rules to logs and structured snippets. It is designed for repeatable review before material is copied, downloaded, or packaged.",
    sections: [
      {
        heading: "What it supports",
        body:
          "Sanitization supports pasted text, common log presets, JSON-aware cleaning, reusable local policy packs, custom regex rules, policy import/export, batch text-file sanitization, and safe-share bundle export with SHA-256 package metadata.",
      },
      {
        heading: "How to use it",
        list: [
          "Choose a preset or import a baseline policy.",
          "Paste logs or load supported text files.",
          "Review the before/after diff and rule impact summary.",
          "Save or export a policy pack when the rules should be reused.",
          "Run batch mode for multiple text files or export a safe-share bundle.",
        ],
      },
      {
        heading: "Not the same as metadata cleanup",
        body:
          "Sanitization rewrites text content. Metadata cleanup reviews file metadata and image/PDF outputs. Redaction is better for one-off sensitive spans that need manual masking control.",
      },
      {
        heading: "Limitations",
        list: [
          "Rules operate on text; binary files need another workflow.",
          "Invalid JSON falls back to plain text rule handling.",
          "Token detection avoids short strings but may miss uncommon credential formats.",
          "HMAC metadata verifies policy exports only for parties sharing the same passphrase.",
        ],
      },
    ],
    cta: { label: "Open Sanitization in NullID", href: "/?tool=sanitize" },
    related: ["/local-redaction/", "/metadata-privacy/", "/secret-scanner/", "/safe-share/"],
  },
  {
    path: "/hash-and-verify/",
    title: "SHA-256 hash and checksum verifier - NullID",
    description:
      "Compute local SHA-256, SHA-512, and legacy SHA-1 digests for text or files, compare expected checksums, and export integrity manifests.",
    h1: "Hash and verify files locally",
    intent: "SHA-256 hash tool, checksum verifier, local hash tool",
    module: "hash",
    intro:
      "Hash & Verify computes file or text digests in the browser and compares them with expected checksums. It is useful for download checks, artifact review, and local integrity manifests.",
    sections: [
      {
        heading: "Algorithms and outputs",
        body:
          "NullID implements SHA-256, SHA-512, and SHA-1 for legacy interoperability. Outputs can be shown as hex, base64, or a SHA-256 sum-style line when SHA-256 is selected.",
      },
      {
        heading: "How to use it",
        list: [
          "Paste text or choose a local file.",
          "Select SHA-256, SHA-512, or SHA-1.",
          "Compare against an expected digest or compare two files.",
          "Export an integrity manifest or batch hash report when needed.",
        ],
      },
      {
        heading: "Privacy notes",
        body:
          "Digest calculation happens locally. The digest itself may still reveal that two parties have the same input, so treat exported manifests as integrity data rather than secret data.",
      },
      {
        heading: "Limitations",
        list: [
          "SHA-1 is collision-weakened and should only be used for legacy checks.",
          "Browser memory and the configured file limit constrain very large files.",
          "A matching checksum detects identical bytes; it does not prove who created the file.",
        ],
      },
    ],
    cta: { label: "Open Hash & Verify in NullID", href: "/?tool=hash" },
    related: ["/package-verification/", "/metadata-privacy/", "/offline-file-encryption/", "/faq/"],
  },
  {
    path: "/secret-scanner/",
    title: "Local secret scanner - NullID",
    description:
      "Scan text, logs, headers, and config snippets locally for likely tokens, private keys, bearer credentials, JWTs, and high-entropy candidates.",
    h1: "Scan likely secrets before sharing",
    intent: "local secret scanner, offline credential scanner",
    module: "secret",
    intro:
      "Secret Scanner reviews pasted text or supported text files for likely credentials. It is a local triage tool, not a token validation service.",
    sections: [
      {
        heading: "What it flags",
        body:
          "The scanner looks for JWTs, bearer tokens, private key blocks, GitHub, Slack, and AWS-style tokens, credential-like assignments, and optional high-entropy candidates.",
      },
      {
        heading: "How to use it",
        list: [
          "Paste text, configuration, headers, or logs.",
          "Choose whether to include heuristic high-entropy candidates.",
          "Review finding type, confidence, evidence, reason, and preview.",
          "Apply local redaction or send findings into Text Redaction.",
          "Export a local scan report if you need review evidence.",
        ],
      },
      {
        heading: "Limitations",
        list: [
          "Findings are pattern-based and do not prove a token is active.",
          "High-entropy candidates have a higher false-positive rate.",
          "Unusual credentials can be missed.",
          "Input remains in the current browser session until cleared or wiped.",
        ],
      },
    ],
    cta: { label: "Open Secret Scanner in NullID", href: "/?tool=secret" },
    related: ["/local-redaction/", "/file-sanitization/", "/safe-share/", "/privacy/"],
  },
  {
    path: "/password-generator/",
    title: "Offline password and passphrase generator - NullID",
    description:
      "Generate passwords and passphrases locally, review strength estimates, create batches, and build one-way password storage records.",
    h1: "Generate passwords and passphrases locally",
    intent: "offline password generator, local passphrase generator",
    module: "pw",
    intro:
      "Password & Passphrase creates local password and passphrase candidates and can generate password storage verifier records for applications or local prototypes.",
    sections: [
      {
        heading: "Generation controls",
        body:
          "Password generation supports length, character sets, ambiguity avoidance, sequence and repeat blocking, and minimum unique-character settings. Passphrase generation supports dictionary profiles, word counts, separators, casing, numbers, symbols, and unique-word enforcement.",
      },
      {
        heading: "Hashing and verification",
        body:
          "Password storage records can use Argon2id when supported by the runtime or PBKDF2-SHA256 for compatibility. Legacy fast hash options are migration-only because they are not slow password KDFs.",
      },
      {
        heading: "How to use it",
        list: [
          "Choose a password or passphrase mode.",
          "Adjust generation settings or apply a preset.",
          "Review the strength lab and batch candidates.",
          "Copy with clipboard hygiene when needed.",
          "For storage records, save the full encoded record with salt and cost settings.",
        ],
      },
      {
        heading: "Limitations",
        list: [
          "Generated passwords should still be stored in a dedicated password manager.",
          "Strength estimates are model-based guidance, not a guarantee.",
          "One-way password records cannot recover the original password.",
          "Clipboard auto-clear is best-effort.",
        ],
      },
    ],
    cta: { label: "Open Password Generator in NullID", href: "/?tool=pw" },
    related: ["/offline-file-encryption/", "/privacy/", "/faq/"],
  },
  {
    path: "/safe-share/",
    title: "Safe sharing workflow - NullID",
    description:
      "Prepare text or files for sharing with local review, sanitization, metadata checks, workflow packages, warnings, hashes, and optional encryption.",
    h1: "Prepare sensitive material before sharing",
    intent: "safe share privacy workflow, local sharing preparation",
    module: "share",
    intro:
      "Safe Share is a guided workflow for preparing sensitive text or files. It helps you review what will be shared, what was transformed, and what still needs manual judgment.",
    sections: [
      {
        heading: "What it does",
        body:
          "Safe Share can classify text, apply sanitize policies, analyze file metadata, prepare local metadata cleanup when supported, build receiver-facing workflow packages, include SHA-256 package metadata, and optionally wrap exports in NULLID:ENC:2.",
      },
      {
        heading: "How to use it",
        list: [
          "Choose text or file mode.",
          "Pick a workflow preset and optional policy pack.",
          "Review sanitize findings, metadata signals, filename/path warnings, and package summary.",
          "Decide whether to include a source reference, cleaned file, or original payload when the preset allows it.",
          "Export the package, optionally encrypted with a passphrase.",
        ],
      },
      {
        heading: "What it does not do",
        list: [
          "It does not guarantee a file is safe.",
          "It does not prove sender identity.",
          "It does not replace legal, security, or incident-command review.",
          "Unsupported file formats may require external offline cleanup.",
        ],
      },
    ],
    cta: { label: "Open Safe Share in NullID", href: "/?tool=share" },
    related: ["/file-sanitization/", "/metadata-privacy/", "/offline-file-encryption/", "/package-verification/"],
  },
  {
    path: "/package-verification/",
    title: "Package verification tool - NullID",
    description:
      "Inspect NullID workflow packages, safe-share bundles, policy packs, profile snapshots, vault snapshots, and encryption envelopes locally.",
    h1: "Verify NullID packages honestly",
    intent: "package verification tool, local package inspection",
    module: "verify",
    intro:
      "Verify Package is the receiver-side inspection surface for NullID artifacts. It reports what can be checked locally and what remains declared-only or unproven.",
    sections: [
      {
        heading: "Supported artifacts",
        body:
          "The verifier handles workflow packages, safe-share bundles, policy packs, profile snapshots, vault snapshots, and NULLID:ENC:2 envelopes. It can use an envelope passphrase for encrypted packages and a shared verification passphrase for HMAC-protected formats.",
      },
      {
        heading: "What it can prove",
        body:
          "NullID can check schema shape, embedded hashes, envelope decryption and integrity, and shared-passphrase HMAC metadata where the artifact supports it. It labels unsigned and package-declared fields plainly.",
      },
      {
        heading: "How to use it",
        list: [
          "Paste an artifact or load a local file.",
          "Enter an envelope passphrase only for encrypted envelopes.",
          "Enter a verification passphrase only when the format includes shared-secret HMAC metadata.",
          "Review verified checks, warnings, trust basis, and manual-review items.",
          "Export a receiver checklist if needed.",
        ],
      },
      {
        heading: "Limitations",
        list: [
          "Successful decryption is not the same as sender authentication.",
          "Unsigned workflow packages do not assert sender identity.",
          "HMAC verification only works for parties already sharing the passphrase.",
          "Unknown or malformed artifacts are rejected or labeled unsupported.",
        ],
      },
    ],
    cta: { label: "Open Verify Package in NullID", href: "/?tool=verify" },
    related: ["/safe-share/", "/hash-and-verify/", "/offline-file-encryption/", "/faq/"],
  },
  {
    path: "/privacy/",
    title: "Privacy Policy - NullID",
    description:
      "NullID's privacy policy explains local browser processing, storage, PWA caching, exports, WebAuthn, analytics status, and data deletion.",
    h1: "Privacy Policy",
    intent: "NullID privacy policy",
    module: "privacy",
    intro:
      "NullID is designed for local browser processing. This policy explains what happens in the app, what can be stored in your browser profile, and where network access is still part of loading and updating the web application.",
    sections: [
      {
        heading: "Local processing",
        body:
          "Files, text, passphrases, generated passwords, redaction input, metadata analysis, hashing, and verification operations run in your browser session. NullID has no required backend service for those workflows.",
      },
      {
        heading: "Network delivery",
        body:
          "The web application assets must be loaded from nullid.kamranboroomand.ir before use and may be refreshed from that origin. After the service worker caches the runtime shell, supported browsers can reload the root workbench offline.",
      },
      {
        heading: "Browser storage",
        body:
          "NullID stores preferences and workflow settings under nullid-prefixed localStorage keys. Some tools retain local drafts or settings such as selected modules, theme, locale, layout, sanitize policies, redaction settings, password generator settings, and hash batch input.",
      },
      {
        heading: "Secure Notes and WebAuthn",
        body:
          "Secure Notes stores encrypted vault records in IndexedDB when available, with a generation-backed localStorage fallback in restricted runtimes. Optional local WebAuthn MFA is device-bound and is not a recovery system.",
      },
      {
        heading: "Exports and downloads",
        body:
          "User-triggered downloads can contain plaintext, redacted text, encrypted envelopes, metadata-cleaned files, reports, profiles, policy packs, vault snapshots, or workflow packages depending on the tool and choices made.",
      },
      {
        heading: "Analytics, cookies, and third parties",
        body:
          "The application does not include analytics, tracking scripts, external fonts, or runtime external API calls. Browser-visible local session markers may be used by the vault; server-side cookies or hosting logs are controlled by the deployment environment, not by a NullID backend.",
      },
      {
        heading: "Deleting local data",
        body:
          "Use Wipe local data inside the app to clear managed preferences and, when selected, vault stores. Browser site-data controls can also remove service-worker caches, localStorage, IndexedDB, and installed PWA data for the NullID origin.",
      },
      {
        heading: "Security limitations",
        body:
          "Local browser tools cannot protect against compromised devices, malicious browser extensions, operating-system malware, clipboard managers, or someone with access to your unlocked browser profile.",
      },
      {
        heading: "Security contact",
        body:
          "Report security issues through the private channels listed in the repository security policy. Do not open public vulnerability reports.",
      },
    ],
    cta: { label: "Open NullID workbench", href: "/" },
    related: ["/faq/", "/tools/"],
  },
  {
    path: "/faq/",
    title: "NullID FAQ - Local privacy tools",
    description:
      "Answers about NullID file uploads, offline use, supported metadata cleanup, encryption, package verification, storage, mobile use, and data reset.",
    h1: "NullID FAQ",
    intent: "NullID questions, local privacy tools FAQ",
    module: "faq",
    intro:
      "These answers describe the current NullID browser workbench and local CLI behavior. They are intentionally narrow so users can make informed choices.",
    faqs: [
      {
        question: "Does NullID upload my files?",
        answer:
          "No required backend receives your files for the core browser workflows. Files and text are processed in your browser session. The application assets still load from the NullID origin and may be refreshed from that origin.",
      },
      {
        question: "Can NullID work offline?",
        answer:
          "The root PWA workbench can reload offline after the runtime shell has been loaded and cached in a supported browser. The first load and updates require the production origin.",
      },
      {
        question: "Is NullID free?",
        answer:
          "The public repository is MIT licensed and the hosted browser workbench is intended to be free to use. No paid account system is part of the app.",
      },
      {
        question: "What file types can metadata cleanup handle?",
        answer:
          "Browser image cleanup depends on browser decoding and encoding support. JPEG, PNG, WebP, AVIF, GIF, BMP, and TIFF receive format diagnostics where applicable. PDF metadata cleanup is available for visible fields, while HEIC/HEIF and complex document/media formats may require external offline tools.",
      },
      {
        question: "What encryption does NullID use?",
        answer:
          "NULLID:ENC:2 envelopes use PBKDF2 with SHA-256 or SHA-512 to derive a 256-bit AES-GCM key. Version 2 authenticates header metadata with additional data.",
      },
      {
        question: "Can NullID guarantee a file is safe?",
        answer:
          "No. NullID can inspect, transform, hash, and label what it can verify, but it cannot guarantee safety, sender identity, legal sufficiency, or absence of every hidden issue.",
      },
      {
        question: "What does package verification prove?",
        answer:
          "It proves only the checks that complete: schema validity, embedded hash consistency, envelope integrity, or shared-passphrase HMAC verification for supported formats. Declared-only metadata remains labeled as such.",
      },
      {
        question: "Where does NullID store preferences or vault data?",
        answer:
          "Preferences and tool settings use nullid-prefixed browser storage keys. Secure Notes stores encrypted records in IndexedDB when available, with a localStorage fallback in restricted runtimes.",
      },
      {
        question: "Can I use NullID on mobile?",
        answer:
          "The workbench has responsive compact controls and mobile-oriented E2E coverage. Browser capability support still varies by device, especially for service workers, storage, image codecs, and WebAuthn.",
      },
      {
        question: "Is NullID open source?",
        answer:
          "Yes. The repository is public and licensed under MIT. Security issues should be reported privately through the repository security policy.",
      },
      {
        question: "What is the difference between Redact, Sanitize, and Metadata?",
        answer:
          "Redact masks sensitive text spans. Sanitize applies repeatable text/log cleanup policies and batch processing. Metadata inspects and cleans supported file metadata and image/PDF outputs.",
      },
      {
        question: "How do I clear local NullID data?",
        answer:
          "Use Wipe local data in the workbench, including the vault option when needed. Browser site-data controls can additionally remove service-worker caches, IndexedDB, localStorage, and installed PWA data.",
      },
    ],
    cta: { label: "Open NullID workbench", href: "/" },
    related: ["/privacy/", "/tools/"],
  },
];

export const sitemapPaths = [rootPage.path, ...publicPages.map((page) => page.path)];

export function canonicalUrl(pathname) {
  return `${PRODUCTION_ORIGIN}${pathname}`;
}
