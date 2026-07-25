// @ts-check
const EOCD_SIGNATURE = 0x06054b50;
const ZIP64_EOCD_LOCATOR_SIGNATURE = 0x07064b50;
const CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50;
const LOCAL_FILE_HEADER_SIGNATURE = 0x04034b50;
const UTF8_FLAG = 0x0800;
const ENCRYPTED_FLAG = 0x0001;
const STRONG_ENCRYPTION_FLAG = 0x0040;
const PATCHED_DATA_FLAG = 0x0020;

/**
 * @typedef {"rejected" | "policy-limit" | "malformed" | "unsupported"} ZipProblemCategory
 *
 * @typedef {Object} ZipSafetyLimits
 * @property {number} maxEntries
 * @property {number} maxNameBytes
 * @property {number} maxArchiveCompressedBytes
 * @property {number} maxEntryUncompressedBytes
 * @property {number} maxArchiveUncompressedBytes
 * @property {number} maxCompressionRatio
 *
 * @typedef {Object} ZipProblem
 * @property {ZipProblemCategory} category
 * @property {ZipProblemCategory} status
 * @property {string} detail
 *
 * @typedef {Object} ZipEntry
 * @property {string} path
 * @property {string} normalizedPath
 * @property {Uint8Array} rawName
 * @property {boolean} directory
 * @property {number} compressionMethod
 * @property {number} compressedBytes
 * @property {number} uncompressedBytes
 * @property {number} crc32
 * @property {number} localHeaderOffset
 * @property {number} dataOffset
 * @property {number} flags
 * @property {boolean} encrypted
 * @property {number} externalAttributes
 * @property {number | null} unixMode
 * @property {ZipProblem | null} problem
 *
 * @typedef {Object} ZipArchiveReadState
 * @property {number} actualArchiveBytes
 * @property {ZipSafetyLimits} limits
 *
 * @typedef {Object} ZipReadContext
 * @property {number} maxOutputBytes
 * @property {number} expectedBytes
 * @property {number} compressedBytes
 * @property {(byteLength: number) => void} accountOutputBytes
 * @property {number} accountedBytes
 *
 * @typedef {Object} ZipEocd
 * @property {number} eocdOffset
 * @property {number} totalEntries
 * @property {number} centralDirectoryBytes
 * @property {number} centralDirectoryOffset
 *
 * @typedef {Object} PathTrieNode
 * @property {Map<string, PathTrieNode>} children
 * @property {ZipEntry | null} terminalEntry
 */

const UNIX_SYSTEM_ID = 3;
const MACOS_SYSTEM_ID = 19;
const UNIX_FILE_TYPE_MASK = 0o170000;
const UNIX_REGULAR_FILE = 0o100000;
const UNIX_DIRECTORY = 0o040000;
const UNIX_SYMLINK = 0o120000;
const ZIP64_16 = 0xffff;
const ZIP64_32 = 0xffffffff;
const BYTES_PER_MIB = 1024 * 1024;

export const ZIP_SAFETY_LIMITS = Object.freeze({
  maxEntries: 4096,
  maxNameBytes: 4096,
  maxArchiveCompressedBytes: 50 * BYTES_PER_MIB,
  maxEntryUncompressedBytes: 50 * BYTES_PER_MIB,
  maxArchiveUncompressedBytes: 50 * BYTES_PER_MIB,
  maxCompressionRatio: 100,
});

const ZIP_ARCHIVE_STATE = Symbol("zipArchiveState");
const WINDOWS_RESERVED_NAMES = new Set([
  "CON",
  "PRN",
  "AUX",
  "NUL",
  ...Array.from({ length: 9 }, (_unused, index) => `COM${index + 1}`),
  ...Array.from({ length: 9 }, (_unused, index) => `LPT${index + 1}`),
]);

export class ZipSafetyError extends Error {
  /**
   * @param {ZipProblemCategory} category
   * @param {string} message
   * @param {string} [path]
   */
  constructor(category, message, path) {
    super(message);
    this.name = "ZipSafetyError";
    this.category = category;
    this.path = path;
  }
}

/**
 * @param {Uint8Array | ArrayBuffer} input
 * @param {{ limits?: Partial<ZipSafetyLimits> }} [options]
 * @returns {{ entries: ZipEntry[], limits: ZipSafetyLimits }}
 */
export function parseZipArchive(input, options = {}) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  /** @type {ZipSafetyLimits} */
  const limits = { ...ZIP_SAFETY_LIMITS, ...(options.limits ?? {}) };
  if (bytes.byteLength > limits.maxArchiveCompressedBytes) {
    throw new ZipSafetyError("policy-limit", `ZIP compressed archive exceeds ${limits.maxArchiveCompressedBytes} bytes.`);
  }
  const eocd = readEocd(bytes);
  const entries = readCentralDirectory(bytes, eocd, limits);
  markPathPolicyProblems(entries);
  markAggregateLimitProblems(entries, limits);
  attachArchiveReadState(entries, limits);
  return { entries, limits };
}

/**
 * @param {Uint8Array | ArrayBuffer} input
 * @param {ZipEntry} entry
 * @param {(compressed: Uint8Array, entry: ZipEntry, context: ZipReadContext) => Uint8Array} inflateRaw
 * @returns {Uint8Array}
 */
export function readZipEntryBytes(input, entry, inflateRaw) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (entry.problem) {
    throw new ZipSafetyError(entry.problem.category, entry.problem.detail, entry.path);
  }

  const compressed = bytes.subarray(entry.dataOffset, entry.dataOffset + entry.compressedBytes);
  const context = createReadContext(entry);
  let output;
  if (entry.compressionMethod === 0) {
    if (entry.compressedBytes !== entry.uncompressedBytes) {
      throw new ZipSafetyError("malformed", "Stored ZIP entry compressed and uncompressed sizes differ.", entry.path);
    }
    output = Uint8Array.from(compressed);
  } else if (entry.compressionMethod === 8) {
    try {
      output = inflateRaw(compressed, entry, context);
    } catch (error) {
      if (error instanceof ZipSafetyError) throw error;
      if (isBoundedOutputError(error)) {
        throw new ZipSafetyError("policy-limit", "Deflated ZIP entry exceeded bounded output policy limits.", entry.path);
      }
      const message = error instanceof Error ? error.message : String(error);
      throw new ZipSafetyError("malformed", `Deflated ZIP entry could not be decompressed: ${message}`, entry.path);
    }
  } else {
    throw new ZipSafetyError("unsupported", `Unsupported ZIP compression method ${entry.compressionMethod}.`, entry.path);
  }

  accountReturnedOutput(context, output);
  return verifyZipEntryOutput(entry, output);
}

/**
 * @param {Uint8Array | ArrayBuffer} input
 * @param {ZipEntry} entry
 * @param {(compressed: Uint8Array, entry: ZipEntry, context: ZipReadContext) => Promise<Uint8Array>} inflateRaw
 * @returns {Promise<Uint8Array>}
 */
export async function readZipEntryBytesAsync(input, entry, inflateRaw) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  if (entry.problem) {
    throw new ZipSafetyError(entry.problem.category, entry.problem.detail, entry.path);
  }

  const compressed = bytes.subarray(entry.dataOffset, entry.dataOffset + entry.compressedBytes);
  const context = createReadContext(entry);
  let output;
  if (entry.compressionMethod === 0) {
    if (entry.compressedBytes !== entry.uncompressedBytes) {
      throw new ZipSafetyError("malformed", "Stored ZIP entry compressed and uncompressed sizes differ.", entry.path);
    }
    output = Uint8Array.from(compressed);
  } else if (entry.compressionMethod === 8) {
    try {
      output = await inflateRaw(compressed, entry, context);
    } catch (error) {
      if (error instanceof ZipSafetyError) throw error;
      if (isBoundedOutputError(error)) {
        throw new ZipSafetyError("policy-limit", "Deflated ZIP entry exceeded bounded output policy limits.", entry.path);
      }
      const message = error instanceof Error ? error.message : String(error);
      throw new ZipSafetyError("malformed", `Deflated ZIP entry could not be decompressed: ${message}`, entry.path);
    }
  } else {
    throw new ZipSafetyError("unsupported", `Unsupported ZIP compression method ${entry.compressionMethod}.`, entry.path);
  }

  accountReturnedOutput(context, output);
  return verifyZipEntryOutput(entry, output);
}

/**
 * @param {ZipEntry[]} entries
 * @param {ZipSafetyLimits} limits
 */
function attachArchiveReadState(entries, limits) {
  /** @type {ZipArchiveReadState} */
  const state = {
    actualArchiveBytes: 0,
    limits,
  };
  entries.forEach((entry) => {
    Object.defineProperty(entry, ZIP_ARCHIVE_STATE, {
      configurable: false,
      enumerable: false,
      value: state,
    });
  });
}

/**
 * @param {ZipEntry & Partial<Record<symbol, ZipArchiveReadState>>} entry
 * @returns {ZipReadContext}
 */
function createReadContext(entry) {
  const state = entry[ZIP_ARCHIVE_STATE] ?? { actualArchiveBytes: 0, limits: ZIP_SAFETY_LIMITS };
  const limits = state.limits;
  let actualEntryBytes = 0;
  const ratioLimitBytes = entry.compressedBytes > 0
    ? Math.floor(entry.compressedBytes * limits.maxCompressionRatio)
    : 0;
  const aggregateRemaining = Math.max(0, limits.maxArchiveUncompressedBytes - state.actualArchiveBytes);
  const maxOutputBytes = Math.min(limits.maxEntryUncompressedBytes, aggregateRemaining, ratioLimitBytes);

  return {
    maxOutputBytes,
    expectedBytes: entry.uncompressedBytes,
    compressedBytes: entry.compressedBytes,
    accountOutputBytes(byteLength) {
      if (!Number.isSafeInteger(byteLength) || byteLength < 0) {
        throw new ZipSafetyError("malformed", "ZIP decompressor reported an invalid output length.", entry.path);
      }
      if (byteLength === 0) return;
      actualEntryBytes += byteLength;
      state.actualArchiveBytes += byteLength;
      if (actualEntryBytes > limits.maxEntryUncompressedBytes) {
        throw new ZipSafetyError("policy-limit", `ZIP entry actual output exceeds ${limits.maxEntryUncompressedBytes} bytes.`, entry.path);
      }
      if (state.actualArchiveBytes > limits.maxArchiveUncompressedBytes) {
        throw new ZipSafetyError("policy-limit", `ZIP aggregate actual output exceeds ${limits.maxArchiveUncompressedBytes} bytes.`, entry.path);
      }
      if (entry.compressedBytes > 0 && actualEntryBytes / entry.compressedBytes > limits.maxCompressionRatio) {
        throw new ZipSafetyError("policy-limit", `ZIP entry actual compression ratio exceeds ${limits.maxCompressionRatio}:1.`, entry.path);
      }
    },
    get accountedBytes() {
      return actualEntryBytes;
    },
  };
}

/**
 * @param {ZipReadContext} context
 * @param {unknown} output
 */
function accountReturnedOutput(context, output) {
  if (!(output instanceof Uint8Array)) {
    throw new ZipSafetyError("malformed", "ZIP decompressor did not return bytes.");
  }
  if (context.accountedBytes === 0 && output.byteLength > 0) {
    context.accountOutputBytes(output.byteLength);
    return;
  }
  if (context.accountedBytes !== output.byteLength) {
    throw new ZipSafetyError("malformed", "ZIP decompressor output accounting mismatch.");
  }
}

/**
 * @param {unknown} error
 * @returns {boolean}
 */
function isBoundedOutputError(error) {
  return Boolean(
    error
      && typeof error === "object"
      && "code" in error
      && error.code === "ERR_BUFFER_TOO_LARGE",
  );
}

/**
 * @param {ZipEntry} entry
 * @param {Uint8Array} output
 * @returns {Uint8Array}
 */
function verifyZipEntryOutput(entry, output) {
  if (output.byteLength !== entry.uncompressedBytes) {
    throw new ZipSafetyError("malformed", "ZIP entry decompressed length does not match the central directory.", entry.path);
  }
  if (crc32(output) !== entry.crc32) {
    throw new ZipSafetyError("malformed", "ZIP entry CRC32 does not match the central directory.", entry.path);
  }
  return output;
}

/**
 * @param {number} value
 * @returns {string}
 */
export function zipCompressionLabel(value) {
  if (value === 0) return "stored";
  if (value === 8) return "deflate";
  return `method-${value}`;
}

/**
 * @param {Uint8Array} bytes
 * @returns {number}
 */
export function crc32(bytes) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc = CRC32_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * @param {Uint8Array} bytes
 * @returns {ZipEocd}
 */
function readEocd(bytes) {
  if (bytes.byteLength < 22) {
    throw new ZipSafetyError("malformed", "ZIP end-of-central-directory record is truncated.");
  }
  const minOffset = Math.max(0, bytes.byteLength - 65_557);
  for (let offset = bytes.byteLength - 22; offset >= minOffset; offset -= 1) {
    if (readUInt32(bytes, offset, "ZIP end-of-central-directory signature") !== EOCD_SIGNATURE) {
      continue;
    }
    const commentLength = readUInt16(bytes, offset + 20, "ZIP end-of-central-directory comment length");
    if (offset + 22 + commentLength !== bytes.byteLength) {
      continue;
    }
    const diskNumber = readUInt16(bytes, offset + 4, "ZIP disk number");
    const centralDirectoryDisk = readUInt16(bytes, offset + 6, "ZIP central directory disk");
    const entriesOnDisk = readUInt16(bytes, offset + 8, "ZIP entries on disk");
    const totalEntries = readUInt16(bytes, offset + 10, "ZIP entry count");
    const centralDirectoryBytes = readUInt32(bytes, offset + 12, "ZIP central directory size");
    const centralDirectoryOffset = readUInt32(bytes, offset + 16, "ZIP central directory offset");
    if (diskNumber !== 0 || centralDirectoryDisk !== 0 || entriesOnDisk !== totalEntries) {
      throw new ZipSafetyError("unsupported", "Multi-disk ZIP archives are not supported.");
    }
    if (
      entriesOnDisk === ZIP64_16 ||
      totalEntries === ZIP64_16 ||
      centralDirectoryBytes === ZIP64_32 ||
      centralDirectoryOffset === ZIP64_32 ||
      hasZip64Locator(bytes, offset)
    ) {
      throw new ZipSafetyError("unsupported", "Zip64 archives are not supported in this safety policy.");
    }
    if (totalEntries === 0) {
      return {
        eocdOffset: offset,
        totalEntries,
        centralDirectoryBytes,
        centralDirectoryOffset,
      };
    }
    ensureRange(bytes, centralDirectoryOffset, centralDirectoryBytes, "ZIP central directory");
    if (centralDirectoryOffset + centralDirectoryBytes > offset) {
      throw new ZipSafetyError("malformed", "ZIP central directory extends outside the archive.");
    }
    return {
      eocdOffset: offset,
      totalEntries,
      centralDirectoryBytes,
      centralDirectoryOffset,
    };
  }
  throw new ZipSafetyError("malformed", "ZIP end-of-central-directory record not found.");
}

/**
 * @param {Uint8Array} bytes
 * @param {number} eocdOffset
 * @returns {boolean}
 */
function hasZip64Locator(bytes, eocdOffset) {
  return eocdOffset >= 20 && readUInt32(bytes, eocdOffset - 20, "Zip64 locator probe") === ZIP64_EOCD_LOCATOR_SIGNATURE;
}

/**
 * @param {Uint8Array} bytes
 * @param {ZipEocd} eocd
 * @param {ZipSafetyLimits} limits
 * @returns {ZipEntry[]}
 */
function readCentralDirectory(bytes, eocd, limits) {
  if (eocd.totalEntries > limits.maxEntries) {
    throw new ZipSafetyError("policy-limit", `ZIP entry count exceeds ${limits.maxEntries}.`);
  }

  /** @type {ZipEntry[]} */
  const entries = [];
  let offset = eocd.centralDirectoryOffset;
  for (let index = 0; index < eocd.totalEntries; index += 1) {
    ensureRange(bytes, offset, 46, "ZIP central directory header");
    if (readUInt32(bytes, offset, "ZIP central directory signature") !== CENTRAL_DIRECTORY_SIGNATURE) {
      throw new ZipSafetyError("malformed", "ZIP central directory is malformed.");
    }

    const versionMadeBy = readUInt16(bytes, offset + 4, "ZIP version made by");
    const versionNeeded = readUInt16(bytes, offset + 6, "ZIP version needed");
    const flags = readUInt16(bytes, offset + 8, "ZIP general purpose bit flag");
    const compressionMethod = readUInt16(bytes, offset + 10, "ZIP compression method");
    const crc = readUInt32(bytes, offset + 16, "ZIP CRC32");
    const compressedBytes = readUInt32(bytes, offset + 20, "ZIP compressed size");
    const uncompressedBytes = readUInt32(bytes, offset + 24, "ZIP uncompressed size");
    const nameLength = readUInt16(bytes, offset + 28, "ZIP file name length");
    const extraLength = readUInt16(bytes, offset + 30, "ZIP extra field length");
    const commentLength = readUInt16(bytes, offset + 32, "ZIP file comment length");
    const externalAttributes = readUInt32(bytes, offset + 38, "ZIP external attributes");
    const localHeaderOffset = readUInt32(bytes, offset + 42, "ZIP local header offset");
    const headerBytes = 46 + nameLength + extraLength + commentLength;
    ensureRange(bytes, offset, headerBytes, "ZIP central directory entry");

    const rawName = bytes.subarray(offset + 46, offset + 46 + nameLength);
    const path = decodeZipName(rawName, flags);
    /** @type {ZipEntry} */
    const entry = {
      path,
      normalizedPath: normalizeEntryPathForPolicy(path),
      rawName: Uint8Array.from(rawName),
      directory: path.endsWith("/"),
      compressionMethod,
      compressedBytes,
      uncompressedBytes,
      crc32: crc,
      localHeaderOffset,
      dataOffset: 0,
      flags,
      encrypted: Boolean(flags & ENCRYPTED_FLAG),
      externalAttributes,
      unixMode: isUnixLikeHost(versionMadeBy >>> 8) ? (externalAttributes >>> 16) & 0xffff : null,
      problem: null,
    };

    if (nameLength === 0 || rawName.includes(0)) {
      markProblem(entry, "rejected", "ZIP entry names must be non-empty and must not contain NUL bytes.");
    }
    if (nameLength > limits.maxNameBytes) {
      markProblem(entry, "policy-limit", `ZIP entry name exceeds ${limits.maxNameBytes} bytes.`);
    }
    if (versionNeeded >= 45 || compressedBytes === ZIP64_32 || uncompressedBytes === ZIP64_32 || localHeaderOffset === ZIP64_32) {
      markProblem(entry, "unsupported", "Zip64 entry structures are not supported in this safety policy.");
    }
    if (flags & (STRONG_ENCRYPTION_FLAG | PATCHED_DATA_FLAG)) {
      markProblem(entry, "unsupported", "Unsupported ZIP general-purpose flag is set.");
    }
    if (entry.encrypted) {
      markProblem(entry, "unsupported", "Encrypted ZIP entries are rejected by this safety policy.");
    }
    if (compressionMethod !== 0 && compressionMethod !== 8) {
      markProblem(entry, "unsupported", `Unsupported ZIP compression method ${compressionMethod}.`);
    }
    markUnixModeProblems(entry);
    markSizePolicyProblems(entry, limits);
    validateLocalHeader(bytes, entry, eocd);

    entries.push(entry);
    offset += headerBytes;
  }

  if (offset !== eocd.centralDirectoryOffset + eocd.centralDirectoryBytes) {
    throw new ZipSafetyError("malformed", "ZIP central directory size does not match parsed entries.");
  }
  validateEntryRanges(entries);
  return entries;
}

/**
 * @param {Uint8Array} bytes
 * @param {ZipEntry} entry
 * @param {ZipEocd} eocd
 */
function validateLocalHeader(bytes, entry, eocd) {
  try {
    ensureRange(bytes, entry.localHeaderOffset, 30, `Local ZIP header for ${entry.path}`);
    if (readUInt32(bytes, entry.localHeaderOffset, `Local ZIP header for ${entry.path}`) !== LOCAL_FILE_HEADER_SIGNATURE) {
      markProblem(entry, "malformed", "Local ZIP header signature does not match the central directory.");
      return;
    }
    const localFlags = readUInt16(bytes, entry.localHeaderOffset + 6, `Local ZIP flags for ${entry.path}`);
    const localMethod = readUInt16(bytes, entry.localHeaderOffset + 8, `Local ZIP method for ${entry.path}`);
    const localNameLength = readUInt16(bytes, entry.localHeaderOffset + 26, `Local ZIP name length for ${entry.path}`);
    const localExtraLength = readUInt16(bytes, entry.localHeaderOffset + 28, `Local ZIP extra length for ${entry.path}`);
    const localHeaderBytes = 30 + localNameLength + localExtraLength;
    ensureRange(bytes, entry.localHeaderOffset, localHeaderBytes, `Local ZIP header for ${entry.path}`);
    const localName = bytes.subarray(entry.localHeaderOffset + 30, entry.localHeaderOffset + 30 + localNameLength);
    if (!sameBytes(localName, entry.rawName)) {
      markProblem(entry, "malformed", "Local ZIP filename does not match the central directory.");
    }
    if (localMethod !== entry.compressionMethod || localFlags !== entry.flags) {
      markProblem(entry, "malformed", "Local ZIP method or flags do not match the central directory.");
    }
    entry.dataOffset = entry.localHeaderOffset + localHeaderBytes;
    ensureRange(bytes, entry.dataOffset, entry.compressedBytes, `Compressed data for ${entry.path}`);
    if (entry.dataOffset + entry.compressedBytes > eocd.centralDirectoryOffset) {
      markProblem(entry, "malformed", "ZIP entry compressed data extends into the central directory.");
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    markProblem(entry, "malformed", message);
  }
}

/**
 * @param {ZipEntry} entry
 */
function markUnixModeProblems(entry) {
  const unixMode = entry.unixMode;
  if (unixMode == null || unixMode === 0) {
    return;
  }
  const fileType = unixMode & UNIX_FILE_TYPE_MASK;
  if (fileType === 0) {
    return;
  }
  if (fileType === UNIX_SYMLINK) {
    markProblem(entry, "rejected", "ZIP symbolic link entries are rejected.");
    return;
  }
  if (fileType === UNIX_DIRECTORY) {
    if (!entry.directory && entry.uncompressedBytes !== 0) {
      markProblem(entry, "malformed", "ZIP directory mode disagrees with file data.");
    }
    entry.directory = true;
    return;
  }
  if (fileType !== UNIX_REGULAR_FILE) {
    markProblem(entry, "rejected", "ZIP special file entries are rejected.");
    return;
  }
  if (entry.directory) {
    markProblem(entry, "malformed", "ZIP regular-file mode disagrees with directory path.");
  }
}

/**
 * @param {ZipEntry} entry
 * @param {ZipSafetyLimits} limits
 */
function markSizePolicyProblems(entry, limits) {
  if (entry.uncompressedBytes > limits.maxEntryUncompressedBytes) {
    markProblem(entry, "policy-limit", `ZIP entry exceeds ${limits.maxEntryUncompressedBytes} uncompressed bytes.`);
  }
  if (entry.directory && (entry.compressedBytes !== 0 || entry.uncompressedBytes !== 0)) {
    markProblem(entry, "malformed", "ZIP directory entries must not contain file data.");
  }
  if (entry.compressionMethod === 0 && entry.compressedBytes !== entry.uncompressedBytes) {
    markProblem(entry, "malformed", "Stored ZIP entry compressed and uncompressed sizes differ.");
  }
  if (entry.uncompressedBytes > 0 && entry.compressedBytes === 0) {
    markProblem(entry, "malformed", "ZIP entry declares uncompressed data without compressed bytes.");
  }
  if (
    entry.compressedBytes > 0 &&
    entry.uncompressedBytes / entry.compressedBytes > limits.maxCompressionRatio
  ) {
    markProblem(entry, "policy-limit", `ZIP entry compression ratio exceeds ${limits.maxCompressionRatio}:1.`);
  }
}

/**
 * @param {ZipEntry[]} entries
 */
function markPathPolicyProblems(entries) {
  /** @type {Map<string, ZipEntry>} */
  const exact = new Map();
  /** @type {Map<string, string>} */
  const conservative = new Map();
  const root = createPathTrieNode();

  for (const entry of entries) {
    const pathProblem = validateSafeRelativePath(entry.path);
    if (pathProblem) {
      markProblem(entry, "rejected", pathProblem);
      continue;
    }
    const normalized = normalizeEntryPathForPolicy(entry.path);
    entry.normalizedPath = normalized;
    const exactOwner = exact.get(normalized);
    if (exactOwner) {
      if (exactOwner.directory !== entry.directory) {
        markProblem(entry, "rejected", `ZIP file/directory path conflicts with ${exactOwner.path}.`);
      } else {
        markProblem(entry, "rejected", `Duplicate ZIP path collides with ${exactOwner.path}.`);
      }
    } else {
      exact.set(normalized, entry);
    }

    const conservativeKey = normalized.normalize("NFC").toLocaleLowerCase("en-US");
    const conservativeOwner = conservative.get(conservativeKey);
    if (conservativeOwner && conservativeOwner !== normalized) {
      markProblem(entry, "rejected", `ZIP path case-folding/Unicode-normalization collision with ${conservativeOwner}.`);
    } else {
      conservative.set(conservativeKey, normalized);
    }

    markPathTrieProblems(root, entry, normalized);
  }
}

/**
 * @returns {PathTrieNode}
 */
function createPathTrieNode() {
  return {
    children: new Map(),
    terminalEntry: null,
  };
}

/**
 * @param {PathTrieNode} root
 * @param {ZipEntry} entry
 * @param {string} normalized
 */
function markPathTrieProblems(root, entry, normalized) {
  const parts = normalized.split("/");
  let node = root;
  /** @type {string[]} */
  const traversed = [];
  for (const part of parts) {
    if (node.terminalEntry && !node.terminalEntry.directory) {
      markProblem(entry, "rejected", `ZIP path conflicts with file entry ${traversed.join("/")}.`);
      return;
    }
    traversed.push(part);
    let child = node.children.get(part);
    if (!child) {
      child = createPathTrieNode();
      node.children.set(part, child);
    }
    node = child;
  }

  if (node.terminalEntry) {
    markProblem(entry, "rejected", `Duplicate ZIP path collides with ${node.terminalEntry.path}.`);
    return;
  }
  if (!entry.directory && node.children.size > 0) {
    markProblem(entry, "rejected", `ZIP file path conflicts with child entries under ${normalized}.`);
    return;
  }
  node.terminalEntry = entry;
}

/**
 * @param {ZipEntry[]} entries
 * @param {ZipSafetyLimits} limits
 */
function markAggregateLimitProblems(entries, limits) {
  let total = 0;
  for (const entry of entries) {
    if (entry.directory) continue;
    total += entry.uncompressedBytes;
    if (total > limits.maxArchiveUncompressedBytes) {
      markProblem(entry, "policy-limit", `ZIP aggregate uncompressed size exceeds ${limits.maxArchiveUncompressedBytes} bytes.`);
      return;
    }
  }
}

/**
 * @param {ZipEntry[]} entries
 */
function validateEntryRanges(entries) {
  const ranges = entries
    .map((entry) => ({
      path: entry.path,
      start: entry.localHeaderOffset,
      end: entry.dataOffset + entry.compressedBytes,
      entry,
    }))
    .sort((a, b) => a.start - b.start);
  for (let index = 1; index < ranges.length; index += 1) {
    const previous = ranges[index - 1];
    const current = ranges[index];
    if (current.start < previous.end) {
      markProblem(current.entry, "malformed", `ZIP entry data overlaps with ${previous.path}.`);
    }
  }
}

/**
 * @param {string} value
 * @returns {string | null}
 */
export function validateSafeRelativePath(value) {
  if (!value) return "ZIP entry path is empty.";
  if (value.includes("\0")) return "ZIP entry path contains a NUL byte.";
  if (value.includes("\\")) return "ZIP entry path contains backslashes.";
  if (value.startsWith("//")) return "ZIP entry path is a UNC path.";
  if (value.startsWith("/")) return "ZIP entry path is absolute.";
  if (/^[A-Za-z]:/.test(value)) return "ZIP entry path contains a Windows drive letter.";

  const segments = value.split("/");
  const lastIndex = segments.length - 1;
  for (let index = 0; index < segments.length; index += 1) {
    const segment = segments[index];
    if (segment === "" && index !== lastIndex) return "ZIP entry path contains empty segments.";
    if (segment === "." || segment === "..") return "ZIP entry path contains traversal segments.";
    if (segment.includes(":")) return "ZIP entry path contains a Windows-unsafe colon.";
    if (/[<>"|?*\u0001-\u001f]/u.test(segment)) return "ZIP entry path component contains Windows-forbidden characters.";
    if (/[. ]$/u.test(segment)) return "ZIP entry path component ends with a Windows-unsafe dot or space.";
    const deviceName = segment.split(".")[0].toLocaleUpperCase("en-US");
    if (WINDOWS_RESERVED_NAMES.has(deviceName)) {
      return `ZIP entry path contains reserved Windows device name ${deviceName}.`;
    }
  }
  return null;
}

/**
 * @param {string} value
 * @returns {string}
 */
export function normalizeEntryPathForPolicy(value) {
  return value.endsWith("/") ? value.slice(0, -1) : value;
}

/**
 * @param {number} hostSystem
 * @returns {boolean}
 */
function isUnixLikeHost(hostSystem) {
  return hostSystem === UNIX_SYSTEM_ID || hostSystem === MACOS_SYSTEM_ID;
}

/**
 * @param {Uint8Array} rawName
 * @param {number} flags
 * @returns {string}
 */
function decodeZipName(rawName, flags) {
  if (rawName.byteLength === 0) {
    return "";
  }
  try {
    const decoder = new globalThis.TextDecoder("utf-8", { fatal: true });
    return decoder.decode(rawName);
  } catch {
    if (flags & UTF8_FLAG) {
      throw new ZipSafetyError("malformed", "ZIP entry name is not valid UTF-8.");
    }
    throw new ZipSafetyError("unsupported", "ZIP entry names must be UTF-8.");
  }
}

/**
 * @param {ZipEntry} entry
 * @param {ZipProblemCategory} category
 * @param {string} detail
 */
function markProblem(entry, category, detail) {
  if (entry.problem) return;
  entry.problem = {
    category,
    status: categoryToStatus(category),
    detail,
  };
}

/**
 * @param {ZipProblemCategory} category
 * @returns {ZipProblemCategory}
 */
function categoryToStatus(category) {
  if (category === "rejected") return "rejected";
  if (category === "policy-limit") return "policy-limit";
  if (category === "malformed") return "malformed";
  return "unsupported";
}

/**
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @param {number} length
 * @param {string} label
 */
function ensureRange(bytes, offset, length, label) {
  if (!Number.isSafeInteger(offset) || !Number.isSafeInteger(length) || offset < 0 || length < 0 || offset + length > bytes.byteLength) {
    throw new ZipSafetyError("malformed", `${label} is truncated or outside the archive.`);
  }
}

/**
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @param {string} label
 * @returns {number}
 */
function readUInt16(bytes, offset, label) {
  ensureRange(bytes, offset, 2, label);
  return bytes[offset] | (bytes[offset + 1] << 8);
}

/**
 * @param {Uint8Array} bytes
 * @param {number} offset
 * @param {string} label
 * @returns {number}
 */
function readUInt32(bytes, offset, label) {
  ensureRange(bytes, offset, 4, label);
  return (
    bytes[offset] |
    (bytes[offset + 1] << 8) |
    (bytes[offset + 2] << 16) |
    (bytes[offset + 3] << 24)
  ) >>> 0;
}

/**
 * @param {Uint8Array} left
 * @param {Uint8Array} right
 * @returns {boolean}
 */
function sameBytes(left, right) {
  if (left.byteLength !== right.byteLength) return false;
  for (let index = 0; index < left.byteLength; index += 1) {
    if (left[index] !== right[index]) return false;
  }
  return true;
}

const CRC32_TABLE = Array.from({ length: 256 }, (_unused, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return value >>> 0;
});
