import zlib from "node:zlib";

export type ZipFixtureEntry = {
  path: string;
  content?: Uint8Array;
  compressionMethod?: number;
  compression?: "stored" | "deflate";
  flags?: number;
  localFlags?: number;
  localPath?: string;
  localCompressionMethod?: number;
  mode?: number;
  versionMadeBy?: number;
  versionNeeded?: number;
  crc32Override?: number;
  compressedSizeOverride?: number;
  uncompressedSizeOverride?: number;
};

export function createStoredZip(entries: Array<{ path: string; content: Uint8Array; mode?: number }>) {
  return createZip(entries.map((entry) => ({ ...entry, compression: "stored" as const })));
}

export function createZip(entries: ZipFixtureEntry[]) {
  const localParts: Uint8Array[] = [];
  const centralParts: Uint8Array[] = [];
  let offset = 0;

  entries.forEach((entry) => {
    const content = entry.content ?? new Uint8Array();
    const method = entry.compressionMethod ?? (entry.compression === "deflate" ? 8 : 0);
    const localMethod = entry.localCompressionMethod ?? method;
    const payload = method === 8 ? zlib.deflateRawSync(Buffer.from(content)) : Buffer.from(content);
    const name = Buffer.from(entry.path, "utf8");
    const localName = Buffer.from(entry.localPath ?? entry.path, "utf8");
    const flags = entry.flags ?? 0;
    const localFlags = entry.localFlags ?? flags;
    const crc = entry.crc32Override ?? crc32(content);
    const compressedSize = entry.compressedSizeOverride ?? payload.length;
    const uncompressedSize = entry.uncompressedSizeOverride ?? content.length;

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(entry.versionNeeded ?? 20, 4);
    local.writeUInt16LE(localFlags, 6);
    local.writeUInt16LE(localMethod, 8);
    local.writeUInt32LE(0, 10);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressedSize, 18);
    local.writeUInt32LE(uncompressedSize, 22);
    local.writeUInt16LE(localName.length, 26);
    local.writeUInt16LE(0, 28);
    localParts.push(local, localName, payload);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(entry.versionMadeBy ?? 0x0314, 4);
    central.writeUInt16LE(entry.versionNeeded ?? 20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(0, 12);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressedSize, 20);
    central.writeUInt32LE(uncompressedSize, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(((entry.mode ?? 0o100644) << 16) >>> 0, 38);
    central.writeUInt32LE(offset, 42);
    centralParts.push(central, name);

    offset += local.length + localName.length + payload.length;
  });

  const centralDirectory = concatBytes(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDirectory.length, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);
  return concatBytes([...localParts, centralDirectory, eocd]);
}

export function createMinimalOfficeZip(coreXml: string | Uint8Array, mode?: number) {
  const schemaOrigin = `${"http"}://schemas.openxmlformats.org`;
  const contentTypes = Buffer.from(
    `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="${schemaOrigin}/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>`,
    "utf8",
  );
  const appXml = Buffer.from(
    `<?xml version="1.0" encoding="UTF-8"?><Properties xmlns="${schemaOrigin}/officeDocument/2006/extended-properties"><Application>Fixture</Application></Properties>`,
    "utf8",
  );
  const coreBytes = typeof coreXml === "string" ? Buffer.from(coreXml, "utf8") : coreXml;
  return createStoredZip([
    { path: "[Content_Types].xml", content: contentTypes },
    { path: "docProps/core.xml", content: coreBytes, mode },
    { path: "docProps/app.xml", content: appXml },
  ]);
}

function crc32(bytes: Uint8Array) {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc = CRC32_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function concatBytes(parts: Uint8Array[]) {
  const total = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  parts.forEach((part) => {
    out.set(part, offset);
    offset += part.length;
  });
  return out;
}

const CRC32_TABLE = Array.from({ length: 256 }, (_unused, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit += 1) {
    value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  }
  return value >>> 0;
});
