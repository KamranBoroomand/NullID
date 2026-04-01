import { type OutputMime } from "./imageFormats.js";
import { sanitizePdfMetadata, type MetadataAnalysisResult } from "./metadataAdvanced.js";
import { sanitizeBrowserImage } from "./metadataCleaning.js";

export interface LocalMetadataCleanupResult {
  cleanedBytes?: Uint8Array;
  cleanedMediaType?: string;
  cleanedLabel?: string;
  cleanActions: string[];
  message: string;
}

export async function prepareLocalMetadataCleanup(
  file: File,
  analysis: MetadataAnalysisResult,
  options: {
    applyMetadataClean: boolean;
    outputSupport: Record<OutputMime, boolean> | null;
  },
): Promise<LocalMetadataCleanupResult> {
  if (!options.applyMetadataClean) {
    return {
      cleanActions: [],
      message: `analysis ready (${analysis.risk} risk)`,
    };
  }

  if (analysis.recommendedSanitizer === "browser-image" && options.outputSupport) {
    const cleaned = await sanitizeBrowserImage(file, {
      scale: 1,
      outputSupport: options.outputSupport,
      outputChoice: "auto",
      quality: 0.92,
    });
    return {
      cleanedBytes: new Uint8Array(await cleaned.cleanedBlob.arrayBuffer()),
      cleanedMediaType: cleaned.outputMime,
      cleanedLabel: "Metadata-cleaned file",
      cleanActions: cleaned.removed.length > 0 ? cleaned.removed : ["image re-encode completed"],
      message: "analysis ready with local image cleanup",
    };
  }

  if (analysis.recommendedSanitizer === "browser-pdf") {
    const cleaned = await sanitizePdfMetadata(file);
    return {
      cleanedBytes: new Uint8Array(await cleaned.cleanedBlob.arrayBuffer()),
      cleanedMediaType: "application/pdf",
      cleanedLabel: "Metadata-cleaned PDF",
      cleanActions: cleaned.actions.length > 0 ? cleaned.actions : ["no visible PDF metadata rewrites were required"],
      message: cleaned.changed ? "analysis ready with local PDF cleanup" : "analysis ready; no PDF rewrites were required",
    };
  }

  return {
    cleanActions: [],
    message: analysis.commandHint
      ? `analysis ready (${analysis.risk} risk); external offline cleanup is still recommended`
      : `analysis ready (${analysis.risk} risk)`,
  };
}
