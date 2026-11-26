/**
 * Random-access binary source backed by a File/Blob (browser) or FileHandle (Node.js).
 */
export interface RandomAccessSource {
  /** Total byte length of the source. */
  readonly size: number;
  /** Reads exact byte slice [start, end). */
  readRange(start: number, end: number): Promise<Uint8Array<ArrayBuffer>>;
  /** Optional zero-copy Blob slice when backed by a Blob/File. */
  sliceBlob?(start: number, end: number): Blob;
  /** Streams byte range [start, end) without buffering the full range in memory. */
  streamRange(start: number, end: number): ReadableStream<Uint8Array<ArrayBuffer>>;
}

/**
 * Output destination for writing ZIP archives sequentially.
 */
export interface ZipOutputSink {
  /** Writes a byte buffer sequentially to the output. */
  writeBytes(data: Uint8Array<ArrayBuffer>): Promise<void>;
  /** Copies an untouched raw byte range [start, end) directly from the source. */
  copySourceRange(source: RandomAccessSource, start: number, end: number): Promise<void>;
}

/**
 * Metadata extracted from a single Mach-O architecture slice.
 */
export interface MachOSliceInfo {
  sliceOffset: number;
  cputype: number;
  littleEndian: boolean;
  stroff: number;
  strsize: number;
  sigDataoff: number;
  end: number;
  gap: number;
}

/**
 * Describes a required 4-byte LC_SYMTAB.strsize patch for a Mach-O slice.
 */
export interface MachOPatch {
  sliceOffset: number;
  cputype: number;
  littleEndian: boolean;
  oldStrsize: number;
  newStrsize: number;
  oldEnd: number;
  newEnd: number;
  gap: number;
  strsizeFileOffset: number;
}

/**
 * User-facing detail for a single patched offset in an IPA entry.
 */
export interface PatchDetail {
  file: string;
  offset: number;
  oldVal: number;
  newVal: number;
  gap: number;
  sliceOffset: number;
}

/**
 * Aggregate scan and repair statistics returned by fixIpa / fixIpaBlob / fixIpaFile.
 */
export interface ScanStats {
  binariesScanned: number;
  binariesAffected: number;
  offsetsFound: number;
  extensionKitFoldersRemoved: number;
  plugInsFoldersRemoved: number;
  entriesRemoved: number;
  signaturesCleaned: number;
  totalEntriesIn: number;
  totalEntriesOut: number;
  elapsedMs: number;
  details: PatchDetail[];
}

/**
 * Progress events emitted while scanning and repackaging an IPA.
 */
export type ProgressEvent =
  | {
      type: "stage";
      stage: "reading-index" | "scanning" | "writing" | "done";
      message: string;
    }
  | {
      type: "inspect";
      file: string;
      slices: MachOSliceInfo[];
    }
  | {
      type: "patch";
      detail: PatchDetail;
      dryRun: boolean;
    }
  | {
      type: "remove";
      category: "signature" | "extensionkit" | "plugins";
      path: string;
      dryRun: boolean;
    }
  | {
      type: "progress";
      completed: number;
      total: number;
      currentFile: string;
    };

/**
 * Configuration options for inspecting or patching an IPA.
 */
export interface FixIpaOptions {
  /** Remove Payload/*.app/Extensions/ (ExtensionKit). Fixes SideStore IXErrorDomain Code=8 while keeping PlugIns/. */
  stripExtensionKit?: boolean;
  /** Remove Payload/*.app/PlugIns/ (legacy NSExtension app extensions). */
  stripPlugIns?: boolean;
  /** Remove both Extensions/ and PlugIns/. */
  stripExtensions?: boolean;
  /** Remove _CodeSignature/ folders (defaults to true). */
  cleanSignatures?: boolean;
  /** Analyze without writing an output archive. */
  dryRun?: boolean;
  /** Inspect all ZIP entries instead of skipping known asset extensions. */
  scanAllFiles?: boolean;
  /** Emit per-binary inspect progress events even when no patch is needed. */
  verbose?: boolean;
  /** Callback invoked with progress updates. */
  onProgress?: (event: ProgressEvent) => void;
  /** Optional abort signal to cancel long operations. */
  signal?: AbortSignal;
}

/**
 * Result returned by fixIpaBlob in browser/isomorphic contexts.
 */
export interface FixIpaBlobResult {
  stats: ScanStats;
  blob: Blob | null;
}
