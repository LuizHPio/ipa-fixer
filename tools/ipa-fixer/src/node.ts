import { once } from "node:events";
import * as fs from "node:fs";
import * as path from "node:path";
import { fixIpa } from "./fixer.js";
import type {
  FixIpaOptions,
  RandomAccessSource,
  ScanStats,
  ZipOutputSink,
} from "./types.js";

/**
 * Opens a local file with random-access range reads and Web Streams support.
 */
export async function openFileSource(filePath: string): Promise<{
  source: RandomAccessSource;
  close: () => Promise<void>;
}> {
  const fh = await fs.promises.open(filePath, "r");
  try {
    const stat = await fh.stat();
    const totalSize = stat.size;
    let closed = false;

    const readRange = async (start: number, end: number): Promise<Uint8Array<ArrayBuffer>> => {
      if (start < 0 || end < start || end > totalSize) {
        throw new RangeError(`Invalid readRange [${start}, ${end}) for file size ${totalSize}`);
      }
      const len = end - start;
      const buf = new Uint8Array(len);
      let offset = 0;
      while (offset < len) {
        const { bytesRead } = await fh.read(buf, offset, len - offset, start + offset);
        if (bytesRead === 0) {
          throw new Error(`Unexpected EOF reading range [${start}, ${end}) from ${filePath}`);
        }
        offset += bytesRead;
      }
      return buf;
    };

    const streamRange = (start: number, end: number): ReadableStream<Uint8Array<ArrayBuffer>> => {
      if (start < 0 || end < start || end > totalSize) {
        throw new RangeError(`Invalid streamRange [${start}, ${end}) for file size ${totalSize}`);
      }
      const CHUNK_SIZE = 256 * 1024;
      let cursor = start;
      let cancelled = false;

      return new ReadableStream<Uint8Array<ArrayBuffer>>({
        async pull(controller) {
          if (cancelled || closed || cursor >= end) {
            controller.close();
            return;
          }
          const toRead = Math.min(CHUNK_SIZE, end - cursor);
          const buf = new Uint8Array(toRead);
          let filled = 0;
          while (filled < toRead) {
            if (cancelled || closed) {
              controller.close();
              return;
            }
            const { bytesRead } = await fh.read(buf, filled, toRead - filled, cursor + filled);
            if (bytesRead === 0) {
              break;
            }
            filled += bytesRead;
          }
          if (filled === 0) {
            controller.close();
            return;
          }
          cursor += filled;
          controller.enqueue(filled === toRead ? buf : buf.subarray(0, filled));
          if (cursor >= end) {
            controller.close();
          }
        },
        cancel() {
          cancelled = true;
        },
      });
    };

    return {
      source: {
        size: totalSize,
        readRange,
        streamRange,
      },
      close: async () => {
        if (!closed) {
          closed = true;
          await fh.close();
        }
      },
    };
  } catch (err) {
    await fh.close().catch(() => {});
    throw err;
  }
}

/**
 * Streaming file output sink writing to an atomic temp file before renaming on commit.
 */
export class FileZipSink implements ZipOutputSink {
  private readonly outputPath: string;
  private readonly tempPath: string;
  private readonly stream: fs.WriteStream;
  private streamError: Error | null = null;
  private closed = false;

  constructor(outputPath: string) {
    this.outputPath = path.resolve(outputPath);
    fs.mkdirSync(path.dirname(this.outputPath), { recursive: true });
    this.tempPath = `${this.outputPath}.tmp-${process.pid}-${Date.now()}`;
    this.stream = fs.createWriteStream(this.tempPath);
    this.stream.on("error", (err) => {
      this.streamError = err;
    });
  }

  async writeBytes(data: Uint8Array<ArrayBuffer>): Promise<void> {
    if (this.streamError !== null) {
      throw this.streamError;
    }
    if (data.length === 0) {
      return;
    }
    const ok = this.stream.write(data);
    if (!ok) {
      await once(this.stream, "drain");
      if (this.streamError !== null) {
        throw this.streamError;
      }
    }
  }

  async copySourceRange(
    source: RandomAccessSource,
    start: number,
    end: number
  ): Promise<void> {
    const CHUNK_SIZE = 1024 * 1024;
    for (let pos = start; pos < end; pos += CHUNK_SIZE) {
      const chunkEnd = Math.min(end, pos + CHUNK_SIZE);
      const chunk = await source.readRange(pos, chunkEnd);
      await this.writeBytes(chunk);
    }
  }

  async commit(): Promise<void> {
    if (this.closed) {
      return;
    }
    this.closed = true;
    await new Promise<void>((resolve, reject) => {
      if (this.streamError !== null) {
        reject(this.streamError);
        return;
      }
      this.stream.once("error", reject);
      this.stream.once("finish", resolve);
      this.stream.end();
    });
    await fs.promises.rename(this.tempPath, this.outputPath);
  }

  async abort(): Promise<void> {
    if (!this.closed) {
      this.closed = true;
      this.stream.destroy();
    }
    await fs.promises.unlink(this.tempPath).catch(() => {});
  }
}

/**
 * Inspects and optionally repairs + repackages a local .ipa file on desktop via Node.js.
 */
export async function fixIpaFile(
  inputPath: string,
  outputPath: string | null,
  options: FixIpaOptions = {}
): Promise<ScanStats> {
  const dryRun = Boolean(options.dryRun || outputPath === null);
  const { source, close } = await openFileSource(inputPath);
  const sink = !dryRun && outputPath !== null ? new FileZipSink(outputPath) : null;

  try {
    const stats = await fixIpa(source, sink, { ...options, dryRun });
    if (sink !== null) {
      await sink.commit();
    }
    return stats;
  } catch (err) {
    if (sink !== null) {
      await sink.abort();
    }
    throw err;
  } finally {
    await close();
  }
}
