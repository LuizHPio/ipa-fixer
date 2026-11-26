import { fixIpaBlob } from "../src/index.js";
import type { ProgressEvent, ScanStats } from "../src/types.js";

interface StartMessage {
  type: "start";
  file: File;
  options: {
    stripExtensionKit: boolean;
    stripPlugIns: boolean;
    cleanSignatures: boolean;
    dryRun: boolean;
    verbose: boolean;
  };
}

interface CancelMessage {
  type: "cancel";
}

type InboundMessage = StartMessage | CancelMessage;

type OutboundMessage =
  | { type: "progress"; event: ProgressEvent }
  | { type: "done"; stats: ScanStats; blob: Blob | null }
  | { type: "error"; message: string; aborted: boolean };

interface WorkerSelf {
  onmessage: ((ev: MessageEvent<InboundMessage>) => void) | null;
  postMessage: (msg: OutboundMessage) => void;
}

const workerSelf = globalThis as unknown as WorkerSelf;
let activeController: AbortController | null = null;

workerSelf.onmessage = async (ev: MessageEvent<InboundMessage>): Promise<void> => {
  const msg = ev.data;

  if (msg.type === "cancel") {
    activeController?.abort(new DOMException("Cancelled by user", "AbortError"));
    return;
  }

  if (msg.type === "start") {
    activeController?.abort();
    const controller = new AbortController();
    activeController = controller;

    let lastProgressSent = 0;

    try {
      const result = await fixIpaBlob(msg.file, {
        stripExtensionKit: msg.options.stripExtensionKit,
        stripPlugIns: msg.options.stripPlugIns,
        cleanSignatures: msg.options.cleanSignatures,
        dryRun: msg.options.dryRun,
        verbose: msg.options.verbose,
        signal: controller.signal,
        onProgress(event) {
          if (event.type === "progress") {
            const now = performance.now();
            if (event.completed !== event.total && now - lastProgressSent < 50) {
              return;
            }
            lastProgressSent = now;
          }
          workerSelf.postMessage({ type: "progress", event });
        },
      });

      if (activeController === controller) {
        activeController = null;
      }

      workerSelf.postMessage({
        type: "done",
        stats: result.stats,
        blob: result.blob,
      });
    } catch (err) {
      if (activeController === controller) {
        activeController = null;
      }
      const aborted =
        controller.signal.aborted ||
        (err instanceof DOMException && err.name === "AbortError");
      const message = err instanceof Error ? err.message : String(err);
      workerSelf.postMessage({ type: "error", message, aborted });
    }
  }
};
