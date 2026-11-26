#!/usr/bin/env node
import * as fs from "node:fs";
import * as path from "node:path";
import { fixIpaFile } from "./node.js";
import type { FixIpaOptions, ProgressEvent, ScanStats } from "./types.js";

const Color = {
  RESET: "\x1b[0m",
  BOLD: "\x1b[1m",
  GREY: "\x1b[90m",
  RED: "\x1b[91m",
  GREEN: "\x1b[92m",
  YELLOW: "\x1b[93m",
  CYAN: "\x1b[96m",
} as const;

function paint(text: string, ...styles: string[]): string {
  if (process.env["NO_COLOR"]) {
    return text;
  }
  return `${styles.join("")}${text}${Color.RESET}`;
}

interface CliArgs {
  input: string;
  output: string | null;
  stripExtensionKit: boolean;
  stripPlugIns: boolean;
  stripExtensions: boolean;
  cleanSignatures: boolean;
  scanAllFiles: boolean;
  dryRun: boolean;
  verbose: boolean;
  help: boolean;
}

function printHelp(): void {
  console.log(`Usage: ipa-ldid-fixer <input.ipa> [options]

Fix "ldid.cpp(1461): _assert(): end >= size - 0x10" errors (and optional SideStore
ExtensionKit bundle ID mismatches) in iOS IPA archives.

Options:
  -o, --output <path>       Output .ipa path (defaults to <name>_fixed.ipa)
      --strip-extensionkit  Remove Payload/*.app/Extensions/ (fixes SideStore
                            IXErrorDomain Code=8 while keeping PlugIns/)
      --strip-plugins       Remove Payload/*.app/PlugIns/ (legacy extensions)
      --strip-extensions    Remove both Extensions/ and PlugIns/
      --keep-signatures     Keep existing _CodeSignature folders
      --scan-all            Inspect all ZIP entries, even known asset extensions
      --dry-run             Analyze and report issues without modifying or writing
  -v, --verbose             Show every Mach-O binary and slice inspected
  -h, --help                Show this help message

Examples:
  node dist/cli.js app.ipa --dry-run -v
  node dist/cli.js app.ipa --strip-extensionkit -o app_fixed.ipa
  node dist/cli.js app.ipa --strip-extensions -o app_fixed.ipa`);
}

function parseArgs(argv: readonly string[]): CliArgs {
  let input: string | null = null;
  let output: string | null = null;
  let stripExtensionKit = false;
  let stripPlugIns = false;
  let stripExtensions = false;
  let cleanSignatures = true;
  let scanAllFiles = false;
  let dryRun = false;
  let verbose = false;
  let help = false;

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg === "-h" || arg === "--help") {
      help = true;
    } else if (arg === "-o" || arg === "--output") {
      const next = argv[i + 1];
      if (next === undefined || next.startsWith("-")) {
        throw new Error(`Option ${arg} requires a file path argument.`);
      }
      output = next;
      i++;
    } else if (arg.startsWith("--output=")) {
      output = arg.slice("--output=".length);
    } else if (arg === "--strip-extensionkit") {
      stripExtensionKit = true;
    } else if (arg === "--strip-plugins") {
      stripPlugIns = true;
    } else if (arg === "--strip-extensions") {
      stripExtensions = true;
    } else if (arg === "--keep-signatures") {
      cleanSignatures = false;
    } else if (arg === "--scan-all") {
      scanAllFiles = true;
    } else if (arg === "--dry-run") {
      dryRun = true;
    } else if (arg === "-v" || arg === "--verbose") {
      verbose = true;
    } else if (arg.startsWith("-")) {
      throw new Error(`Unknown option: ${arg}`);
    } else if (input === null) {
      input = arg;
    } else {
      throw new Error(`Unexpected extra positional argument: ${arg}`);
    }
  }

  if (!help && input === null) {
    throw new Error("Missing required <input.ipa> argument.");
  }

  return {
    input: input ?? "",
    output,
    stripExtensionKit,
    stripPlugIns,
    stripExtensions,
    cleanSignatures,
    scanAllFiles,
    dryRun,
    verbose,
    help,
  };
}

function defaultOutputPath(inputPath: string): string {
  const parsed = path.parse(inputPath);
  return path.join(parsed.dir, `${parsed.name}_fixed.ipa`);
}

function printSummary(stats: ScanStats, dryRun: boolean): void {
  const title = dryRun ? "=== Scan / Dry-Run Summary ===" : "=== Scan / Patch Summary ===";
  console.log(`\n${paint(title, Color.BOLD, Color.CYAN)}`);
  console.log(`  Binaries scanned:          ${paint(String(stats.binariesScanned), Color.BOLD)}`);
  if (dryRun) {
    console.log(
      `  Binaries needing repair:   ${paint(String(stats.binariesAffected), Color.BOLD, Color.RED)}`
    );
    console.log(
      `  Offsets with wrong value:  ${paint(String(stats.offsetsFound), Color.BOLD, Color.RED)}`
    );
    if (stats.extensionKitFoldersRemoved > 0) {
      console.log(
        `  ExtensionKit to remove:    ${paint(String(stats.extensionKitFoldersRemoved), Color.BOLD, Color.YELLOW)}`
      );
    }
    if (stats.plugInsFoldersRemoved > 0) {
      console.log(
        `  PlugIns to remove:         ${paint(String(stats.plugInsFoldersRemoved), Color.BOLD, Color.YELLOW)}`
      );
    }
    console.log(
      `  Signatures to clean:       ${paint(String(stats.signaturesCleaned), Color.BOLD, Color.YELLOW)}`
    );
  } else {
    console.log(
      `  Binaries repaired:         ${paint(String(stats.binariesAffected), Color.BOLD, Color.GREEN)}`
    );
    console.log(
      `  Offsets corrected:         ${paint(String(stats.offsetsFound), Color.BOLD, Color.GREEN)}`
    );
    if (stats.extensionKitFoldersRemoved > 0) {
      console.log(
        `  ExtensionKit removed:      ${paint(String(stats.extensionKitFoldersRemoved), Color.BOLD, Color.YELLOW)}`
      );
    }
    if (stats.plugInsFoldersRemoved > 0) {
      console.log(
        `  PlugIns removed:           ${paint(String(stats.plugInsFoldersRemoved), Color.BOLD, Color.YELLOW)}`
      );
    }
    console.log(
      `  Signatures cleaned:        ${paint(String(stats.signaturesCleaned), Color.BOLD, Color.YELLOW)}`
    );
  }
  console.log(
    `  Elapsed time:              ${paint(`${(stats.elapsedMs / 1000).toFixed(2)}s`, Color.CYAN)}`
  );
}

async function run(): Promise<void> {
  let args: CliArgs;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(paint(`[X] Error: ${msg}`, Color.RED, Color.BOLD));
    process.exit(1);
  }

  if (args.help) {
    printHelp();
    return;
  }

  const inputPath = path.resolve(args.input);
  if (!fs.existsSync(inputPath)) {
    console.error(paint(`[X] Error: Input file '${inputPath}' does not exist.`, Color.RED, Color.BOLD));
    process.exit(1);
  }

  const outputPath = args.dryRun
    ? null
    : path.resolve(args.output ?? defaultOutputPath(inputPath));

  const onProgress = (event: ProgressEvent): void => {
    switch (event.type) {
      case "stage": {
        if (event.stage === "reading-index") {
          console.log(`${paint("[*]", Color.CYAN)} Reading IPA: ${paint(inputPath, Color.BOLD)}...`);
        } else if (event.stage === "scanning") {
          console.log(`${paint("[*]", Color.CYAN)} ${event.message}`);
        } else if (event.stage === "writing") {
          console.log(`${paint("[*]", Color.CYAN)} ${event.message}`);
        }
        break;
      }
      case "remove": {
        const label =
          event.category === "signature"
            ? "stale signature"
            : event.category === "extensionkit"
              ? "Extensions (ExtensionKit) folder"
              : "PlugIns folder";
        const action = event.dryRun ? "Would remove" : "Removing";
        const color = event.dryRun ? Color.YELLOW : Color.RED;
        console.log(`${paint("[*]", Color.CYAN)} ${paint(`${action} ${label}:`, color)} ${event.path}`);
        break;
      }
      case "inspect": {
        console.log(paint(`  [+] Inspecting: ${event.file}`, Color.GREY));
        for (const s of event.slices) {
          console.log(paint(`      [Slice at 0x${s.sliceOffset.toString(16)}]`, Color.GREY));
          console.log(
            paint(
              `        LC_SYMTAB: stroff=0x${s.stroff.toString(16)}, strsize=0x${s.strsize.toString(16)}, end=0x${s.end.toString(16)}`,
              Color.GREY
            )
          );
          console.log(
            paint(`        LC_CODE_SIGNATURE: dataoff=0x${s.sigDataoff.toString(16)}`, Color.GREY)
          );
          console.log(
            paint(
              `        Gap (size - end): ${s.gap} bytes (0x${s.gap.toString(16)})`,
              Color.GREY
            )
          );
        }
        break;
      }
      case "patch": {
        const action = event.dryRun ? "Would patch" : "Patched";
        const actionColor = event.dryRun ? Color.RED : Color.GREEN;
        const { detail } = event;
        const offsetHex = `0x${detail.offset.toString(16)}`;
        const oldHex = `0x${detail.oldVal.toString(16)}`;
        const newHex = `0x${detail.newVal.toString(16)}`;
        const gapStr = `${detail.gap.toLocaleString("en-US")} bytes`;
        console.log(
          `  ${paint("[!]", actionColor, Color.BOLD)} ${paint(`${action} ${detail.file}:`, actionColor)}\n` +
            `      Offset ${paint(offsetHex, Color.YELLOW)}: ` +
            `strsize ${paint(oldHex, Color.RED)} -> ${paint(newHex, Color.GREEN)} ` +
            `(bridged gap of ${paint(gapStr, Color.CYAN, Color.BOLD)})`
        );
        break;
      }
      case "progress":
        break;
    }
  };

  const options: FixIpaOptions = {
    stripExtensionKit: args.stripExtensionKit,
    stripPlugIns: args.stripPlugIns,
    stripExtensions: args.stripExtensions,
    cleanSignatures: args.cleanSignatures,
    dryRun: args.dryRun,
    scanAllFiles: args.scanAllFiles,
    verbose: args.verbose,
    onProgress,
  };

  const stats = await fixIpaFile(inputPath, outputPath, options);
  printSummary(stats, args.dryRun);

  if (args.dryRun) {
    console.log(paint("\n[*] Dry run complete. No files were modified or repackaged.", Color.YELLOW, Color.BOLD));
  } else if (outputPath !== null) {
    const outStat = fs.statSync(outputPath);
    console.log(
      paint(
        `\n[✓] Successfully created: ${outputPath} (${outStat.size.toLocaleString("en-US")} bytes)`,
        Color.GREEN,
        Color.BOLD
      )
    );
  }
}

run().catch((err) => {
  const msg = err instanceof Error ? err.message : String(err);
  console.error(paint(`[X] Error: ${msg}`, Color.RED, Color.BOLD));
  process.exit(1);
});
