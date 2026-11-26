# IPA ldid Assert Fixer

[![Buy Me a Coffee](https://img.shields.io/badge/Buy%20Me%20a%20Coffee-ffdd00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=000000)](https://buymeacoffee.com/luizhpio)

A 100% client-side web tool, isomorphic TypeScript/Node.js library, and CLI for fixing:

1. **`ldid.cpp(1461): _assert(): end >= size - 0x10`** — Repairs Mach-O `LC_SYMTAB.strsize` headers when a gap exists before `LC_CODE_SIGNATURE.dataoff`.
2. **SideStore `IXErrorDomain Code=8` (`Mismatched bundle IDs`)** — Optionally strips `Payload/*.app/Extensions/` (ExtensionKit bundles that SideStore cannot rewrite) while keeping `PlugIns/` selectable.

## Live Web Tool (GitHub Pages)

**[https://luizhpio.github.io/ipa-fixer/](https://luizhpio.github.io/ipa-fixer/)**

- Runs **100% locally in your browser** (zero uploads, works offline and in iOS Safari).
- Uses **raw ZIP entry pass-through** and streaming Mach-O header inspection so untouched assets are never decompressed or loaded into RAM.

## Repository Structure

- `web/index.html` — Self-contained static website with the library & Web Worker embedded inline.
- `web/ipa-fixer.esm.js` — Standalone browser ES module bundle.
- `tools/ipa-fixer/` — Zero-runtime-dependency TypeScript library, desktop Node.js CLI, and web build script.
- `tools/python/ipa_ldid_fixer.py` — Standalone Python CLI.

## Usage

### Desktop Node.js CLI

```bash
cd tools/ipa-fixer
npm install
npm run build

# Dry-run inspection
node dist/cli.js /path/to/app.ipa --dry-run

# Fix & strip ExtensionKit (Extensions/), keeping PlugIns/
node dist/cli.js /path/to/app.ipa --strip-extensionkit -o app_fixed.ipa

# Fix & strip all extensions (Extensions/ + PlugIns/)
node dist/cli.js /path/to/app.ipa --strip-extensions -o app_fixed.ipa
```

### Library (Node.js & Browser)

```js
// Node.js
import { fixIpaFile } from "./tools/ipa-fixer/dist/node.js";
const stats = await fixIpaFile("input.ipa", "output_fixed.ipa", {
  stripExtensionKit: true,
});

// Browser
import { fixIpaBlob } from "./web/ipa-fixer.esm.js";
const { stats: webStats, blob } = await fixIpaBlob(file, {
  stripExtensionKit: true,
});
```

### Building the Static Website

```bash
cd tools/ipa-fixer
npm run build:web
```

This bundles `tools/ipa-fixer/src/index.ts` and `tools/ipa-fixer/web-src/worker.ts` into `web/ipa-fixer.esm.js` and `web/index.html`.
