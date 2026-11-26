#!/usr/bin/env python3
"""
IPA ldid Assert Fixer (ipa_ldid_fixer.py)
-----------------------------------------
Fixes the "ldid.cpp(1461): _assert(): end >= size - 0x10" crash during SideStore/AltStore
installation by patching the Mach-O string table size (LC_SYMTAB.strsize) to bridge the gap
before the code signature (LC_CODE_SIGNATURE).

Optionally strips app extensions (to save App IDs on free Apple Developer accounts) and
cleans stale _CodeSignature directories so SideStore can sign cleanly.
"""

from __future__ import annotations

import argparse
import os
import shutil
import struct
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import BinaryIO, TypedDict

# ANSI Color Codes
class Color:
    RESET: str = "\033[0m"
    BOLD: str = "\033[1m"
    DIM: str = "\033[2m"
    GREY: str = "\033[90m"
    RED: str = "\033[91m"
    GREEN: str = "\033[92m"
    YELLOW: str = "\033[93m"
    BLUE: str = "\033[94m"
    MAGENTA: str = "\033[95m"
    CYAN: str = "\033[96m"
    WHITE: str = "\033[97m"


def paint(text: str, *styles: str) -> str:
    """Wraps text in ANSI styling codes unless NO_COLOR is set."""
    if os.environ.get("NO_COLOR"):
        return text
    joined = "".join(styles)
    return f"{joined}{text}{Color.RESET}"


# Mach-O Constants
MH_MAGIC: int = 0xFEEDFACE
MH_CIGAM: int = 0xCEFAEDFE
MH_MAGIC_64: int = 0xFEEDFACF
MH_CIGAM_64: int = 0xCFFAEDFE
FAT_MAGIC: int = 0xCAFEBABE
FAT_CIGAM: int = 0xBEBAFECA
FAT_MAGIC_64: int = 0xCAFEBABE + 1
FAT_CIGAM_64: int = 0xBFBAFECA

LC_SYMTAB: int = 0x2
LC_CODE_SIGNATURE: int = 0x1D


class PatchResult(TypedDict):
    slice_offset: int
    cputype: int
    old_strsize: int
    new_strsize: int
    old_end: int
    new_end: int
    gap: int
    strsize_file_offset: int


class PatchDetail(TypedDict):
    file: str
    offset: int
    old_val: int
    new_val: int
    gap: int


class ScanStats(TypedDict):
    binaries_scanned: int
    binaries_affected: int
    offsets_found: int
    extensions_found: int
    extensions_removed: int
    signatures_found: int
    signatures_cleaned: int
    details: list[PatchDetail]


def check_and_patch_slice(
    f: BinaryIO, slice_offset: int, dry_run: bool = False, verbose: bool = False
) -> PatchResult | None:
    """
    Checks a single Mach-O slice. If end < size - 0x10, patches LC_SYMTAB.strsize.
    Returns a PatchResult dict if patched or needing patch, or None if unaffected.
    """
    f.seek(slice_offset)
    magic_bytes = f.read(4)
    if len(magic_bytes) < 4:
        return None

    (magic,) = struct.unpack(">I", magic_bytes)

    if magic in (MH_MAGIC, MH_CIGAM):
        is_64 = False
        endian = ">" if magic == MH_MAGIC else "<"
        hdr_size = 28
    elif magic in (MH_MAGIC_64, MH_CIGAM_64):
        is_64 = True
        endian = ">" if magic == MH_MAGIC_64 else "<"
        hdr_size = 32
    else:
        return None

    f.seek(slice_offset)
    if is_64:
        magic_val, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved = struct.unpack(
            endian + "IIIIIIII", f.read(32)
        )
    else:
        magic_val, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags = struct.unpack(
            endian + "IIIIIII", f.read(28)
        )

    cmds_data = f.read(sizeofcmds)
    if len(cmds_data) < sizeofcmds:
        return None

    cmd_offset = 0
    symtab_offset_in_cmds: int | None = None
    symtab_stroff: int | None = None
    symtab_strsize: int | None = None
    sig_dataoff: int | None = None

    for _ in range(ncmds):
        if cmd_offset + 8 > len(cmds_data):
            break
        cmd, cmdsize = struct.unpack(endian + "II", cmds_data[cmd_offset : cmd_offset + 8])
        if cmdsize == 0 or cmd_offset + cmdsize > len(cmds_data):
            break

        if cmd == LC_SYMTAB and cmdsize >= 24:
            symoff, nsyms, stroff, strsize = struct.unpack(
                endian + "IIII", cmds_data[cmd_offset + 8 : cmd_offset + 24]
            )
            symtab_offset_in_cmds = cmd_offset
            symtab_stroff = stroff
            symtab_strsize = strsize
        elif cmd == LC_CODE_SIGNATURE and cmdsize >= 16:
            dataoff, datasize = struct.unpack(
                endian + "II", cmds_data[cmd_offset + 8 : cmd_offset + 16]
            )
            sig_dataoff = dataoff

        cmd_offset += cmdsize

    if (
        symtab_offset_in_cmds is None
        or symtab_stroff is None
        or symtab_strsize is None
        or sig_dataoff is None
    ):
        return None

    # ldid check:
    # size = signature->dataoff
    # end = symtab->stroff + symtab->strsize
    # _assert(end <= size);
    # _assert(end >= size - 0x10);
    size = sig_dataoff
    end = symtab_stroff + symtab_strsize

    if verbose:
        print(paint(f"      [Slice at 0x{slice_offset:x}]", Color.GREY))
        print(paint(f"        LC_SYMTAB: stroff=0x{symtab_stroff:x}, strsize=0x{symtab_strsize:x}, end=0x{end:x}", Color.GREY))
        print(paint(f"        LC_CODE_SIGNATURE: dataoff=0x{size:x}", Color.GREY))
        print(paint(f"        Gap (size - end): {size - end} bytes (0x{size - end:x})", Color.GREY))

    if end < size - 0x10:
        needed_strsize = size - symtab_stroff
        # Field offset of strsize within the file:
        # slice_offset + hdr_size + symtab_offset_in_cmds + 8 (cmd & cmdsize) + 12 (symoff, nsyms, stroff)
        strsize_file_offset = slice_offset + hdr_size + symtab_offset_in_cmds + 20

        result: PatchResult = {
            "slice_offset": slice_offset,
            "cputype": cputype,
            "old_strsize": symtab_strsize,
            "new_strsize": needed_strsize,
            "old_end": end,
            "new_end": size,
            "gap": size - end,
            "strsize_file_offset": strsize_file_offset,
        }

        if not dry_run:
            f.seek(strsize_file_offset)
            f.write(struct.pack(endian + "I", needed_strsize))
            f.flush()

        return result

    return None


def _scan_and_patch_macho(
    f: BinaryIO, dry_run: bool = False, verbose: bool = False
) -> list[PatchResult]:
    """Inspects a Mach-O or FAT binary stream and patches any invalid slices."""
    magic_bytes = f.read(4)
    if len(magic_bytes) < 4:
        return []

    (magic,) = struct.unpack(">I", magic_bytes)
    patches: list[PatchResult] = []

    # Check if FAT
    if magic in (FAT_MAGIC, FAT_CIGAM):
        endian = ">" if magic == FAT_MAGIC else "<"
        f.seek(4)
        (nfat_arch,) = struct.unpack(endian + "I", f.read(4))
        for _ in range(nfat_arch):
            cputype, cpusubtype, offset, size, align = struct.unpack(
                endian + "IIIII", f.read(20)
            )
            curr_pos = f.tell()
            patch = check_and_patch_slice(f, offset, dry_run, verbose)
            if patch:
                patches.append(patch)
            f.seek(curr_pos)
    elif magic in (FAT_MAGIC_64, FAT_CIGAM_64):
        endian = ">" if magic == FAT_MAGIC_64 else "<"
        f.seek(4)
        (nfat_arch,) = struct.unpack(endian + "I", f.read(4))
        for _ in range(nfat_arch):
            cputype, cpusubtype, offset, size, align, reserved = struct.unpack(
                endian + "IIQQII", f.read(32)
            )
            curr_pos = f.tell()
            patch = check_and_patch_slice(f, offset, dry_run, verbose)
            if patch:
                patches.append(patch)
            f.seek(curr_pos)
    elif magic in (MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64):
        # Thin Mach-O
        patch = check_and_patch_slice(f, 0, dry_run, verbose)
        if patch:
            patches.append(patch)

    return patches


def patch_macho_file(
    filepath: Path | str, dry_run: bool = False, verbose: bool = False
) -> list[PatchResult]:
    """
    Scans a binary file (FAT or Thin Mach-O) and repairs any slice failing the ldid check.
    Returns list of patch descriptions.
    """
    try:
        if dry_run:
            with open(filepath, "rb") as f:
                return _scan_and_patch_macho(f, dry_run=True, verbose=verbose)
        else:
            with open(filepath, "r+b") as f:
                return _scan_and_patch_macho(f, dry_run=False, verbose=verbose)
    except Exception as e:
        if verbose:
            print(paint(f"    [!] Error reading {filepath}: {e}", Color.RED))
        return []


def is_macho(filepath: Path | str) -> bool:
    """Quick check for Mach-O or FAT binary magic."""
    try:
        with open(filepath, "rb") as f:
            magic = f.read(4)
            if len(magic) < 4:
                return False
            (val,) = struct.unpack(">I", magic)
            return val in (
                MH_MAGIC,
                MH_CIGAM,
                MH_MAGIC_64,
                MH_CIGAM_64,
                FAT_MAGIC,
                FAT_CIGAM,
                FAT_MAGIC_64,
                FAT_CIGAM_64,
            )
    except Exception:
        return False


def fix_payload_directory(
    payload_root: Path,
    strip_extensions: bool = False,
    clean_signatures: bool = True,
    dry_run: bool = False,
    verbose: bool = False,
) -> ScanStats:
    """
    Traverses extracted payload directory:
    - Optionally strips Extensions and PlugIns
    - Optionally deletes _CodeSignature directories
    - Patches all Mach-O binaries failing the ldid assertion
    """
    stats: ScanStats = {
        "binaries_scanned": 0,
        "binaries_affected": 0,
        "offsets_found": 0,
        "extensions_found": 0,
        "extensions_removed": 0,
        "signatures_found": 0,
        "signatures_cleaned": 0,
        "details": [],
    }

    # 1. Strip extensions / plugins if requested
    for app_dir in payload_root.glob("**/*.app"):
        for folder_name in ("Extensions", "PlugIns"):
            ext_dir = app_dir / folder_name
            if ext_dir.is_dir():
                stats["extensions_found"] += 1
                if strip_extensions:
                    action = "Would remove" if dry_run else "Removing"
                    color = Color.YELLOW if dry_run else Color.RED
                    print(
                        f"{paint('[*]', Color.CYAN)} {paint(f'{action} {folder_name} folder:', color)} "
                        f"{ext_dir.relative_to(payload_root)}"
                    )
                    if not dry_run:
                        shutil.rmtree(ext_dir)
                    stats["extensions_removed"] += 1

    # 2. Clean stale _CodeSignature folders
    for cs_dir in list(payload_root.glob("**/_CodeSignature")):
        if cs_dir.is_dir():
            stats["signatures_found"] += 1
            if clean_signatures:
                action = "Would remove" if dry_run else "Removing"
                color = Color.YELLOW if dry_run else Color.RED
                print(
                    f"{paint('[*]', Color.CYAN)} {paint(f'{action} stale signature:', color)} "
                    f"{cs_dir.relative_to(payload_root)}"
                )
                if not dry_run:
                    shutil.rmtree(cs_dir)
                stats["signatures_cleaned"] += 1

    # 3. Scan and patch Mach-O binaries
    print(f"{paint('[*]', Color.CYAN)} Scanning binaries for ldid assertion errors...")
    for root, _, files in os.walk(payload_root):
        for fname in files:
            fpath = Path(root) / fname
            if not fpath.is_symlink() and fpath.is_file():
                if is_macho(fpath):
                    stats["binaries_scanned"] += 1
                    rel_path = fpath.relative_to(payload_root)
                    if verbose:
                        print(paint(f"  [+] Inspecting: {rel_path}", Color.GREY))
                    patches = patch_macho_file(fpath, dry_run=dry_run, verbose=verbose)
                    if patches:
                        stats["binaries_affected"] += 1
                        stats["offsets_found"] += len(patches)
                        for p in patches:
                            action = "Would patch" if dry_run else "Patched"
                            action_color = Color.RED if dry_run else Color.GREEN
                            offset_hex = f"0x{p['strsize_file_offset']:x}"
                            old_val_hex = f"0x{p['old_strsize']:x}"
                            new_val_hex = f"0x{p['new_strsize']:x}"
                            gap_str = f"{p['gap']:,} bytes"
                            detail: PatchDetail = {
                                "file": str(rel_path),
                                "offset": p["strsize_file_offset"],
                                "old_val": p["old_strsize"],
                                "new_val": p["new_strsize"],
                                "gap": p["gap"],
                            }
                            stats["details"].append(detail)
                            print(
                                f"  {paint('[!]', action_color, Color.BOLD)} {paint(f'{action} {rel_path}:', action_color)}\n"
                                f"      Offset {paint(offset_hex, Color.YELLOW)}: "
                                f"strsize {paint(old_val_hex, Color.RED)} -> {paint(new_val_hex, Color.GREEN)} "
                                f"(bridged gap of {paint(gap_str, Color.CYAN, Color.BOLD)})"
                            )

    return stats


def print_summary(stats: ScanStats, dry_run: bool = False) -> None:
    """Prints a clear summary of the scan / patch operation."""
    title = "=== Scan / Dry-Run Summary ===" if dry_run else "=== Scan / Patch Summary ==="
    print(f"\n{paint(title, Color.BOLD, Color.CYAN)}")
    print(f"  Binaries scanned:          {paint(str(stats['binaries_scanned']), Color.BOLD)}")
    if dry_run:
        print(f"  Binaries needing repair:   {paint(str(stats['binaries_affected']), Color.BOLD, Color.RED)}")
        print(f"  Offsets with wrong value:  {paint(str(stats['offsets_found']), Color.BOLD, Color.RED)}")
        if stats["extensions_removed"] > 0:
            print(f"  Extensions to remove:      {paint(str(stats['extensions_removed']), Color.BOLD, Color.YELLOW)}")
        print(f"  Signatures to clean:       {paint(str(stats['signatures_cleaned']), Color.BOLD, Color.YELLOW)}")
    else:
        print(f"  Binaries repaired:         {paint(str(stats['binaries_affected']), Color.BOLD, Color.GREEN)}")
        print(f"  Offsets corrected:         {paint(str(stats['offsets_found']), Color.BOLD, Color.GREEN)}")
        if stats["extensions_removed"] > 0:
            print(f"  Extensions removed:        {paint(str(stats['extensions_removed']), Color.BOLD, Color.YELLOW)}")
        print(f"  Signatures cleaned:        {paint(str(stats['signatures_cleaned']), Color.BOLD, Color.YELLOW)}")


def repackage_ipa(source_dir: Path, output_ipa_path: Path) -> None:
    """
    Zips source_dir into output_ipa_path, preserving Unix executable permissions.
    """
    print(f"{paint('[*]', Color.CYAN)} Repackaging fixed IPA to: {paint(str(output_ipa_path), Color.BOLD)}...")
    output_ipa_path.parent.mkdir(parents=True, exist_ok=True)
    temp_zip = output_ipa_path.with_suffix(".tmp.zip")
    if temp_zip.exists():
        temp_zip.unlink()

    with zipfile.ZipFile(temp_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for root, dirs, files in os.walk(source_dir):
            for name in dirs:
                full_path = Path(root) / name
                rel_path = full_path.relative_to(source_dir).as_posix() + "/"
                zinfo = zipfile.ZipInfo(rel_path)
                st = full_path.stat()
                zinfo.external_attr = (st.st_mode & 0xFFFF) << 16
                zf.writestr(zinfo, "")

            for name in files:
                full_path = Path(root) / name
                rel_path = full_path.relative_to(source_dir).as_posix()
                zinfo = zipfile.ZipInfo(rel_path)
                st = full_path.stat()
                zinfo.external_attr = (st.st_mode & 0xFFFF) << 16
                zinfo.compress_type = zipfile.ZIP_DEFLATED
                with open(full_path, "rb") as f:
                    zf.writestr(zinfo, f.read())

    temp_zip.replace(output_ipa_path)
    print(paint(f"[✓] Successfully created: {output_ipa_path} ({output_ipa_path.stat().st_size:,} bytes)", Color.GREEN, Color.BOLD))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fix 'ldid.cpp: _assert(): end >= size - 0x10' error in IPAs for SideStore/AltStore.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Fix an IPA file and create a new fixed IPA:
  python3 ipa_ldid_fixer.py app.ipa -o app_fixed.ipa

  # Fix and strip extensions (recommended for SideStore free account App ID limits):
  python3 ipa_ldid_fixer.py app.ipa --strip-extensions -o app_fixed.ipa

  # Check what would be patched without writing changes:
  python3 ipa_ldid_fixer.py app.ipa --dry-run --verbose

  # Fix an already unpacked directory:
  python3 ipa_ldid_fixer.py /path/to/unpacked_ipa_folder
""",
    )
    parser.add_argument("input", help="Path to input .ipa file or unpacked folder")
    parser.add_argument(
        "-o",
        "--output",
        help="Path for fixed .ipa output (defaults to <name>_fixed.ipa if input is an IPA)",
    )
    parser.add_argument(
        "--strip-extensions",
        action="store_true",
        help="Strip Extensions/ and PlugIns/ folders (saves App IDs on free Apple accounts & prevents extension crashes)",
    )
    parser.add_argument(
        "--keep-signatures",
        action="store_true",
        help="Do not remove existing _CodeSignature folders (default is to remove them so SideStore re-signs cleanly)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Analyze and print affected binaries without making modifications",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose inspection output"
    )

    args = parser.parse_args()
    input_path = Path(args.input).resolve()

    if not input_path.exists():
        print(paint(f"[X] Error: Input path '{input_path}' does not exist.", Color.RED, Color.BOLD))
        sys.exit(1)

    clean_signatures = not args.keep_signatures

    if input_path.is_file() and input_path.suffix.lower() == ".ipa":
        out_ipa = (
            Path(args.output).resolve()
            if args.output
            else input_path.parent / f"{input_path.stem}_fixed.ipa"
        )

        with tempfile.TemporaryDirectory(prefix="ipa_fixer_") as tmpdir:
            tmp_root = Path(tmpdir)
            print(f"{paint('[*]', Color.CYAN)} Extracting IPA: {paint(str(input_path), Color.BOLD)}...")
            with zipfile.ZipFile(input_path, "r") as zf:
                zf.extractall(tmp_root)

            stats = fix_payload_directory(
                tmp_root,
                strip_extensions=args.strip_extensions,
                clean_signatures=clean_signatures,
                dry_run=args.dry_run,
                verbose=args.verbose,
            )

            print_summary(stats, dry_run=args.dry_run)

            if not args.dry_run:
                repackage_ipa(tmp_root, out_ipa)
            else:
                print(paint("\n[*] Dry run complete. No files were modified or repackaged.", Color.YELLOW, Color.BOLD))

    elif input_path.is_dir():
        print(f"{paint('[*]', Color.CYAN)} Processing directory: {paint(str(input_path), Color.BOLD)}...")
        stats = fix_payload_directory(
            input_path,
            strip_extensions=args.strip_extensions,
            clean_signatures=clean_signatures,
            dry_run=args.dry_run,
            verbose=args.verbose,
        )

        print_summary(stats, dry_run=args.dry_run)

        if args.output and not args.dry_run:
            repackage_ipa(input_path, Path(args.output).resolve())
        elif args.dry_run:
            print(paint("\n[*] Dry run complete. No files were modified or repackaged.", Color.YELLOW, Color.BOLD))
    else:
        print(paint(f"[X] Error: Input '{input_path}' is neither a .ipa file nor a directory.", Color.RED, Color.BOLD))
        sys.exit(1)


if __name__ == "__main__":
    main()
