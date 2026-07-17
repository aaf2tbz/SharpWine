#!/usr/bin/env python3
"""Create the allowlisted, relocatable MetalSharp Wine runtime tree."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
from pathlib import Path


SYSTEM_PREFIXES = ("/System/Library/", "/usr/lib/")
RUNTIME_LINKS = (
    "msidb", "msiexec", "notepad", "regedit", "regsvr32", "wineboot",
    "winecfg", "wineconsole", "winedbg", "winefile", "winemine", "winepath",
)
OPTIONAL_UNBOUND_MODULES = ("winex11.so", "winedmo.so", "winegstreamer.so")
EMBEDDED_PREFIXES = (
    re.compile(rb"/Users/[^\0\r\n]*"),
    re.compile(rb"/home/runner/[^\0\r\n]*"),
    re.compile(rb"/private/var/folders/[^\0\r\n]*"),
    re.compile(rb"/usr/local/Cellar/[^\0\r\n]*"),
    re.compile(rb"/opt/homebrew[^\0\r\n]*"),
)
LICENSES = {
    "freetype": ("LICENSE.TXT", "FTL.txt"),
    "libpng": ("LICENSE", "libpng-2.0.txt"),
    "libx11": ("COPYING", "MIT-libX11.txt"),
    "libxau": ("COPYING", "MIT-libXau.txt"),
    "libxcb": ("COPYING", "MIT-libxcb.txt"),
    "libxdmcp": ("COPYING", "MIT-libXdmcp.txt"),
    "llvm": ("LICENSE.TXT", "Apache-2.0-WITH-LLVM-exception.txt"),
    "mesa": ("license.rst", "Mesa-licenses.rst"),
    "molten-vk": ("LICENSE", "Apache-2.0-MoltenVK.txt"),
    "sdl2-compat": ("LICENSE.txt", "Zlib-SDL2.txt"),
    "sdl3": ("LICENSE.txt", "Zlib-SDL3.txt"),
    "spirv-tools": ("LICENSE", "Apache-2.0-SPIRV-Tools.txt"),
    "vulkan-loader": ("LICENSE.txt", "Apache-2.0-Vulkan-Loader.txt"),
    "z3": ("LICENSE.txt", "MIT-Z3.txt"),
    "zstd": ("LICENSE", "BSD-3-Clause-Zstandard.txt"),
}


def fail(message: str) -> None:
    raise SystemExit(f"runtime staging failed: {message}")


def run(*argv: str, check: bool = True) -> str:
    result = subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if check and result.returncode:
        fail(f"{' '.join(argv)}: {result.stderr.strip()}")
    return result.stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def copy_file(source: Path, destination: Path, mode: int | None = None) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    os.chmod(destination, mode if mode is not None else stat.S_IMODE(source.stat().st_mode))


def is_macho(path: Path) -> bool:
    return path.is_file() and not path.is_symlink() and "Mach-O" in run("file", "-b", str(path))


def dependencies(path: Path) -> list[str]:
    lines = run("otool", "-L", str(path)).splitlines()[1:]
    return [line.strip().split(" (", 1)[0] for line in lines if line.strip()]


def dylib_id(path: Path) -> str | None:
    lines = [line.strip() for line in run("otool", "-D", str(path), check=False).splitlines()[1:]
             if line.strip()]
    return lines[0] if lines else None


def dependency_source(name: str, origin: Path, runtime: Path) -> Path | None:
    if name.startswith(SYSTEM_PREFIXES):
        return None
    if name.startswith("/"):
        value = Path(name)
        if value.exists():
            return value.resolve()
        fail(f"missing absolute dependency {name} referenced by {origin}")
    basename = Path(name).name
    packaged = runtime / basename
    if packaged.exists():
        return packaged.resolve()
    package = runtime.parents[2]
    matches = [path for path in package.rglob(basename) if path.is_file()]
    if len(matches) == 1:
        return matches[0].resolve()
    if name.startswith("@loader_path/"):
        value = (origin.parent / name.removeprefix("@loader_path/")).resolve()
        if value.exists():
            return value
    if name.startswith("@rpath/"):
        # Initial Wine modules use package-local rpaths. Homebrew libraries are
        # discovered through another absolute dependency before this is needed.
        candidate = runtime / basename
        if candidate.exists():
            return candidate.resolve()
    fail(f"unresolved non-system dependency {name} referenced by {origin}")


def validate_bundle(bundle: Path, expected_commit: str | None) -> tuple[Path, Path | None, str]:
    manifest_path = bundle / "bundle.manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"invalid ARM64X bundle manifest: {error}")
    commit = manifest.get("gitCommit")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        fail("ARM64X bundle commit is invalid")
    if expected_commit and commit != expected_commit:
        fail(f"ARM64X bundle commit {commit} does not match {expected_commit}")
    listed = manifest.get("files")
    if not isinstance(listed, list) or not listed:
        fail("ARM64X bundle file inventory is empty")
    expected: set[str] = set()
    for record in listed:
        if not isinstance(record, dict) or set(record) != {"path", "sha256", "size"}:
            fail("ARM64X bundle contains an invalid file record")
        relative = Path(record["path"])
        if relative.is_absolute() or ".." in relative.parts:
            fail("ARM64X bundle contains an unsafe path")
        path = bundle / relative
        if not path.is_file() or path.stat().st_size != record["size"] or sha256(path) != record["sha256"]:
            fail(f"ARM64X bundle payload mismatch: {relative}")
        expected.add(relative.as_posix())
    actual = {p.relative_to(bundle).as_posix() for p in bundle.rglob("*") if p.is_file()}
    if actual != expected | {"bundle.manifest.json"}:
        fail("ARM64X bundle has unmanifested or missing files")
    a = bundle / "a/arm64x_fixture.dll"
    b = bundle / "b/arm64x_fixture.dll"
    if sha256(a) != sha256(b):
        fail("ARM64X fixture is not reproducible")
    host = bundle / "a/arm64x_fixture_host.exe"
    if host.exists():
        other_host = bundle / "b/arm64x_fixture_host.exe"
        if not other_host.is_file() or sha256(host) != sha256(other_host):
            fail("ARM64X validation host is not reproducible")
    else:
        host = None
    return a, host, commit


def copy_wine(foundation: Path, package: Path) -> None:
    source = foundation / "wine" if (foundation / "wine/bin/wine").is_file() else foundation
    if not (source / "bin/wine").is_file() or not (source / "bin/wineserver").is_file():
        fail(f"foundation does not contain an installed Wine tree: {source}")
    (package / "bin").mkdir(parents=True)
    copy_file(source / "bin/wine", package / "bin/.wine-real", 0o755)
    copy_file(source / "bin/wineserver", package / "bin/.wineserver-real", 0o755)
    launcher = package / "bin/wine"
    launcher.write_text("""#!/bin/sh
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
export WINELOADER="$root/bin/.wine-real"
export WINESERVER="$root/bin/.wineserver-real"
export WINEDLLPATH="$root/lib/wine"
export WINEDATADIR="$root/share/wine"
export VK_ICD_FILENAMES="$root/share/vulkan/icd.d/MoltenVK_icd.json"
export XDG_CONFIG_DIRS="$root/share"
export XDG_DATA_DIRS="$root/share"
export DRIRC_CONFIGDIR="$root/share/drirc.d"
export XLOCALEDIR="$root/share/X11/locale"
export XERRORDB="$root/share/X11/XErrorDB"
cd "$root"

# Publication archives intentionally omit extended attributes. Restore the
# branded Finder/Dock icon directly on the native loader after extraction,
# before Cocoa registers the process with the Dock.
runtime_icon="$root/share/metalsharp/MetalSharpRuntime.icns"
if [ -f "$runtime_icon" ] && \
   ! /usr/bin/xattr -p com.apple.ResourceFork "$root/bin/.wine-real" >/dev/null 2>&1; then
    /usr/bin/osascript -l JavaScript - "$root/bin/.wine-real" "$runtime_icon" \
        >/dev/null 2>&1 <<'METALSHARP_ICON' || true
ObjC.import('AppKit')
function run(argv) {
    const target = $(argv[0])
    const icon = $.NSImage.alloc.initWithContentsOfFile($(argv[1]))
    if (!icon) throw new Error('could not load MetalSharp runtime icon')
    return Boolean($.NSWorkspace.sharedWorkspace.setIconForFileOptions(icon, target, 0))
}
METALSHARP_ICON
fi

prefix_ready()
{
    prefix=${WINEPREFIX:-"$HOME/.wine"}
    for relative in .update-timestamp system.reg user.reg userdef.reg \
        drive_c/windows/system32/kernel32.dll \
        drive_c/windows/system32/ntdll.dll \
        drive_c/windows/system32/services.exe
    do
        test -s "$prefix/$relative" || return 1
    done
}

wow64_ready()
{
    prefix=${WINEPREFIX:-"$HOME/.wine"}
    for name in notepad.exe ntdll.dll kernel32.dll user32.dll win32u.dll
    do
        test -s "$prefix/drive_c/windows/syswow64/$name" || return 1
    done
}

ensure_wow64_payload()
{
    wow64_ready && return 0
    source="$root/lib/wine/i386-windows"
    target="${WINEPREFIX:-"$HOME/.wine"}/drive_c/windows/syswow64"
    test -d "$source" || return 1
    mkdir -p "$target"
    /usr/bin/ditto "$source" "$target"
    wow64_ready
}

recover_wineboot()
{
    prefix=${WINEPREFIX:-"$HOME/.wine"}
    "$root/bin/.wineserver-real" -k >/dev/null 2>&1 || true
    "$root/bin/.wineserver-real" -w >/dev/null 2>&1 || true
    inf=$(printf '%s' "$root/share/wine/wine.inf" | sed 's,/,\\\\,g')
    start_recovery_installer()
    {
        (
            export METALSHARP_WINEBOOT_SKIP_FAKE_REGISTRY=1
            exec -a "$root/bin/wine" "$root/bin/.wine-real" rundll32.exe \
                setupapi,InstallHinfSection DefaultInstall 128 "Z:$inf"
        ) &
        installer=$!
    }
    start_recovery_installer
    installer_age=0
    previous=
    stable=0
    attempts=0
    while test "$attempts" -lt 240
    do
        if { ! kill -0 "$installer" 2>/dev/null || test "$installer_age" -ge 40; } && ! prefix_ready; then
            kill "$installer" 2>/dev/null || true
            wait "$installer" 2>/dev/null || true
            "$root/bin/.wineserver-real" -k >/dev/null 2>&1 || true
            "$root/bin/.wineserver-real" -w >/dev/null 2>&1 || true
            start_recovery_installer
            installer_age=0
        fi
        if prefix_ready; then
            current=$(stat -f '%z:%m' \
                "$prefix/.update-timestamp" \
                "$prefix/system.reg" "$prefix/user.reg" "$prefix/userdef.reg" \
                "$prefix/drive_c/windows/system32/kernel32.dll" \
                "$prefix/drive_c/windows/system32/ntdll.dll" \
                "$prefix/drive_c/windows/system32/services.exe")
            if test "$current" = "$previous"; then
                stable=$((stable + 1))
            else
                stable=0
                previous=$current
            fi
            test "$stable" -ge 10 && break
        else
            stable=0
        fi
        attempts=$((attempts + 1))
        installer_age=$((installer_age + 1))
        sleep 0.5
    done
    kill "$installer" 2>/dev/null || true
    wait "$installer" 2>/dev/null || true
    "$root/bin/.wineserver-real" -k >/dev/null 2>&1 || true
    "$root/bin/.wineserver-real" -w >/dev/null 2>&1 || true
    prefix_ready && ensure_wow64_payload
}

if test "$(basename "$0")" = wineboot; then
    case " $* " in
        *" --kill "*|*" --shutdown "*|*" --end-session "*)
            exec -a "$0" "$root/bin/.wine-real" "$@"
            ;;
    esac
    # The packaged native bootstrap deliberately omits callback-heavy fake-DLL
    # registry resources on its first pass. Manifests and the complete staged
    # PE tree remain installed; this is the same bounded mode used by recovery.
    export METALSHARP_WINEBOOT_SKIP_FAKE_REGISTRY=1
    initial=0
    (exec -a "$0" "$root/bin/.wine-real" "$@") || initial=$?
    if prefix_ready; then
        ensure_wow64_payload
        exit "$initial"
    fi
    recover_wineboot
    exit 0
fi

if prefix_ready; then
    ensure_wow64_payload
fi
exec -a "$0" "$root/bin/.wine-real" "$@"
""", encoding="utf-8")
    os.chmod(launcher, 0o755)
    os.symlink(".wineserver-real", package / "bin/wineserver")
    for name in RUNTIME_LINKS:
        os.symlink("wine", package / "bin" / name)
    shutil.copytree(source / "lib/wine", package / "lib/wine", symlinks=True)
    for candidate in (package / "lib/wine").rglob("*"):
        if candidate.is_file() and (candidate.name in OPTIONAL_UNBOUND_MODULES or
                                    candidate.suffix in {".a", ".la", ".pc"}):
            candidate.unlink()
    shutil.copytree(source / "share/wine", package / "share/wine", symlinks=True)
    for name in ("libmetalsharp-gem-wine.0.1.0.dylib",):
        candidate = source / "lib" / name
        if candidate.is_file():
            copy_file(candidate, package / "lib" / name, 0o755)
    bridge = package / "lib/libmetalsharp-gem-wine.0.1.0.dylib"
    if not bridge.is_file():
        fail("versioned GEM bridge is absent from foundation")
    os.symlink(bridge.name, package / "lib/libmetalsharp-gem-wine.0.dylib")
    os.symlink("libmetalsharp-gem-wine.0.dylib", package / "lib/libmetalsharp-gem-wine.dylib")


def seed_runtime_libraries(runtime: Path, brew: Path, deps: Path) -> None:
    seeds = {
        deps / "vulkan/libvulkan.dylib": "libvulkan.1.dylib",
        deps / "moltenvk/libMoltenVK.dylib": "libMoltenVK.dylib",
        brew / "opt/mesa/lib/libEGL.1.dylib": "libEGL.1.dylib",
        brew / "opt/freetype/lib/libfreetype.6.dylib": "libfreetype.6.dylib",
        brew / "opt/sdl2-compat/lib/libSDL2-2.0.0.dylib": "libSDL2-2.0.0.dylib",
        brew / "opt/sdl3/lib/libSDL3.0.dylib": "libSDL3.0.dylib",
    }
    for source, name in seeds.items():
        if not source.is_file():
            fail(f"required runtime seed is missing: {source}")
        copy_file(source.resolve(), runtime / name, 0o755)
    links = {
        "libvulkan.dylib": "libvulkan.1.dylib",
        "libEGL.dylib": "libEGL.1.dylib",
        "libfreetype.dylib": "libfreetype.6.dylib",
        "libSDL2-2.0.dylib": "libSDL2-2.0.0.dylib",
        "libSDL2.dylib": "libSDL2-2.0.0.dylib",
        "libSDL3.dylib": "libSDL3.0.dylib",
    }
    for link, target in links.items():
        destination = runtime / link
        if not destination.exists() and not destination.is_symlink():
            os.symlink(target, destination)


def vendor_closure(package: Path) -> None:
    runtime = package / "lib/wine/aarch64-unix"
    changed = True
    while changed:
        changed = False
        for origin in sorted(p for p in package.rglob("*") if is_macho(p)):
            for name in dependencies(origin):
                source = dependency_source(name, origin, runtime)
                if source is None:
                    continue
                try:
                    source.relative_to(package)
                    destination = source
                except ValueError:
                    destination = runtime / source.name
                if not destination.exists():
                    copy_file(source, destination, 0o755)
                    changed = True

    machos = sorted(p for p in package.rglob("*") if is_macho(p))
    for origin in machos:
        for name in dependencies(origin):
            if name.startswith(SYSTEM_PREFIXES):
                continue
            source = dependency_source(name, origin, runtime)
            if source is None:
                continue
            try:
                source.relative_to(package)
                destination = source
            except ValueError:
                destination = runtime / source.name
            if name == "@rpath/libmetalsharp-gem-wine.0.dylib":
                replacement = name
            else:
                replacement = f"@loader_path/{os.path.relpath(destination, origin.parent)}"
            if name != replacement:
                run("install_name_tool", "-change", name, replacement, str(origin))
        identity = dylib_id(origin)
        if identity and origin.suffix == ".dylib":
            install_id = ("@rpath/libmetalsharp-gem-wine.0.dylib"
                          if origin.name == "libmetalsharp-gem-wine.0.1.0.dylib"
                          else f"@rpath/{origin.name}")
            run("install_name_tool", "-id", install_id, str(origin))
        load_commands = run("otool", "-l", str(origin))
        lines = load_commands.splitlines()
        for index, line in enumerate(lines):
            if line.strip() == "cmd LC_RPATH" and index + 2 < len(lines):
                path_line = lines[index + 2].strip()
                if path_line.startswith("path "):
                    rpath = path_line[5:].split(" (offset", 1)[0]
                    if rpath.startswith("/"):
                        run("install_name_tool", "-delete_rpath", rpath, str(origin))
        run("codesign", "--force", "--sign", "-", "--timestamp=none", str(origin))


def scrub_embedded_prefixes(package: Path) -> None:
    """Remove inert build prefixes after env-controlled data paths are vendored.

    Wine and Homebrew bottles compile optional search fallbacks into read-only
    strings. Runtime lookups are redirected by the package launcher; retaining
    those inert strings would nevertheless violate the no-build-path contract.
    Replacements never grow a file, so section offsets and load commands remain
    stable. Any changed Mach-O is ad-hoc signed again.
    """
    for path in sorted(p for p in package.rglob("*") if p.is_file() and not p.is_symlink()):
        data = path.read_bytes()
        changed = False
        for pattern in EMBEDDED_PREFIXES:
            for match in reversed(list(pattern.finditer(data))):
                original = match.group()
                replacement = b"/dev/null"
                for marker in (b"/share/wine", b"/lib/wine"):
                    if marker in original:
                        replacement = b"/metalsharp/runtime" + original[original.rfind(marker):]
                        break
                else:
                    for suffix in (b"/bin", b"/lib"):
                        if original.endswith(suffix):
                            replacement = b"/metalsharp/runtime" + suffix
                            break
                if original.startswith(b"/opt/homebrew"):
                    if b"xdg" in original.lower():
                        replacement = b"/etc/xdg"
                    elif b"share" in original.lower() and b":" in original:
                        replacement = b"/usr/share"
                if len(replacement) > len(original):
                    fail(f"cannot scrub embedded search path in {path}")
                data = (data[:match.start()] + replacement +
                        b"\0" * (len(original) - len(replacement)) + data[match.end():])
                changed = True
        if changed:
            macho = is_macho(path)
            path.write_bytes(data)
            if macho:
                run("codesign", "--force", "--sign", "-", "--timestamp=none", str(path))


def rebind_chained_import(data: bytes, symbol: str, target_library: str) -> bytes:
    """Rebind one format-1 Mach-O chained import without changing file layout."""
    value = bytearray(data)
    if len(value) < 32 or struct.unpack_from("<I", value)[0] != 0xfeedfacf:
        fail("chained import rebinding requires a little-endian 64-bit Mach-O")
    ncmds = struct.unpack_from("<I", value, 16)[0]
    offset = 32
    ordinal = 0
    target_ordinal: int | None = None
    fixups: tuple[int, int] | None = None
    dylib_commands = {0x0c, 0x80000018, 0x8000001f, 0x80000023, 0x20}
    for _ in range(ncmds):
        command, size = struct.unpack_from("<II", value, offset)
        if size < 8 or offset + size > len(value):
            fail("invalid Mach-O load command while rebinding chained import")
        if command in dylib_commands:
            ordinal += 1
            name_offset = struct.unpack_from("<I", value, offset + 8)[0]
            start = offset + name_offset
            end = value.index(0, start, offset + size)
            if value[start:end].decode() == target_library:
                target_ordinal = ordinal
        elif command == 0x80000034:
            fixups = struct.unpack_from("<II", value, offset + 8)
        offset += size
    if target_ordinal is None or fixups is None:
        fail(f"missing {target_library} dependency or chained fixups")
    data_offset, _ = fixups
    _, _, imports_offset, symbols_offset, count, import_format, _ = struct.unpack_from(
        "<7I", value, data_offset)
    if import_format != 1:
        fail(f"unsupported chained import format {import_format}")
    found = 0
    encoded = symbol.encode()
    for index in range(count):
        entry_offset = data_offset + imports_offset + index * 4
        entry = struct.unpack_from("<I", value, entry_offset)[0]
        start = data_offset + symbols_offset + (entry >> 9)
        end = value.index(0, start)
        if value[start:end] == encoded:
            struct.pack_into("<I", value, entry_offset, (entry & ~0xff) | target_ordinal)
            found += 1
    if found != 1:
        fail(f"expected one {symbol} chained import, found {found}")
    return bytes(value)


def normalize_macos15_compatibility(package: Path) -> None:
    """Lower host deployment metadata and remove macOS 27-only FD imports.

    The bridge provides semantic pipe2/dup3 compatibility without requiring
    those macOS 27 libSystem exports. Native ntdll already loads the bridge, so
    only its pipe2 chained-import ordinal is rebound; no load command is added.
    """
    for path in sorted(p for p in package.rglob("*") if is_macho(p)):
        changed = False
        build = run("vtool", "-show-build", str(path))
        minos = re.search(r"^\s*minos\s+(\S+)\s*$", build, re.MULTILINE)
        sdk = re.search(r"^\s*sdk\s+(\S+)\s*$", build, re.MULTILINE)
        version = tuple(map(int, minos.group(1).split("."))) if minos else ()
        if minos and sdk and (version + (0, 0))[:2] > (15, 0):
            temporary = path.with_name(path.name + ".deployment-target-tmp")
            run("vtool", "-set-build-version", "macos", "15.0", sdk.group(1),
                "-replace", "-output", str(temporary), str(path))
            os.chmod(temporary, stat.S_IMODE(path.stat().st_mode))
            os.replace(temporary, path)
            changed = True
        if path.relative_to(package).as_posix() == "lib/wine/aarch64-unix/ntdll.so":
            data = rebind_chained_import(path.read_bytes(), "_pipe2",
                                         "@rpath/libmetalsharp-gem-wine.0.dylib")
            path.write_bytes(data)
            changed = True
        if changed:
            run("codesign", "--force", "--sign", "-", "--timestamp=none", str(path))
        undefined = {line.split()[-1] for line in run("nm", "-u", str(path), check=False).splitlines()
                     if line.split()}
        if "_dup3" in undefined:
            fail(f"macOS 27-only dup3 import survived normalization in {path}")
        if "_pipe2" in undefined:
            imports = run("xcrun", "dyld_info", "-imports", str(path))
            pipe_lines = [line for line in imports.splitlines() if "_pipe2 " in line]
            if not pipe_lines or any("(from libmetalsharp-gem-wine)" not in line
                                     for line in pipe_lines):
                fail(f"pipe2 is not bound to the compatibility bridge in {path}")


def install_selftest(package: Path, foundation: Path, fixture: Path, host: Path,
                     fixture_commit: str) -> None:
    acceptance = package / "lib/wine/aarch64-windows/metalsharp-gem-acceptance.exe"
    if not acceptance.is_file():
        fail("native ARM64 acceptance executable is missing")
    target = package / "share/metalsharp/selftest"
    target.mkdir(parents=True)
    copy_file(fixture, target / fixture.name, 0o644)
    copy_file(host, target / "arm64x_fixture_host.exe", 0o644)
    (target / "fixture-provenance.json").write_text(json.dumps({
        "schema": 1,
        "producerCommit": fixture_commit,
        "dllSha256": sha256(target / fixture.name),
        "hostSha256": sha256(target / "arm64x_fixture_host.exe"),
    }, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def install_metadata(package: Path, foundation: Path, brew: Path, source_epoch: int) -> None:
    licenses = package / "LICENSES"
    licenses.mkdir(parents=True)
    root = Path(__file__).resolve().parents[2]
    copy_file(root / "LICENSE", licenses / "Apache-2.0-MetalSharp.txt", 0o644)
    foundation_licenses = foundation / "licenses"
    if foundation_licenses.is_dir():
        for source in sorted(foundation_licenses.iterdir()):
            if source.is_file():
                copy_file(source, licenses / source.name, 0o644)
    wine_license = package / "share/wine/wine.inf"  # Presence proves Wine share data was staged.
    if not wine_license.is_file():
        fail("Wine data inventory is incomplete")
    for formula, (source_name, destination_name) in LICENSES.items():
        source = brew / "opt" / formula / source_name
        if not source.is_file():
            fail(f"redistributable license is missing: {source}")
        copy_file(source, licenses / destination_name, 0o644)
    copy_file(brew / "opt/zstd/COPYING", licenses / "GPL-2.0-only-Zstandard-COPYING.txt", 0o644)
    os.symlink("wine", package / "bin/metalsharp-wine")
    shutil.copytree(brew / "opt/libx11/share/X11", package / "share/X11", symlinks=True)
    shutil.copytree(brew / "opt/mesa/share/drirc.d", package / "share/drirc.d", symlinks=True)
    icd = package / "share/vulkan/icd.d/MoltenVK_icd.json"
    icd.parent.mkdir(parents=True)
    icd.write_text(json.dumps({"file_format_version": "1.0.0", "ICD": {
        "library_path": "../../../lib/wine/aarch64-unix/libMoltenVK.dylib",
        "api_version": "1.4.0", "is_portability_driver": True,
    }}, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    subprocess.run(["xattr", "-cr", str(package)], check=False)
    for path in sorted(package.rglob("*")):
        if path.is_symlink():
            continue
        os.chmod(path, 0o755 if path.is_dir() or os.access(path, os.X_OK) else 0o644)
        os.utime(path, (source_epoch, source_epoch), follow_symlinks=False)
    os.utime(package, (source_epoch, source_epoch), follow_symlinks=False)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--foundation", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--arm64x-bundle", required=True, type=Path)
    parser.add_argument("--arm64x-host", type=Path,
                        help="prototype-only fallback for a legacy bundle without its bound host")
    parser.add_argument("--acceptance-exe", type=Path,
                        help="prototype-only fallback for a legacy foundation")
    parser.add_argument("--fixture-commit")
    parser.add_argument("--llvm-mingw", required=True, type=Path)
    parser.add_argument("--deps", required=True, type=Path)
    parser.add_argument("--brew-prefix", type=Path, default=Path("/opt/homebrew"))
    parser.add_argument("--source-date-epoch", required=True, type=int)
    args = parser.parse_args()
    if args.output.exists() and any(args.output.iterdir()):
        fail(f"output is not empty: {args.output}")
    args.output.mkdir(parents=True, exist_ok=True)
    fixture, bundled_host, fixture_commit = validate_bundle(args.arm64x_bundle, args.fixture_commit)
    host = bundled_host or args.arm64x_host
    if host is None or not host.is_file():
        fail("ARM64X bundle lacks its bound validation host")
    copy_wine(args.foundation.resolve(), args.output)
    packaged_acceptance = args.output / "lib/wine/aarch64-windows/metalsharp-gem-acceptance.exe"
    if not packaged_acceptance.is_file() and args.acceptance_exe and args.acceptance_exe.is_file():
        copy_file(args.acceptance_exe.resolve(), packaged_acceptance, 0o644)
    runtime = args.output / "lib/wine/aarch64-unix"
    seed_runtime_libraries(runtime, args.brew_prefix.resolve(), args.deps.resolve())
    install_selftest(args.output, args.foundation.resolve(), fixture, host.resolve(), fixture_commit)
    vendor_closure(args.output)
    scrub_embedded_prefixes(args.output)
    normalize_macos15_compatibility(args.output)
    install_metadata(args.output, args.foundation.resolve(), args.brew_prefix.resolve(),
                     args.source_date_epoch)
    print(f"staged relocatable runtime: {args.output}")


if __name__ == "__main__":
    main()
