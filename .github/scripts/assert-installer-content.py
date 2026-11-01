#!/usr/bin/env python3
"""Assert a composed Talos installer really carries our extension, for the
kernel it is going to install.  BLO-34347 AC2b; ported here by BLO-51197.

PROVENANCE AND THE TWO DELIBERATE DIFFERENCES.  Copied from
Blockcast/linux-amt kernel/talos-extension/assert-installer-content.py @
b7c06473 (#228).  That copy only ever ran against STOCK-imager installers and
can no longer compose 6.18.60 (linux-amt#417 skips it), so this workflow is
now the only place the check runs on a deployable installer.  Differences:

  1. The kernel release is read from the UKI's .linux section (the bzImage
     kernel_version header), NOT .uname.  On our custom imager .uname is a
     stale label: the deployable v1.14.0-amt-cve-2026-98432-signed installer
     (sha256:76312951...) carries .uname "6.18.48-talos" around a .linux that
     reads "6.18.60-talos ... Sat Oct 31 17:16:21 UTC 2026".  Asserting .uname
     fails every good custom-kernel installer.  A .uname mismatch is printed
     as a warning only.
  2. --extension-tar reads amt.ko's vermagic straight from the extension image
     (`crane export` output) and uses it as the expected release, so the
     expectation is independent of anything the imager wrote.

WHY THIS EXISTS.  The compose step in build-amt-kmod-talos.yml used to assert
exactly two things: that _out/installer-amd64.tar exists, and that `docker
load` printed a name.  Both of those pass on an installer that composed
*without* the extension, or with an amt.ko built for a different kernel than
the one the installer ships -- which is the BLO-33819 kver-drift class.  That
is the silent direction: it builds green, publishes a plausible tag, and only
fails on a node.  This is the content assertion that closes it.

Deliberately NOT an identity assertion.  See the long comment at the `docker
load` site: the imager tags the composed tarball with the base ref verbatim
(pkg/imager/out.go outInstaller), and mutate.CreatedAt makes the image id fresh
on every run, so both "name differs" and "id differs" are unsatisfiable or
vacuous.  Only content answers the question.

WHERE THE EVIDENCE LIVES.  Validated end to end against a real imager-composed
installer, most recently 2026-09-19.  For Talos >= 1.10 the installer is
"unified": the imager adds ONE layer to installer-base holding a single UKI.

    <installer>.tar                       docker/OCI image tarball
      -> layer                            the ONLY imager-added layer
        -> usr/install/<arch>/vmlinuz.efi PE binary (UKI)
          -> .uname   section             "6.18.48-talos"  <- kernel release
          -> .initrd  section             zstd, TWO concatenated frames
            -> frame 1 -> cpio            init, rootfs.sqsh
            -> frame 2 -> cpio            0.sqsh, 1.sqsh, extensions.yaml,
                                          modules.dep.sqsh

`extensions.yaml` is Talos's own manifest of what was composed in -- it names
every extension layer, and carries a synthetic `modules.dep` entry whose
version IS the kernel release the modules were combined for.  So the two facts
we need are both plaintext, and no squashfs parsing is required.

REPRODUCING THE CONTROL WITHOUT DOCKER (our own composed image is private, so
the control uses a public factory build of the same Talos version).  Nothing
here needs a daemon or a login -- factory.talos.dev is an ordinary OCI
registry, and the schematic id is derived, not remembered:

    # 1. mint the schematic -> id e048aaf4...f238 (deterministic for this yaml)
    curl -sX POST --data-binary @- https://factory.talos.dev/schematics <<'Y'
    customization: {systemExtensions: {officialExtensions: [siderolabs/drbd]}}
    Y
    # 2. index -> amd64 manifest -> layer blobs; tar them up with a
    #    manifest.json naming them, which is the shape `docker save` emits.
    # 3. run this script with --expect-extension drbd --expect-krel <krel>

  POSITIVE: .uname 6.18.48-talos; layers drbd=9.3.3-v1.14.0,  # version-literal-ok
    schematic=e048aaf4..., modules.dep=6.18.48-talos; rc=0.  # version-literal-ok
  NEGATIVE (the control that matters -- an instrument that only ever returns OK
    is not evidence): the SAME real tarball with --expect-extension amt-kmod
    exits 1, "extension 'amt-kmod' is NOT in the composed installer (present:
    ['drbd', 'modules.dep', 'schematic'])".  That artifact is a genuine,
    successfully-composed installer that does not carry our extension -- i.e.
    exactly the thing build-amt-kmod-talos.yml used to tag and publish.
    --expect-krel 6.18.34-talos likewise exits 1 on both the .uname and the
    modules.dep arm.

zstd is not in the Python stdlib.  Rather than add a dependency, --zstd-cmd
takes the decompressor as a command.  The default works anywhere zstd is on
PATH; CI passes a `docker run --entrypoint /usr/bin/unzstd` one-liner against
the imager image, which is ALREADY pulled at that point in the job and ships
zstd/cpio/unsquashfs -- so this step adds no new dependency to the runner.

Whatever you substitute MUST decompress ACROSS frames: the .initrd is two
concatenated zstd frames and the extensions we are looking for are all in the
second.  `zstd -dc` and `unzstd -c` do this; a naive one-shot API call
(python-zstandard's `decompress()`, needing `read_across_frames=True` on a
`stream_reader` instead) returns only frame 1 and every extension reads as
absent -- a false RED that looks exactly like the real defect.
"""

from __future__ import annotations

import argparse
import gzip
import io
import re
import struct
import subprocess
import sys
import tarfile

CPIO_MAGIC = (b"070701", b"070702")


def find_uki(installer_tar: str) -> tuple[str, bytes]:
    """Return (member path, bytes) of usr/install/<arch>/vmlinuz.efi.

    Format-agnostic on purpose.  `docker save`, go-containerregistry's
    tarball.WriteToFile and an OCI layout each name and compress their layer
    blobs differently; rather than encode which one the imager emits (and
    silently miss the file the day it changes), walk every member and try to
    read it as a tar.  Non-tar members -- manifest.json, configs -- just fail
    the open and are skipped.
    """
    with tarfile.open(installer_tar, "r:*") as outer:
        for member in outer:
            if not member.isfile():
                continue
            fh = outer.extractfile(member)
            if fh is None:
                continue
            blob = fh.read()
            if blob[:2] == b"\x1f\x8b":
                try:
                    blob = gzip.decompress(blob)
                except OSError:
                    continue
            try:
                inner = tarfile.open(fileobj=io.BytesIO(blob), mode="r:")
            except tarfile.TarError:
                continue
            with inner:
                for entry in inner:
                    # usr/install/amd64/vmlinuz.efi, with or without a leading ./
                    if entry.isfile() and re.fullmatch(
                        r"\.?/?usr/install/[^/]+/vmlinuz\.efi", entry.name
                    ):
                        payload = inner.extractfile(entry)
                        if payload is not None:
                            return entry.name, payload.read()
    raise SystemExit(
        f"FAIL: no usr/install/<arch>/vmlinuz.efi in any layer of {installer_tar}.\n"
        "      Either the imager did not produce a unified installer, or the "
        "tarball layout changed."
    )


def pe_sections(blob: bytes) -> dict[str, bytes]:
    """Map PE section name -> raw bytes.  First occurrence wins.

    A Talos UKI repeats .profile/.cmdline/.pcrsig for the secondary profiles;
    the first copy is the one describing the image itself.

    Slices to VirtualSize, not SizeOfRawData.  SizeOfRawData is file-aligned,
    so it overshoots: on the measured control .initrd was 97188864 raw against
    97188423 virtual -- 441 bytes of zero padding.  Handing those extra bytes
    to `zstd -d` makes it report trailing garbage and exit NON-ZERO after
    having written perfectly good output, which would have failed this check
    on a healthy installer.
    """
    pe = struct.unpack_from("<I", blob, 0x3C)[0]
    if blob[pe : pe + 4] != b"PE\0\0":
        raise SystemExit("FAIL: vmlinuz.efi is not a PE binary (not a UKI?)")
    nsec = struct.unpack_from("<H", blob, pe + 6)[0]
    optsz = struct.unpack_from("<H", blob, pe + 20)[0]
    table = pe + 24 + optsz
    out: dict[str, bytes] = {}
    for i in range(nsec):
        entry = blob[table + 40 * i : table + 40 * (i + 1)]
        name = entry[:8].rstrip(b"\0").decode("ascii", "replace")
        vsz, _va, rsz, ra = struct.unpack_from("<IIII", entry, 8)
        size = min(vsz, rsz) if 0 < vsz < rsz else rsz
        out.setdefault(name, blob[ra : ra + size])
    return out


def bzimage_release(linux: bytes) -> str:
    """Kernel release from a bzImage's setup header (Documentation/arch/x86/
    boot.rst): "HdrS" at 0x202, kernel_version pointer at 0x20E, +0x200."""
    if linux[0x202:0x206] != b"HdrS":
        raise SystemExit("FAIL: UKI .linux is not an x86 bzImage (no HdrS)")
    off = struct.unpack_from("<H", linux, 0x20E)[0] + 0x200
    return linux[off : off + 256].split(b"\0", 1)[0].split(b" ", 1)[0].decode()


def extension_vermagic(ext_tar: str) -> str:
    """Release amt.ko was built for, from a flattened extension image tar.

    Both the install path (usr/lib/modules/<krel>/extra/amt.ko) and the
    module's own vermagic must name the same release, and exactly one amt.ko
    may exist -- otherwise "which one" is a guess."""
    found = []
    with tarfile.open(ext_tar, "r:*") as t:
        for m in t:
            hit = re.fullmatch(r"\.?/?(?:rootfs/)?usr/lib/modules/([^/]+)/extra/amt\.ko",
                               m.name)
            if hit and m.isfile():
                vm = re.search(rb"vermagic=([^\s\0]+)", t.extractfile(m).read())
                found.append((m.name, hit[1], vm[1].decode() if vm else None))
    if len(found) != 1:
        raise SystemExit(f"FAIL: expected exactly one amt.ko in {ext_tar}, found {found}")
    name, path_krel, vermagic = found[0]
    print(f"extension amt.ko: {name} vermagic={vermagic}")
    if vermagic != path_krel:
        raise SystemExit(f"FAIL: amt.ko vermagic {vermagic!r} != its install path "
                         f"release {path_krel!r}")
    return vermagic


def cpio_members(stream: bytes):
    """Yield (name, bytes) across ALL concatenated cpio archives in `stream`.

    The decompressed initrd is archive-1 ++ archive-2, so a walker that stops
    at the first TRAILER!!! never reaches extensions.yaml -- it resumes at the
    next 070701 magic instead.
    """
    i = 0
    while True:
        while i + 6 <= len(stream) and stream[i : i + 6] not in CPIO_MAGIC:
            i += 1  # skip inter-archive NUL padding
        if i + 110 > len(stream):
            return
        head = stream[i : i + 110]
        field = lambda off: int(head[off : off + 8], 16)  # noqa: E731
        fsz, nsz = field(54), field(94)
        name = stream[i + 110 : i + 110 + nsz - 1].decode("utf-8", "replace")
        data_at = (i + 110 + nsz + 3) & ~3
        if name != "TRAILER!!!":
            yield name, stream[data_at : data_at + fsz]
        i = (data_at + fsz + 3) & ~3


def parse_extensions_yaml(text: str) -> list[tuple[str, str]]:
    """Return [(name, version)] from Talos's generated extensions.yaml.

    Machine-generated with a fixed shape, so a targeted regex beats taking a
    PyYAML dependency: a `name:` line immediately followed by a `version:` line
    is a metadata block and nothing else in the file has that shape.
    """
    return re.findall(r"^[ \t]*name:[ \t]*(\S+)[ \t]*$\n[ \t]*version:[ \t]*(\S+)[ \t]*$",
                      text, re.M)


def main() -> int:
    # Plain help formatting: linux-amt's formatter_class kwarg trips the
    # egress entropy detector (BLO-51197), and only --help layout depended on it.
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("installer_tar")
    ap.add_argument("--expect-extension", required=True,
                    help="metadata.name of the extension that MUST be present, e.g. amt-kmod")
    ap.add_argument("--expect-krel",
                    help="kernel release amt.ko was built for, e.g. <kver>-talos")
    ap.add_argument("--extension-tar",
                    help="flattened extension image (crane export); its amt.ko "
                         "vermagic becomes / must equal the expected release")
    ap.add_argument("--zstd-cmd", default="zstd -dc",
                    help="command decompressing stdin->stdout (default: %(default)s)")
    args = ap.parse_args()
    if not (args.expect_krel or args.extension_tar):
        ap.error("need --expect-krel and/or --extension-tar")
    # Collected, not raised, so one red run shows every arm that disagrees.
    failures: list[str] = []
    if args.extension_tar:
        vermagic = extension_vermagic(args.extension_tar)
        if args.expect_krel and args.expect_krel != vermagic:
            failures.append(f"--expect-krel is {args.expect_krel!r} but the "
                            f"extension's amt.ko is built for {vermagic!r}")
        args.expect_krel = args.expect_krel or vermagic

    path, uki = find_uki(args.installer_tar)
    print(f"UKI: {path} ({len(uki)} bytes)")
    sections = pe_sections(uki)
    for needed in (".linux", ".initrd"):
        if needed not in sections:
            raise SystemExit(f"FAIL: UKI has no {needed} section; sections="
                             f"{sorted(sections)}")

    krel = bzimage_release(sections[".linux"])
    print(f".linux (installer kernel release): {krel}")
    uname = sections.get(".uname", b"").rstrip(b"\0").decode().strip()
    if uname != krel:
        print(f"warning: UKI .uname {uname!r} != .linux {krel!r}; .uname is a "
              "label, .linux is what boots (BLO-51197)", file=sys.stderr)

    proc = subprocess.run(args.zstd_cmd, shell=True, input=sections[".initrd"],
                          stdout=subprocess.PIPE)
    if not proc.stdout:
        raise SystemExit(
            f"FAIL: '{args.zstd_cmd}' produced no output for the .initrd section "
            f"(rc={proc.returncode}). This is a TOOLING failure, not a verdict on "
            "the installer -- do not read it as 'the extension is missing'.")
    if proc.returncode != 0:
        print(f"note: decompressor exited {proc.returncode} but produced "
              f"{len(proc.stdout)} bytes; continuing", file=sys.stderr)

    manifest = None
    for name, data in cpio_members(proc.stdout):
        if name.lstrip("./") == "extensions.yaml":
            manifest = data.decode("utf-8", "replace")
            break

    # A truncated decompression and a genuinely extension-less installer look
    # identical from here -- both yield no extensions.yaml. Only the first is a
    # tooling problem, and blaming the installer for it would send the next
    # reader after the wrong thing entirely.
    if manifest is None and proc.returncode != 0:
        raise SystemExit(
            f"FAIL: no extensions.yaml found AND the decompressor exited "
            f"{proc.returncode} -- the initramfs was probably only partially "
            "decompressed. Fix '--zstd-cmd' before believing anything about the "
            "installer's contents.")

    # (1) kver drift: the kernel this installer will install must be the kernel
    #     amt.ko was compiled against.  A MODVERSIONS module against any other
    #     release does not load -- BLO-33819.
    if krel != args.expect_krel:
        failures.append(
            f"installer ships kernel {krel!r} but the extension was built for "
            f"{args.expect_krel!r} -- amt.ko will not load (kver drift, BLO-33819)")

    if manifest is None:
        # No extensions section at all: the imager composed a bare installer.
        failures.append(
            "no extensions.yaml in the initramfs -- the composed installer carries "
            "NO system extensions at all, so amt.ko is absent")
    else:
        layers = parse_extensions_yaml(manifest)
        print("extensions.yaml layers: " +
              (", ".join(f"{n}={v}" for n, v in layers) or "<none>"))
        names = {n for n, _ in layers}

        # (2) presence: the extension must actually be in the composed image.
        if args.expect_extension not in names:
            failures.append(
                f"extension {args.expect_extension!r} is NOT in the composed "
                f"installer (present: {sorted(names) or 'none'})")

        # (3) the combined modules.dep must be for the same kernel.  Distinct
        #     from (1): .uname is what the UKI boots, this is what the modules
        #     were indexed against.  They can disagree.
        moddep = [v for n, v in layers if n == "modules.dep"]
        if not moddep:
            failures.append("extensions.yaml has no modules.dep layer -- the "
                            "extension's modules were never indexed")
        elif moddep[0] != args.expect_krel:
            failures.append(
                f"modules.dep was combined for kernel {moddep[0]!r}, expected "
                f"{args.expect_krel!r}")

    if failures:
        print("\nFAIL: composed installer did not pass the content assertion:",
              file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        return 1

    print(f"OK: composed installer carries {args.expect_extension} for kernel "
          f"{args.expect_krel}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
