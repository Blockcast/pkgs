#!/usr/bin/env python3
"""Fixture self-check for the two readers assert-installer-content.py adds over
linux-amt's copy (BLO-51197): .linux release and extension amt.ko vermagic.
The end-to-end reader was checked against the real deployable installer; see
BLO-51197. Stdlib only."""
import importlib.util, io, struct, tarfile, tempfile
from pathlib import Path

spec = importlib.util.spec_from_file_location("a", Path(__file__).with_name("assert-installer-content.py"))
a = importlib.util.module_from_spec(spec); spec.loader.exec_module(a)

def bzimage(ver: bytes) -> bytes:
    b = bytearray(0x400)
    b[0x202:0x206] = b"HdrS"
    struct.pack_into("<H", b, 0x20E, 0x100)          # -> 0x300
    b[0x300:0x300 + len(ver)] = ver + b"\0"
    return bytes(b)

assert a.bzimage_release(bzimage(b"6.18.60-talos (root@x) #1 SMP")) == "6.18.60-talos"
try: a.bzimage_release(b"\0" * 0x400); raise AssertionError("non-bzImage accepted")
except SystemExit: pass

def ext(tmp, *kos):
    p = Path(tmp) / f"e{len(list(Path(tmp).iterdir()))}.tar"
    with tarfile.open(p, "w") as t:
        for krel, vm in kos:
            data = b"x\0vermagic=" + vm.encode() + b" SMP mod_unload modversions \0"
            ti = tarfile.TarInfo(f"rootfs/usr/lib/modules/{krel}/extra/amt.ko"); ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return str(p)

with tempfile.TemporaryDirectory() as tmp:
    assert a.extension_vermagic(ext(tmp, ("6.18.60-talos", "6.18.60-talos"))) == "6.18.60-talos"
    for bad in [(("6.18.60-talos", "6.18.48-talos"),),            # path vs vermagic
                (),                                                # no amt.ko
                (("6.18.60-talos",) * 2, ("6.18.48-talos",) * 2)]: # ambiguous
        try: a.extension_vermagic(ext(tmp, *bad)); raise AssertionError(f"accepted {bad}")
        except SystemExit: pass

# --expect-cmdline-arg (memory-hotplug rollout): the signed UKI's own .cmdline
# must carry each requested kernel argument as a WHOLE token.
def pe(secs):
    """Minimal PE: DOS e_lfanew -> PE header (no optional header) -> section
    table -> section bodies, enough for pe_sections()."""
    hdr = bytearray(0x80); struct.pack_into("<I", hdr, 0x3C, 0x80)
    peh = bytearray(24); peh[0:4] = b"PE\0\0"; struct.pack_into("<H", peh, 6, len(secs))
    table = bytearray(40 * len(secs)); start = 0x80 + 24 + len(table); body = b""
    for i, (name, data) in enumerate(secs):
        table[40 * i:40 * (i + 1)] = (name.ljust(8, b"\0") + struct.pack("<IIII", len(data), 0, len(data), start + len(body)) + b"\0" * 16)
        body += data
    return bytes(hdr) + bytes(peh) + bytes(table) + body

CMD = b"talos.platform=nocloud console=tty0 slab_nomerge memhp_default_state=online\n\0"
sec = a.pe_sections(pe([(b".cmdline", CMD), (b".linux", b"k")]))
assert a.cmdline_tokens(sec) == ["talos.platform=nocloud", "console=tty0", "slab_nomerge", "memhp_default_state=online"]
assert a.missing_cmdline_args(sec, ["memhp_default_state=online", "slab_nomerge"]) == []
assert a.missing_cmdline_args(sec, ["memhp_default_state=offline"]) == ["memhp_default_state=offline"]
assert a.missing_cmdline_args(sec, ["state=online"]) == ["state=online"], "substring must not satisfy a whole-token check"
assert a.missing_cmdline_args(a.pe_sections(pe([(b".linux", b"k")])), ["x=1"]) == ["x=1"], "no .cmdline section: everything is missing"
# A UKI repeats .cmdline for secondary profiles; the FIRST copy describes the image itself.
two = a.pe_sections(pe([(b".cmdline", b"a=1\0"), (b".cmdline", b"memhp_default_state=online\0")]))
assert a.missing_cmdline_args(two, ["memhp_default_state=online"]) == ["memhp_default_state=online"]
assert a.cmdline_failures(sec, ["memhp_default_state=online"]) == []
msgs = a.cmdline_failures(sec, ["memhp_default_state=offline"])
assert len(msgs) == 1 and "'memhp_default_state=offline' is NOT in the UKI .cmdline" in msgs[0]
src = Path(__file__).with_name("assert-installer-content.py").read_text()
assert "failures.extend(cmdline_failures(sections, args.expect_cmdline_arg))" in src, "main() must feed the cmdline check into the collected failures"
assert "if args.expect_cmdline_arg:" in src
ns = a.build_parser().parse_args(["x.tar", "--expect-extension", "e",
                                  "--expect-cmdline-arg", "a=1", "--expect-cmdline-arg", "b=2"])
assert ns.expect_cmdline_arg == ["a=1", "b=2"], "every requested kernel argument must be checked, not just the last"
assert a.build_parser().parse_args(["x.tar", "--expect-extension", "e"]).expect_cmdline_arg == []

# End to end through the real CLI on a synthetic installer tar: the wiring in
# main(), the exit code, and that the UKI cmdline is never echoed into the log.
import subprocess, sys
def cpio(name: str, data: bytes) -> bytes:
    nm = name.encode() + b"\0"
    fields = (1, 0o100644, 0, 0, 1, 0, len(data), 0, 0, 0, 0, len(nm), 0)
    pad = lambda b: b + b"\0" * (-len(b) % 4)  # noqa: E731
    return pad(b"070701" + b"".join(b"%08X" % v for v in fields) + nm) + pad(data)

KREL = "6.18.60-talos"
EXTYAML = f"name: amt-kmod\nversion: v1\nname: modules.dep\nversion: {KREL}\n".encode()
INITRD = cpio("extensions.yaml", EXTYAML) + cpio("TRAILER!!!", b"")

def installer_tar(tmp, cmdline):
    secs = [(b".linux", bzimage(KREL.encode() + b" (root@x) #1")), (b".initrd", INITRD)]
    if cmdline is not None:
        secs.append((b".cmdline", cmdline))
    inner = io.BytesIO()
    with tarfile.open(fileobj=inner, mode="w") as t:
        uki = pe(secs); ti = tarfile.TarInfo("usr/install/amd64/vmlinuz.efi"); ti.size = len(uki)
        t.addfile(ti, io.BytesIO(uki))
    path = Path(tmp) / f"inst{len(list(Path(tmp).iterdir()))}.tar"
    with tarfile.open(path, "w") as t:
        blob = inner.getvalue(); ti = tarfile.TarInfo("layer.tar"); ti.size = len(blob)
        t.addfile(ti, io.BytesIO(blob))
    return str(path)

def run_cli(tar, *extra):
    return subprocess.run([sys.executable, str(Path(__file__).with_name("assert-installer-content.py")),
                           tar, "--expect-extension", "amt-kmod", "--expect-krel", KREL,
                           "--zstd-cmd", "cat", *extra], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

CANARY = b"talos.platform=nocloud per-node-canary=SHOULD-NOT-REACH-THE-LOG memhp_default_state=online\0"
with tempfile.TemporaryDirectory() as tmp:
    t_ok = installer_tar(tmp, CANARY); t_none = installer_tar(tmp, None)
    r = run_cli(t_ok); assert r.returncode == 0, ("no cmdline check requested must still pass", r)
    r = run_cli(t_ok, "--expect-cmdline-arg", "memhp_default_state=online")
    assert r.returncode == 0, r
    assert "SHOULD-NOT-REACH-THE-LOG" not in r.stdout + r.stderr, "the UKI cmdline must not be echoed into the job log"
    for missing in (["memhp_default_state=offline"], ["state=online"],
                    ["memhp_default_state=online", "slab_nomerge"]):
        r = run_cli(t_ok, *[x for m in missing for x in ("--expect-cmdline-arg", m)])
        assert r.returncode == 1 and "NOT in the UKI .cmdline" in r.stderr, (missing, r)
        assert "SHOULD-NOT-REACH-THE-LOG" not in r.stdout + r.stderr
    r = run_cli(t_none, "--expect-cmdline-arg", "memhp_default_state=online")
    assert r.returncode == 1 and "NOT in the UKI .cmdline" in r.stderr, ("a UKI without .cmdline must fail", r)
print("assert-installer-content cmdline check: ok")
print("assert-installer-content readers: ok")
