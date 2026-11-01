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
print("assert-installer-content readers: ok")
