#!/usr/bin/env python3
"""Exercise workflow ref resolution and the output consumed by Harbor promotion."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import textwrap

workflow = (Path(__file__).parent.parent / "workflows/compose-signed-installer.yml").read_text()
compose = workflow.split("      - name: Compose + push signed installer\n", 1)[1]
compose = compose.split("      - name:", 1)[0]
step_id = re.search(r"^        id: (\w+)$", compose, re.M)[1]
resolve = compose[compose.index('          : "${BASE:?'):compose.index('          sock=')]
emit = re.search(r'^          echo "out=\$OUT" >> "\$GITHUB_OUTPUT"$', compose, re.M)[0]
promote = workflow.split("      - name: Promote the signed installer into Harbor\n", 1)[1]
source = re.search(r"OUT: \$\{\{ steps\.(\w+)\.outputs\.(\w+) \}\}", promote)
assert source and source[1] == step_id, "Harbor must consume the compose step output"

with tempfile.TemporaryDirectory() as temp:
    output = Path(temp) / "output"
    version = "v1.14.0"  # version-literal-ok
    base = "ghcr.io/blockcast/installer:" + version + "-amt-ct6-mroute"
    for override in ("", base + "-candidate-signed"):
        output.write_text("")
        env = dict(os.environ, BASE=base, IMAGER="", EXT="ghcr.io/blockcast/amt-kmod:" + version,
                   OUT=override, GITHUB_OUTPUT=str(output))
        subprocess.run(["bash", "-euc", textwrap.dedent(resolve + emit)], env=env, check=True,
                       stdout=subprocess.DEVNULL)
        outputs = dict(line.split("=", 1) for line in output.read_text().splitlines())
        assert outputs[source[2]] == (override or base + "-signed")
    env["EXT"] = ""
    rejected = subprocess.run(["bash", "-euc", textwrap.dedent(resolve)], env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    assert rejected.returncode != 0 and "pass the extension input explicitly" in rejected.stderr
print("compose output: derived/explicit refs reach Harbor; ambiguous extension rejected")

# extra_kernel_args: the SAME resolver output must feed the imager flag and the
# content assertion, so a kernel argument can never be requested without being
# checked in the UKI, and an empty input must change nothing.
assert "extra_kernel_args:" in workflow.split("  workflow_dispatch:", 1)[1].split("jobs:", 1)[0]
inputs_block = re.split(r"\n      (?=\S)", workflow.split("      extra_kernel_args:\n", 1)[1], 1)[0]
assert "default: ''" in inputs_block, "extra_kernel_args must default to empty (no change to existing builds)"
assert "EXTRA_KARGS: ${{ inputs.extra_kernel_args }}" in compose, "the input must reach the step through env, never interpolated into shell"
assert ".github/scripts/resolve-extra-kernel-args.sh" in compose
docker_run = compose[compose.index("docker run --rm \\\n            -e DOCKER_CONFIG"):compose.index("tee \"$compose_log\"")]
assert '"${extra_karg_flags[@]}"' in docker_run, "the imager must receive the resolved --extra-kernel-arg flags"
assert "--extra-kernel-arg=" in compose
assert '"${expect_karg_flags[@]}"' in compose[compose.index("assert-installer-content.py"):], "the content assertion must check every requested argument"
assert "--expect-cmdline-arg" in compose
print("compose output: extra kernel args are validated, passed to the imager and asserted in the UKI")

# Behaviour, not text: run the workflow's own bash under the step's `set -euo
# pipefail`, from the repo root. A refused extra_kernel_args must STOP the step.
# (A `done < <(resolver)` loop ignores the resolver's exit status under set -e,
# so a refused input would silently build without the argument.)
repo = Path(__file__).parent.parent.parent
loop = textwrap.dedent(compose[compose.index("          extra_karg_flags=()\n"):compose.index("          # DOCKER_CONFIG is required")])
BASE_REF = "ghcr.io/blockcast/installer:v1-x"  # version-literal-ok
DISTINCT = BASE_REF + "-memhp1"
def run_step(script, **env):
    full = {"PATH": os.environ["PATH"], "BASE": BASE_REF, "OUT": DISTINCT, **env}
    return subprocess.run(["bash", "-c", "set -euo pipefail\n" + script], cwd=repo, env=full,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

report = 'echo "flags=${extra_karg_flags[*]-}"; echo "expect=${expect_karg_flags[*]-}"'
r = run_step(loop + report, EXTRA_KARGS="")
assert r.returncode == 0 and r.stdout.splitlines()[-2:] == ["flags=", "expect="], r
r = run_step(loop + report, EXTRA_KARGS="memhp_default_state=online console=ttyS0")
assert r.returncode == 0, r
assert "extra kernel argument: memhp_default_state=online" in r.stdout and "extra kernel argument: console=ttyS0" in r.stdout, "resolved arguments must be logged"
assert r.stdout.splitlines()[-2:] == [
    "flags=--extra-kernel-arg=memhp_default_state=online --extra-kernel-arg=console=ttyS0",
    "expect=--expect-cmdline-arg memhp_default_state=online --expect-cmdline-arg console=ttyS0"], r.stdout
for refused in ("bad;token memhp_default_state=online", "memhp_default_state=online bad;token",
                "memhp_default_state=online -x", "*"):
    r = run_step(loop + report, EXTRA_KARGS=refused)
    assert r.returncode != 0 and "flags=" not in r.stdout, f"refused input {refused!r} did not stop the step: {r}"

# out_tag guard: the derived/explicit <base>-signed tag is the build WITHOUT the
# arguments, so an image carrying them must not be published under it.
r = run_step(loop + report, EXTRA_KARGS="memhp_default_state=online", OUT=BASE_REF + "-signed")
assert r.returncode != 0 and "out_tag must differ" in r.stderr, ("derived/explicit <base>-signed tag must be refused", r)
assert run_step(loop + report, EXTRA_KARGS="   ", OUT=BASE_REF + "-signed").returncode == 0, "blanks resolve to nothing: no guard"
assert run_step(loop + report, EXTRA_KARGS="", OUT=BASE_REF + "-signed").returncode == 0, "no extra args: the derived tag stays allowed"
print("compose output: a refused extra_kernel_args stops the step; extra args cannot reuse the <base>-signed tag")

# The compose job runs on ubuntu-latest, where DOCKER_HOST is NOT set. The socket
# lookup runs under `set -u`, so reading $DOCKER_HOST unguarded killed every run
# with "DOCKER_HOST: unbound variable" before anything was built (main, 11-13..11-27).
sock_at = compose.index("          sock=")
sock_block = textwrap.dedent(compose[sock_at:compose.index("          test -S", sock_at)])
r = run_step(sock_block + 'echo "sock=$sock"')  # no DOCKER_HOST in the environment
assert r.returncode == 0 and r.stdout.strip() == "sock=/var/run/docker.sock", ("DOCKER_HOST unset must fall back to the default socket", r)
r = run_step(sock_block + 'echo "sock=$sock"', DOCKER_HOST="unix:///run/custom/docker.sock")
assert r.returncode == 0 and r.stdout.strip() == "sock=/run/custom/docker.sock", ("a set DOCKER_HOST must still win", r)
print("compose output: an unset DOCKER_HOST falls back to /var/run/docker.sock; a set one is honoured")
