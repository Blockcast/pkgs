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
