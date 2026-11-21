# Test fixtures

`rebuildRelayDirectHost-chap-epoch.py.gz` is frozen test data, not a runtime
module. It contains the exact historical `src/services/rebuildRelayDirectHost.py`
from `a406947` (Git blob `6b604ba42e0c385731faa269c409b57f48d3f370`). The
`chap-epoch` test needs the old helper's actual CHAP implementation to verify
that it can write before fencing and is refused afterward. Do not update this
fixture to match the current helper or import it from application code.

The test checks the decompressed length (173197 bytes) and SHA-256
(`687c355fe82a73c388c50aff66ba6435f34e48d2281f6a707de30ddf799cc7d0`)
before decoding it as UTF-8. Git is only needed to reproduce the fixture from a
local checkout that already contains the historical blob:

```bash
set -o pipefail
git --no-lazy-fetch --no-replace-objects cat-file blob 6b604ba42e0c385731faa269c409b57f48d3f370 \
  | gzip -n -9 > tests/fixtures/rebuildRelayDirectHost-chap-epoch.py.gz
```

`gzip -n` stores neither a timestamp nor an original filename.
