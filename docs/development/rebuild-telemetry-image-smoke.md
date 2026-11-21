# Rebuild telemetry smoke on the final local image

Run this from the clean integrated checkout used for the **final step2 backend build**, not against an earlier tag that happens to contain some of the same code. Use the immutable local image ID recorded by the build (e.g. `--iidfile`), and retain that ID and the exact source revision with the smoke output.

```sh
# IMAGE_ID is the just-built final local image's ID (sha256:…).
: "${IMAGE_ID:?Use the final step2 image ID from the build}"
podman --remote=false run --rm --pull=never --network=none --read-only --timeout=30 \
  --workdir /tmp --tmpfs /app/logs:rw,nodev,nosuid,noexec \
  -v "$PWD/src/services/tests:/smoke:ro" --entrypoint /usr/bin/env "$IMAGE_ID" \
  -i PATH=/usr/local/bin:/usr/bin:/bin C3_TELEMETRY_IMAGE=1 LOG_LEVEL=error \
  PANEL_DOMAIN=fixture.invalid ACME_EMAIL=fixture@fixture.invalid \
  ENCRYPTION_KEY=fixture-fixture-fixture-fixture-only SESSION_SECRET=fixture-fixture-fixture-fixture-only \
  node --test /smoke/rebuildTelemetryImage.test.js
```

Only the test and its in-memory request helper are loaded from `/smoke`. No host source, dependency tree, `.env`, panel data, socket, or credentials are mounted. The smoke imports the packaged Express router, service, coordinator, Mongoose model, key preparation, and profile composer from `/app`. Match the printed `/app` file hashes (remove the `/app/` prefix) against the same files in the integrated checkout. The smoke mounts the real router with the real auth and CSRF middleware and a synthetic session; it does not boot `index.js`, start a listener, contact Mongo/Redis, or run Xray. The database and profile transport are in-memory fixtures.

Expected: both **Preview / Apply** and **Preview Remove / DELETE** pass. All five health/timestamp fields change between confirmation requests, and the surviving row changes again during preparation and persistence reads. Tickets remain valid. Working-link port drift, observed profile drift, and protected MAIN client drift each return their specific HTTP 409 before writes. The original ticket succeeds after the drift is restored. A source control run with the same harness on `cf5a6cc^` should instead fail with `REBUILD_LINK_CHANGED` when health changes between inventory and preparation. This does not attribute any historical deployment failure.

## Build inputs

The tracked runtime recipe is the root `Dockerfile` with the root `.dockerignore`: Node 20 Alpine, `/app`, runtime APKs (`mongodb-tools`, `libstdc++`, `libgcc`, `curl`), production dependencies from `package-lock.json`, then the filtered source copy. Tests and docs are excluded from packaging. For an offline build, use verified local base/layer cache or the parent's offline APK/npm inputs; `--pull=never --network=none` alone does not supply missing dependencies. Record the actual offline recipe and final image ID. The older local `rebuild-dcbe29e` image history shows `apk add` with `--no-network` and `npm ci --omit=dev` with `--offline` and an explicit cache. It is evidence of an earlier cached build, not a verified current recipe or a substitute for step2; neither is `classic-e303ee7`.
