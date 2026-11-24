# Network map: offline frontend build

Use `npm run build:network` and `npm run build:vendor` in a developer checkout with the locked dev dependencies. Neither command runs in the production image. Commit the resulting `public/js/network/dist/` as a unit, remove obsolete chunks, and set the entry and CSS cache keys in the nodes templates to the first 16 characters of the corresponding SHA-256 digests. The mounted loader test checks the keys against the actual files.

For this offline delivery, the complete npm renderer packages were unavailable. The app source, including both lazy views, was compiled twice with esbuild 0.28.2 against renderer code from the compiled chunks in upstream commit `bae9987ed80a75ca7041e7f70b405beecbd789a6`. The two builds matched byte for byte. This is not a claim of byte equality to a fresh npm-based build. World data and the flag font are unchanged upstream blobs.

To reproduce these particular checked-in bytes without network, export that upstream commit to a temporary directory; supply a local `node_modules` containing esbuild 0.28.2, acorn and eslint-scope. Run in a disposable candidate checkout (the recipe replaces its dist directory):

```
node docs/network-map-build/replay-dist.cjs /path/to/upstream /path/to/candidate /path/to/tools/node_modules
```

The replay checks SHA-256 of both renderer inputs, their bindings, and the absence of external JS imports. On TEST use `/panel/nodes?map=modern` or `/panel/nodes?map=classic`; the latter opens the original Rebuild map. In stage 4(b), real links use the existing Rebuild Preview and explicit confirmation for deploy, chain deploy and removal. Opening the map does not submit writes. Saving graph coordinates is separate from applying node configuration. The modern link form is deferred to 4(c).
