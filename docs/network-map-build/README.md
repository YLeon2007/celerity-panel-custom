# Network map: offline frontend build

Use `npm run build:network` and `npm run build:vendor` in a developer checkout with the locked dev dependencies. Neither command runs in the production image. Commit the resulting `public/js/network/dist/` as a unit, remove obsolete chunks, and set the entry and CSS cache keys in the nodes templates to the first 16 characters of the corresponding SHA-256 digests. The mounted loader test checks the keys against the actual files.

For this offline delivery, the complete npm renderer packages were unavailable. The app source, including both lazy views, was compiled twice with esbuild 0.28.2 against renderer code from the compiled chunks in upstream commit `bae9987ed80a75ca7041e7f70b405beecbd789a6`. The two builds matched byte for byte. This is not a claim of byte equality to a fresh npm-based build. World data and the flag font are unchanged upstream blobs.

To reproduce these particular checked-in bytes without network, export that upstream commit to a temporary directory; supply a local `node_modules` containing esbuild 0.28.2, acorn and eslint-scope. Run in a disposable candidate checkout (the recipe replaces its dist directory):

```
node docs/network-map-build/replay-dist.cjs /path/to/upstream /path/to/candidate /path/to/tools/node_modules
```

The replay checks SHA-256 of both renderer inputs, their bindings, and the absence of external JS imports.

In Rebuild, `/panel/nodes?map=modern` opens the modern map. An authorized session can use **Add Link** to open the new-link editor. Opening or canceling the editor, switching map views, and polling do not save a link. Submitting saves a draft; applying it requires the shared Rebuild Preview and explicit confirmation. Canceling that preview leaves an acknowledged draft saved. A draft save that could not be confirmed is not retried automatically. The editor keeps its entered values on refresh and selection changes.

Existing-link edits remain available through `/panel/nodes?map=classic`, the original Rebuild map. Modern deploy, chain deploy and removal still require the shared Rebuild Preview and explicit confirmation. Saving graph coordinates is separate from applying node configuration. A read-only modern map does not expose link actions or position saving.
