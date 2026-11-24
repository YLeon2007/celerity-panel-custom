#!/usr/bin/env node
/**
 * Builds the network map frontend bundle.
 *
 * Output is an ES module entry (public/js/network/dist/index.js) plus
 * content-hashed lazy chunks for the heavy views (graph, geo). The dist
 * directory is replaced only after compilation succeeds, to remove stale chunks.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const esbuild = require('esbuild');

const root = path.join(__dirname, '..');
const outdir = path.join(root, 'public/js/network/dist');

async function main() {
    const result = await esbuild.build({
        absWorkingDir: root,
        entryPoints: [path.join(root, 'public/js/network/src/index.js')],
        outdir,
        bundle: true,
        splitting: true,
        format: 'esm',
        minify: true,
        target: ['es2020'],
        chunkNames: 'chunks/[name]-[hash]',
        legalComments: 'none',
        write: false,
        metafile: true,
        logLevel: 'warning',
    });

    fs.rmSync(outdir, { recursive: true, force: true });
    for (const file of result.outputFiles) {
        fs.mkdirSync(path.dirname(file.path), { recursive: true });
        fs.writeFileSync(file.path, file.contents);
    }

    const outputs = Object.entries(result.metafile.outputs)
        .map(([file, info]) => `  ${path.relative(root, file).replace(/\\/g, '/')}  ${(info.bytes / 1024).toFixed(1)} KB`);
    console.log(`network bundle built:\n${outputs.join('\n')}`);
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
