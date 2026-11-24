'use strict';
/* Private build receipt, not a release dependency or a substitute for npm ci. */
const { strict: a } = require('node:assert');
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { createRequire } = require('node:module');

const [up, root, cachedNodeModules] = process.argv.slice(2).map(s => path.resolve(s));
const req = createRequire(path.join(cachedNodeModules, 'esbuild/package.json'));
const esbuild = req('esbuild');
const { parse } = req('acorn');
const { analyze } = req('eslint-scope');
const sha = s => createHash('sha256').update(s).digest('hex');
const parseModule = s => parse(s, { ecmaVersion: 'latest', sourceType: 'module', ranges: true });
const chunks = path.join(up, 'public/js/network/dist/chunks');
a.equal(esbuild.version, '0.28.2');

// Keys are the package specifiers in the original view source. Export bindings
// are taken from their use sites in the pinned original compiled view. Byte
// offsets come from top-level AST statements, not textual surgery on minified JS.
const graph = {
    name: 'graph', file: 'graph-TLEX7BUC.js', sha: '4a4839290a85b7f9eb75206110618e3c906d39c71b2a2d7724141dd70ab6058c', boundary: 'Ve',
    packages: { cytoscape: { default: 'sr' }, 'cytoscape-dagre': { default: 'yu' } },
    usages: {
        cytoscape: 'sr({container:', 'cytoscape-dagre': 'sr.use(yu)',
    },
};
const geo = {
    name: 'geo', file: 'geo-4SED53Y2.js', sha: 'dce01bb678f6fe67f9cfe6f622eb6fb3b92a24a8d2afe2c953b4847bf7a6db1c', boundary: 'qn',
    packages: {
        'd3-geo': { geoNaturalEarth1: 'qi', geoPath: 'Ti', geoGraticule10: 'Mi' }, 'd3-selection': { select: 'vn' },
        'd3-zoom': { zoom: 'Wo', zoomIdentity: '_n' }, 'topojson-client': { feature: 'Ir' },
    },
    usages: { 'd3-geo': ['qi().fitExtent(', 'Ti(l)', 'w(Mi())'], 'd3-selection': 'vn(r)', 'd3-zoom': ['Wo().scaleExtent(', '_n.translate('], 'topojson-client': 'Ir(n,n.objects.countries)' },
};

function checkVendor(spec) {
    const text = fs.readFileSync(path.join(chunks, spec.file), 'utf8');
    a.equal(sha(text), spec.sha);
    const ast = parseModule(text);
    const imports = ast.body.filter(n => n.type === 'ImportDeclaration');
    const firstVendor = ast.body[imports.length];
    const boundary = ast.body.find(n => n.type === 'VariableDeclaration' && n.declarations[0].id.name === spec.boundary);
    a.ok(boundary?.declarations[0].init?.arguments[0]?.type === 'CallExpression', `${spec.name} boundary is first application model binding`);
    a.ok(firstVendor.end < boundary.start);
    const body = text.slice(firstVendor.start, boundary.start);
    a.ok(!/\b(?:fetch|XMLHttpRequest|sendBeacon)\b|\/api\/|\bimport\s*\(/.test(body), `${spec.name} vendor region includes an I/O path`);
    const app = text.slice(boundary.start);
    a.ok(app.includes(`${spec.name === 'graph' ? 'nmg-cy' : '/vendor/world-110m.json'}`));
    a.equal((ast.body.at(-1).specifiers || []).map(s => s.exported.name).join(), 'mount');
    const exports = Object.fromEntries(Object.values(spec.packages).flatMap(m => Object.entries(m).map(([ex, sym]) => [sym, ex === 'default' ? sym : ex])));
    spec.code = body + `\nexport { ${Object.entries(exports).map(([sym, ex]) => `${sym} as ${ex}`).join(', ')} };\n`;
    const vendorAst = parseModule(spec.code);
    const scope = analyze(vendorAst, { ecmaVersion: 2022, sourceType: 'module', optimistic: true });
    const globals = [...new Set(scope.globalScope.through.map(r => r.identifier.name))].sort();
    const droppedImports = imports.flatMap(n => n.specifiers.map(x => x.local.name));
    a.deepEqual(globals.filter(n => droppedImports.includes(n)), [], `${spec.name} depends on an app import`);
    const allowedBrowserGlobals = ['window', 'document', 'navigator', 'HTMLElement', 'SVGElement', 'Element', 'self', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'requestAnimationFrame', 'cancelAnimationFrame', 'performance', 'console', 'global', 'CanvasRenderingContext2D', 'WebGLRenderingContext', 'WebGL2RenderingContext', 'ResizeObserver', 'MutationObserver', 'getComputedStyle', 'Node', 'Image', 'DOMMatrix', 'DOMMatrixReadOnly', 'WheelEvent', 'TouchEvent', 'CustomEvent', 'MouseEvent', 'Path2D', 'Blob', 'atob', 'btoa', 'URL', 'URLSearchParams', 'TextEncoder', 'Buffer', 'OffscreenCanvas', 'setImmediate', 'structuredClone', 'WebKitCSSMatrix'];
    const nativeGlobals = new Set(vm.runInNewContext('Object.getOwnPropertyNames(globalThis)'));
    a.deepEqual(globals.filter(n => !nativeGlobals.has(n) && !allowedBrowserGlobals.includes(n)), [], `${spec.name} unexpected free references`);
    // Verify the binding map against the unchanged in-chunk view's import call sites.
    // String checks here supplement (do not replace) module-scope analysis and browser smoke.
    for (const [pkg, patterns] of Object.entries(spec.usages)) {
        for (const use of [].concat(patterns)) a.ok(app.includes(use), `${pkg} binding witness ${use}`);
    }
    console.log(`${spec.name}: exact vendor slice sha256=${sha(body)}; app imports used=0; exports=${Object.values(exports).join(',')}; free globals=${globals.join(',')}`);
}

(async () => {
    for (const spec of [graph, geo]) checkVendor(spec);
    const outdir = path.join(root, 'public/js/network/dist');
    const specs = [graph, geo];
    const resolved = new Set();
    const plugin = {
        name: 'pinned-upstream-renderers',
        setup(build) {
            build.onResolve({ filter: /^(cytoscape(?:-dagre)?|d3-(?:geo|selection|zoom)|topojson-client)$/ }, args => {
                const spec = specs.find(spec => Object.hasOwn(spec.packages, args.path));
                a.equal(args.importer, path.join(root, `public/js/network/src/views/${spec.name}.js`));
                resolved.add(args.path);
                return { path: args.path, namespace: 'pinned-renderer-alias' };
            });
            build.onLoad({ filter: /.*/, namespace: 'pinned-renderer-alias' }, args => {
                const spec = specs.find(spec => Object.hasOwn(spec.packages, args.path));
                const mapping = Object.entries(spec.packages[args.path]).map(([ex, sym]) => {
                    const name = ex === 'default' ? sym : ex;
                    return ex === name ? name : `${name} as ${ex}`;
                });
                return { contents: `export { ${mapping.join(', ')} } from 'renderer:${spec.name}';`, loader: 'js' };
            });
            build.onResolve({ filter: /^renderer:(graph|geo)$/, namespace: 'pinned-renderer-alias' }, args => ({ path: args.path.slice(9), namespace: 'pinned-renderer' }));
            build.onLoad({ filter: /^(graph|geo)$/, namespace: 'pinned-renderer' }, args => ({ contents: specs.find(x => x.name === args.path).code, loader: 'js' }));
        },
    };
    const result = await esbuild.build({
        absWorkingDir: root,
        entryPoints: [path.join(root, 'public/js/network/src/index.js')],
        outdir, bundle: true, splitting: true, format: 'esm', minify: true, target: ['es2020'],
        chunkNames: 'chunks/[name]-[hash]', legalComments: 'none', write: false, metafile: true, logLevel: 'warning',
        plugins: [plugin],
    });
    a.deepEqual([...resolved].sort(), specs.flatMap(spec => Object.keys(spec.packages)).sort());
    for (const output of Object.values(result.metafile.outputs)) {
        a.ok(output.imports.every(i => !i.external), 'release assets must be closed');
    }
    for (const file of result.outputFiles) {
        if (/\/(graph|geo)-[^/]+\.js$/.test(file.path)) {
            const spec = specs.find(s => path.basename(file.path).startsWith(`${s.name}-`));
            const meta = result.metafile.outputs[path.relative(root, file.path)];
            a.ok(meta.inputs[`pinned-renderer:${spec.name}`]?.bytesInOutput > 0);
            a.ok(meta.inputs[`public/js/network/src/views/${spec.name}.js`]?.bytesInOutput > 0);
        }
    }
    fs.rmSync(outdir, { recursive: true, force: true });
    for (const file of result.outputFiles) {
        fs.mkdirSync(path.dirname(file.path), { recursive: true });
        fs.writeFileSync(file.path, file.contents);
        console.log(`${sha(file.contents)}  ${path.relative(root, file.path)}`);
    }
    fs.writeFileSync(path.join(path.dirname(root), `${path.basename(root)}-metafile.json`), JSON.stringify(result.metafile, null, 2) + '\n');
})().catch(err => { console.error(err); process.exitCode = 1; });
