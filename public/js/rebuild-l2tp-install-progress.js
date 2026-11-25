(() => {
    'use strict';
    const ranges = new Map(Object.entries({ preflight: [0, 0], reserve: [10, 10], foreignCleanup: [0, 64], preparePackages: [20, 49],
        prepare: [50, 50], install: [65, 65], restart: [80, 80], verify: [92, 92], unknown: [10, 92] }));
    function start(page, nodeId, consented) {
        if (typeof nodeId !== 'string' || !/^[a-f0-9]{24}(?![\s\S])/.test(nodeId)) return;
        const root = page.querySelector(`[data-install-progress][data-progress-node="${nodeId}"]`);
        if (!root) return;
        const expected = `/panel/rebuild/relays/${nodeId}/l2tp/install/progress`;
        if (root.dataset.progressUrl !== expected) return;
        const label = root.querySelector('[data-progress-text]'), bar = root.querySelector('progress');
        const words = JSON.parse(root.dataset.progressWords);
        const controller = new AbortController();
        let active = true, pending = false, last = 0;
        function show(stage, percent) {
            label.textContent = words[stage];
            bar.value = percent;
        }
        show(consented === true ? 'foreignCleanup' : 'preflight', 0);
        root.hidden = false;
        const timer = setInterval(async () => {
            if (!active || pending) return;
            pending = true;
            try {
                const response = await fetch(expected, { method: 'GET', credentials: 'same-origin', cache: 'no-store',
                    redirect: 'error', signal: controller.signal });
                if (!response.ok) return;
                const body = await response.json();
                if (!active || !root.isConnected || body?.nodeId !== nodeId) return;
                const p = body.installProgress, range = ranges.get(p?.stage);
                if (!range || p.stage === 'preflight' || (p.stage === 'foreignCleanup' && consented !== true)
                    || Object.keys(p).length !== 3 || !Object.hasOwn(words, p.stage)
                    || !Number.isInteger(p.percent) || p.percent < Math.max(last, range[0]) || p.percent > range[1]
                    || typeof p.at !== 'string' || !Number.isFinite(Date.parse(p.at))) return;
                last = p.percent;
                show(p.stage, last);
            } catch { /* A GET failure says nothing about the active POST. */ }
            finally { pending = false; }
        }, 2000);
        return () => {
            active = false;
            clearInterval(timer);
            controller.abort();
            root.hidden = true;
        };
    }
    window.rebuildL2tpInstallProgress = Object.freeze({ start });
})();
