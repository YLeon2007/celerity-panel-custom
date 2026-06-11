const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function loadI18nWithLocales(localeMap) {
    const source = fs.readFileSync(path.join(__dirname, '../src/middleware/i18n.js'), 'utf8');
    const fakePath = {
        ...path,
        join: (...parts) => {
            const filename = parts[parts.length - 1];
            if (Object.prototype.hasOwnProperty.call(localeMap, filename)) {
                return `/locales/${filename}`;
            }
            return path.join(...parts);
        },
    };
    const fakeFs = {
        existsSync: filePath => Object.prototype.hasOwnProperty.call(localeMap, path.basename(filePath)),
        readFileSync: filePath => localeMap[path.basename(filePath)],
    };
    const module = { exports: {} };

    vm.runInNewContext(source, {
        require: name => {
            if (name === 'fs') return fakeFs;
            if (name === 'path') return fakePath;
            return require(name);
        },
        module,
        exports: module.exports,
        __dirname: '/app/src/middleware',
        console,
    }, { filename: 'i18n.js' });

    return module.exports;
}

const i18n = loadI18nWithLocales({
    'en.json': JSON.stringify({
        dashboard: {
            title: 'Dashboard',
        },
    }),
    'ru.json': JSON.stringify({
        dashboard: {},
    }),
    'zh-CN.json': JSON.stringify({
        dashboard: {},
    }),
});

assert.strictEqual(
    i18n.t('dashboard.title', 'ru'),
    'Dashboard',
    'Russian locale should fall back to English when a key is missing'
);
assert.strictEqual(
    i18n.getLocale('ru').dashboard.title,
    'Dashboard',
    'Merged Russian locale should include English fallback values'
);
assert.strictEqual(
    i18n.t('dashboard.title', 'zh-CN'),
    'Dashboard',
    'Chinese locale should fall back to English when a key is missing'
);
assert.strictEqual(
    i18n.getLocale('zh-CN').dashboard.title,
    'Dashboard',
    'Merged Chinese locale should include English fallback values'
);

console.log('i18n fallback tests passed');
