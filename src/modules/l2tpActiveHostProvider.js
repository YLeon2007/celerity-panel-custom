'use strict';

const L2TP_RUNTIME_UNAVAILABLE = 'L2TP_RUNTIME_UNAVAILABLE';

function runtimeUnavailableError() {
    const error = new Error('The active L2TP runtime is unavailable');
    error.code = L2TP_RUNTIME_UNAVAILABLE;
    return error;
}

function assertServiceMethod(target, methodName) {
    if (!target || typeof target[methodName] !== 'function') {
        throw runtimeUnavailableError();
    }
    return target[methodName];
}

function assertActiveHost(host) {
    if (!host || typeof host !== 'object' || Array.isArray(host)) {
        throw new TypeError('L2TP active host must be an object');
    }
    const runtime = host.runtime;
    if (!runtime || typeof runtime !== 'object' || Array.isArray(runtime)) {
        throw new TypeError('L2TP active host requires a runtime');
    }
    for (const methodName of ['getStatus', 'preflight', 'install', 'getOperation']) {
        if (typeof runtime.service?.[methodName] !== 'function') {
            throw new TypeError(`L2TP active host runtime service requires ${methodName}`);
        }
    }
    if (typeof runtime.stateManagementService?.configureRelay !== 'function') {
        throw new TypeError('L2TP active host runtime requires stateManagementService.configureRelay');
    }
    for (const methodName of ['createUser', 'listUsers', 'updateUser', 'disableUser']) {
        if (typeof runtime.userManagementService?.[methodName] !== 'function') {
            throw new TypeError(
                `L2TP active host runtime userManagementService requires ${methodName}`,
            );
        }
    }
    if (typeof host.loadPanelOverview !== 'function') {
        throw new TypeError('L2TP active host requires loadPanelOverview');
    }
    return host;
}

function createL2tpActiveHostProvider() {
    let activeHost = null;

    return Object.freeze({
        assertActiveHost,
        installActiveHost(host) {
            assertActiveHost(host);
            if (activeHost !== null && activeHost !== host) {
                throw new Error('An L2TP active host is already installed');
            }
            activeHost = host;
            return host;
        },
        clearActiveHost(host) {
            if (activeHost !== host) return false;
            activeHost = null;
            return true;
        },
        getActiveHost() {
            return activeHost;
        },
    });
}

function createL2tpRouteBindings(activeHostProvider) {
    if (!activeHostProvider || typeof activeHostProvider.getActiveHost !== 'function') {
        throw new TypeError('L2TP route bindings require an active host provider');
    }

    const callRuntimeService = (serviceName, methodName, args) => {
        const host = activeHostProvider.getActiveHost();
        const target = host?.runtime?.[serviceName];
        const method = assertServiceMethod(target, methodName);
        return method.apply(target, args);
    };

    const l2tpService = Object.freeze({
        getStatus(...args) {
            return callRuntimeService('service', 'getStatus', args);
        },
        preflight(...args) {
            return callRuntimeService('service', 'preflight', args);
        },
        install(...args) {
            return callRuntimeService('service', 'install', args);
        },
        getOperation(...args) {
            return callRuntimeService('service', 'getOperation', args);
        },
    });
    const stateManagementService = Object.freeze({
        configureRelay(...args) {
            return callRuntimeService(
                'stateManagementService',
                'configureRelay',
                args,
            );
        },
    });
    const userManagementService = Object.freeze({
        createUser(...args) {
            return callRuntimeService('userManagementService', 'createUser', args);
        },
        listUsers(...args) {
            return callRuntimeService('userManagementService', 'listUsers', args);
        },
        updateUser(...args) {
            return callRuntimeService('userManagementService', 'updateUser', args);
        },
        disableUser(...args) {
            return callRuntimeService('userManagementService', 'disableUser', args);
        },
    });

    return Object.freeze({
        l2tpService,
        stateManagementService,
        userManagementService,
        loadPanelOverview(...args) {
            const host = activeHostProvider.getActiveHost();
            const method = assertServiceMethod(host, 'loadPanelOverview');
            return method.apply(host, args);
        },
    });
}

const l2tpActiveHostProvider = createL2tpActiveHostProvider();

module.exports = {
    L2TP_RUNTIME_UNAVAILABLE,
    assertActiveHost,
    createL2tpActiveHostProvider,
    createL2tpRouteBindings,
    l2tpActiveHostProvider,
};
