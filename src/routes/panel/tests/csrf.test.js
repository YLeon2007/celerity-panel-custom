'use strict';

const assert = require('node:assert/strict');
const test = require('node:test');

const {
    issuePanelCsrfToken,
    requirePanelCsrf,
} = require('../csrf');

const HELPERS_SOURCE = require('node:fs').readFileSync(
    require('node:path').resolve(__dirname, '../helpers.js'),
    'utf8',
);

test('panel render exposes the session CSRF token to every template', () => {
    // Templates like nodes.ejs need the token for session-authenticated API calls
    // (e.g. POST /api/cascade/topology/deploy); render() must pass it explicitly
    // because it compiles templates with a curated data object, not res.locals.
    assert.match(HELPERS_SOURCE, /csrfToken: res\.locals\.csrfToken \|\| ''/);
});

function createResponse() {
    return {
        statusCode: null,
        body: null,
        status(code) {
            this.statusCode = code;
            return this;
        },
        json(body) {
            this.body = body;
            return this;
        },
    };
}

test('issuePanelCsrfToken stores an independent 256-bit token in each authenticated session', () => {
    const firstRequest = { session: { authenticated: true } };
    const secondRequest = { session: { authenticated: true } };

    const firstToken = issuePanelCsrfToken(firstRequest);
    const repeatedToken = issuePanelCsrfToken(firstRequest);
    const secondToken = issuePanelCsrfToken(secondRequest);

    assert.match(firstToken, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(repeatedToken, firstToken);
    assert.equal(firstRequest.session.panelCsrfToken, firstToken);
    assert.match(secondToken, /^[A-Za-z0-9_-]{43}$/);
    assert.notEqual(secondToken, firstToken);
});

test('issuePanelCsrfToken refuses to create a token without an authenticated session', () => {
    for (const request of [{}, { session: {} }, { session: { authenticated: false } }]) {
        assert.throws(
            () => issuePanelCsrfToken(request),
            error => error.code === 'CSRF_AUTH_REQUIRED' && error.statusCode === 403,
        );
    }
});

test('requirePanelCsrf accepts an unsafe request with the session token in the header', () => {
    const request = {
        method: 'POST',
        headers: {},
        session: { authenticated: true },
    };
    request.headers['x-csrf-token'] = issuePanelCsrfToken(request);
    const response = createResponse();
    let nextCalls = 0;

    requirePanelCsrf(request, response, () => { nextCalls += 1; });

    assert.equal(nextCalls, 1);
    assert.equal(response.statusCode, null);
    assert.equal(response.body, null);
});

test('requirePanelCsrf accepts an unsafe request with the session token in the body', () => {
    const request = {
        method: 'PUT',
        headers: {},
        body: {},
        session: { authenticated: true },
    };
    request.body._csrf = issuePanelCsrfToken(request);
    const response = createResponse();
    let nextCalls = 0;

    requirePanelCsrf(request, response, () => { nextCalls += 1; });

    assert.equal(nextCalls, 1);
    assert.equal(response.statusCode, null);
    assert.equal(response.body, null);
});

test('requirePanelCsrf rejects an unsafe request without an authenticated session', () => {
    const response = createResponse();
    let nextCalls = 0;

    requirePanelCsrf(
        { method: 'DELETE', headers: {}, session: {} },
        response,
        () => { nextCalls += 1; },
    );

    assert.equal(nextCalls, 0);
    assert.equal(response.statusCode, 403);
    assert.deepEqual(response.body, {
        error: 'CSRF validation failed',
        code: 'CSRF_AUTH_REQUIRED',
    });
});

test('requirePanelCsrf returns structured 403 responses for absent and mismatched tokens', () => {
    for (const submittedToken of [undefined, 'wrong-token']) {
        const request = {
            method: 'PATCH',
            headers: {},
            session: { authenticated: true },
        };
        issuePanelCsrfToken(request);
        if (submittedToken !== undefined) {
            request.headers['x-csrf-token'] = submittedToken;
        }
        const response = createResponse();
        let nextCalls = 0;

        requirePanelCsrf(request, response, () => { nextCalls += 1; });

        assert.equal(nextCalls, 0);
        assert.equal(response.statusCode, 403);
        assert.deepEqual(response.body, {
            error: 'CSRF validation failed',
            code: 'CSRF_TOKEN_INVALID',
        });
    }
});

test('requirePanelCsrf rejects a valid token sent from a cross-origin page', () => {
    const request = {
        method: 'POST',
        headers: {
            host: 'panel.example.test',
            origin: 'https://attacker.example.test',
        },
        session: { authenticated: true },
    };
    request.headers['x-csrf-token'] = issuePanelCsrfToken(request);
    const response = createResponse();
    let nextCalls = 0;

    requirePanelCsrf(request, response, () => { nextCalls += 1; });

    assert.equal(nextCalls, 0);
    assert.equal(response.statusCode, 403);
    assert.deepEqual(response.body, {
        error: 'CSRF validation failed',
        code: 'CSRF_ORIGIN_INVALID',
    });
});

test('requirePanelCsrf rejects an Origin with a different scheme', () => {
    const request = {
        method: 'POST',
        protocol: 'https',
        headers: {
            host: 'panel.example.test',
            origin: 'http://panel.example.test',
        },
        session: { authenticated: true },
    };
    request.headers['x-csrf-token'] = issuePanelCsrfToken(request);
    const response = createResponse();
    let nextCalls = 0;

    requirePanelCsrf(request, response, () => { nextCalls += 1; });

    assert.equal(nextCalls, 0);
    assert.equal(response.statusCode, 403);
    assert.equal(response.body.code, 'CSRF_ORIGIN_INVALID');
});

test('requirePanelCsrf accepts a matching Origin, scheme, and Host', () => {
    const request = {
        method: 'POST',
        protocol: 'https',
        headers: {
            host: 'panel.example.test:8443',
            origin: 'https://panel.example.test:8443',
        },
        session: { authenticated: true },
    };
    request.headers['x-csrf-token'] = issuePanelCsrfToken(request);
    const response = createResponse();
    let nextCalls = 0;

    requirePanelCsrf(request, response, () => { nextCalls += 1; });

    assert.equal(nextCalls, 1);
    assert.equal(response.statusCode, null);
});

test('requirePanelCsrf rejects a token copied from another authenticated session', () => {
    const firstRequest = { session: { authenticated: true } };
    const copiedToken = issuePanelCsrfToken(firstRequest);
    const secondRequest = {
        method: 'POST',
        headers: { 'x-csrf-token': copiedToken },
        session: { authenticated: true },
    };
    issuePanelCsrfToken(secondRequest);
    const response = createResponse();
    let nextCalls = 0;

    requirePanelCsrf(secondRequest, response, () => { nextCalls += 1; });

    assert.equal(nextCalls, 0);
    assert.equal(response.statusCode, 403);
    assert.equal(response.body.code, 'CSRF_TOKEN_INVALID');
});

test('requirePanelCsrf leaves safe GET requests unaffected', () => {
    const request = {
        method: 'GET',
        headers: { origin: 'https://attacker.example.test' },
    };
    const response = createResponse();
    let nextCalls = 0;

    requirePanelCsrf(request, response, () => { nextCalls += 1; });

    assert.equal(nextCalls, 1);
    assert.equal(response.statusCode, null);
    assert.equal(response.body, null);
});

test('requirePanelCsrf rejects an unsafe request when neither stored nor submitted token exists', () => {
    const response = createResponse();
    let nextCalls = 0;

    requirePanelCsrf(
        { method: 'POST', headers: {}, session: { authenticated: true } },
        response,
        () => { nextCalls += 1; },
    );

    assert.equal(nextCalls, 0);
    assert.equal(response.statusCode, 403);
    assert.equal(response.body.code, 'CSRF_TOKEN_INVALID');
});
