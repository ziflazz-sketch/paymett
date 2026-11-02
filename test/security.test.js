/**
 * Security & Integration Test Suite for Rafa Payment (Ziflazz) Unified App
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const http = require('http');
const { app } = require('../src/app');

let server;
let baseUrl;

test.before(async () => {
  return new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      baseUrl = `http://127.0.0.1:${port}`;
      resolve();
    });
  });
});

test.after(async () => {
  return new Promise((resolve) => {
    server.close(() => resolve());
  });
});

// Helper for HTTP requests
function makeRequest(path, options = {}, body = null) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
    const reqOptions = {
      method: options.method || 'GET',
      headers: options.headers || {},
    };

    const req = http.request(url, reqOptions, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: data }));
    });

    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

test('1. Root URL (/) serves landing page (index.html) with 200 OK', async () => {
  const res = await makeRequest('/');
  assert.equal(res.status, 200);
  assert.ok(res.body.includes('Rafa Payment'));
  assert.ok(res.body.includes('ziflazz'));
  // Verify NO backend port or status leakage
  assert.ok(!res.body.includes('Backend Terhubung'));
  assert.ok(!res.body.includes('4000'));
});

test('2. Static assets (CSS, JS, QRIS) are accessible from public directory', async () => {
  const cssRes = await makeRequest('/css/style.css');
  assert.equal(cssRes.status, 200);
  assert.ok(cssRes.headers['content-type'].includes('text/css'));

  const jsRes = await makeRequest('/js/app.js');
  assert.equal(jsRes.status, 200);
  assert.ok(jsRes.headers['content-type'].includes('javascript'));
});

test('3. CRITICAL: Secret file .env is strictly blocked and returns 404', async () => {
  const envRes = await makeRequest('/.env');
  assert.equal(envRes.status, 404);
  assert.ok(!envRes.body.includes('PAYMENT_GATEWAY_WEBHOOK_SECRET'));
});

test('4. CRITICAL: Server root files (server.js, package.json, /src/) are strictly blocked', async () => {
  const srvRes = await makeRequest('/server.js');
  assert.equal(srvRes.status, 404);

  const pkgRes = await makeRequest('/package.json');
  assert.equal(pkgRes.status, 404);

  const srcRes = await makeRequest('/src/app.js');
  assert.equal(srcRes.status, 404);
});

test('5. Helmet security headers are present on all responses', async () => {
  const res = await makeRequest('/');
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
  assert.equal(res.headers['x-frame-options'], 'DENY');
  assert.ok(res.headers['content-security-policy']);
  assert.equal(res.headers['x-powered-by'], undefined);
});

test('6. Anti-DDoS: Payloads exceeding 10KB are rejected with 413 Payload Too Large', async () => {
  const hugePayload = JSON.stringify({ junk: 'A'.repeat(12 * 1024) });
  const res = await makeRequest('/api/payments/webhook', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, hugePayload);
  assert.equal(res.status, 413);
});

test('7. Webhook Security: Unsigned or tampered requests are rejected', async () => {
  const payload = JSON.stringify({
    orderId: 'ORD-2026-001',
    transactionId: 'TXN-99887711',
    amount: 150000,
    status: 'PAID',
    timestamp: new Date().toISOString(),
    signature: '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
  });

  // Signature 64 karakter hex palsu (lolos skema Zod, ditolak verifikasi HMAC)
  const res = await makeRequest('/api/payments/webhook', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Signature': '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    }
  }, payload);

  assert.equal(res.status, 401);
});
