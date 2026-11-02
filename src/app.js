/**
 * Express Application Assembly
 * Configures Trust Proxy, Payload Limits, Global Rate Limiting, Security Headers, and Route Pipelines.
 */

const express = require('express');
const { env } = require('./config/env');
const { helmetSecurity, corsSecurity, hppSecurity } = require('./middlewares/security');
const { globalLimiter } = require('./middlewares/rateLimiter');
const { errorHandler } = require('./middlewares/errorHandler');
const { paymentRouter } = require('./routes/payment.routes');

const app = express();

// ==============================================================================
// 1. REVERSE PROXY & CLOUDFLARE WAF INTEGRATION
// ==============================================================================
// Trust proxy setting enables accurate client IP parsing from CF-Connecting-IP / X-Forwarded-For
app.set('trust proxy', env.TRUST_PROXY === 'true' ? true : Number(env.TRUST_PROXY) || 1);

// Disable X-Powered-By header
app.disable('x-powered-by');

// ==============================================================================
// 2. GLOBAL DEFENSE-IN-DEPTH SECURITY MIDDLEWARES
// ==============================================================================
app.use(helmetSecurity);
app.use(corsSecurity);
app.use(hppSecurity);
app.use(globalLimiter);

// ==============================================================================
// 3. BODY PARSER WITH STRICT 10KB CEILING (ANTI-MEMORY EXHAUSTION)
// Captures rawBuffer for bitwise-identical HMAC signature verification
// ==============================================================================
app.use(express.json({
  limit: '10kb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

app.use(express.urlencoded({
  extended: false,
  limit: '10kb'
}));

const path = require('path');

// ==============================================================================
// 4. SENSITIVE FILE PROTECTION & GATEKEEPER
// Explicitly block any request trying to access .env, package.json, or src/
// ==============================================================================
app.use((req, res, next) => {
  const normalizedPath = req.path.toLowerCase();
  if (
    normalizedPath.includes('.env') ||
    normalizedPath.includes('package.json') ||
    normalizedPath.includes('/src/') ||
    normalizedPath.startsWith('/.')
  ) {
    return res.status(404).json({
      success: false,
      error: {
        code: 'NOT_FOUND',
        message: 'The requested resource was not found.'
      }
    });
  }
  next();
});

// ==============================================================================
// 5. STATIC ASSETS & FRONTEND SERVING (PUBLIC DIRECTORY ONLY)
// ==============================================================================
const publicDirectory = path.join(__dirname, '../public');

app.use(express.static(publicDirectory, {
  dotfiles: 'ignore',
  index: 'index.html',
  maxAge: '1h'
}));

// Route for root '/' to serve index.html (with safe serverless fallback)
app.get('/', (req, res) => {
  const indexPath = path.join(publicDirectory, 'index.html');
  const fs = require('fs');
  if (fs.existsSync(indexPath)) {
    return res.sendFile(indexPath);
  }
  return res.status(200).json({
    status: 'ONLINE',
    service: 'Rafa Payment (Ziflazz) Unified App'
  });
});

// ==============================================================================
// 6. HEALTH CHECK & METRICS (Safe Endpoint)
// ==============================================================================
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'HEALTHY',
    service: 'Rafa Payment (Ziflazz) Unified App',
    timestamp: new Date().toISOString()
  });
});

// ==============================================================================
// 7. FINANCIAL & PAYMENT ROUTES
// ==============================================================================
app.use('/api/payments', paymentRouter);

// ==============================================================================
// 8. 404 UNMATCHED ROUTE CATCHER
// ==============================================================================
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: {
      code: 'ROUTE_NOT_FOUND',
      message: `The requested endpoint ${req.method} ${req.originalUrl} does not exist.`
    }
  });
});

// ==============================================================================
// 7. CENTRALIZED PRODUCTION ERROR HANDLER (NO STACK TRACE LEAK)
// ==============================================================================
app.use(errorHandler);

// Export Express app as default function for Vercel Serverless Function compatibility,
// while preserving named export for CommonJS destructuring: const { app } = require('./src/app')
module.exports = app;
module.exports.app = app;
module.exports.default = app;
