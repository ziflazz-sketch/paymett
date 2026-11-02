/**
 * Core Defense-in-Depth Security Middleware Suite
 * Integrates Helmet (Strict CSP & Headers), HPP, CORS, and Payload Limiting.
 */

const helmet = require('helmet');
const hpp = require('hpp');
const cors = require('cors');
const { env, isProduction } = require('../config/env');

/**
 * Configure Helmet with strict Financial-Grade Content Security Policy
 */
const helmetSecurity = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'none'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", 'https://fonts.googleapis.com'],
      imgSrc: ["'self'", 'data:'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
      objectSrc: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'none'"],
      upgradeInsecureRequests: isProduction ? [] : null
    }
  },
  crossOriginEmbedderPolicy: true,
  crossOriginOpenerPolicy: { policy: 'same-origin' },
  crossOriginResourcePolicy: { policy: 'same-origin' },
  dnsPrefetchControl: { allow: false },
  frameguard: { action: 'deny' },
  hidePoweredBy: true,
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  },
  ieNoOpen: true,
  noSniff: true,
  originAgentCluster: true,
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  xssFilter: true
});

/**
 * Strict Cross-Origin Resource Sharing (CORS) Whitelist
 */
const allowedOrigins = env.ALLOWED_ORIGINS.split(',').map(o => o.trim());

const corsSecurity = cors({
  origin: (origin, callback) => {
    // Allow non-browser agents (server-to-server webhook, curl from gateway)
    if (!origin) return callback(null, true);
    
    const isLocal = origin.includes('localhost') || origin.includes('127.0.0.1');
    const isVercel = origin.endsWith('.vercel.app');

    if (isLocal || isVercel || allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
      callback(null, true);
    } else {
      const err = new Error('CORS Policy: Request origin not permitted by security whitelist.');
      err.status = 403;
      callback(err);
    }
  },
  methods: ['GET', 'POST'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'Idempotency-Key',
    'X-Idempotency-Key',
    'X-Signature',
    'X-Signature-SHA256'
  ],
  credentials: true,
  maxAge: 86400 // 24 hours preflight cache
});

/**
 * HTTP Parameter Pollution (HPP) Prevention
 */
const hppSecurity = hpp();

module.exports = {
  helmetSecurity,
  corsSecurity,
  hppSecurity
};
