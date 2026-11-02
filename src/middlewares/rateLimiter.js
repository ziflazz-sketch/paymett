/**
 * Tiered Rate Limiting Middleware (Anti-DDoS & Brute Force Defense)
 * Implements strict per-endpoint thresholds and standard draft-7 rate-limit headers.
 */

const rateLimit = require('express-rate-limit');
const { env } = require('../config/env');

/**
 * Standardized Rate Limit Breach Response
 */
const rateLimitHandler = (category) => (req, res, next, options) => {
  const retryAfterSec = Math.ceil(options.windowMs / 1000);
  
  console.warn(`⚠️ [RATE_LIMIT_EXCEEDED] Category: ${category} | IP: ${req.ip} | Path: ${req.originalUrl}`);
  
  return res.status(options.statusCode).json({
    success: false,
    error: {
      code: 'RATE_LIMIT_EXCEEDED',
      message: `Too many requests for ${category}. Please try again later.`,
      retryAfterSeconds: retryAfterSec
    }
  });
};

/**
 * 1. Global Baseline Limiter
 * Guards the entire API surface against broad volumetric flooding.
 */
const globalLimiter = rateLimit({
  windowMs: env.RATE_LIMIT_GLOBAL_WINDOW_MS,
  max: env.RATE_LIMIT_GLOBAL_MAX,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler: rateLimitHandler('Global API')
});

/**
 * 2. Strict QR Code Creation Limiter
 * Guards against order generation flooding and merchant quota exhaustion attacks.
 */
const createQrLimiter = rateLimit({
  windowMs: env.RATE_LIMIT_QR_CREATE_WINDOW_MS,
  max: env.RATE_LIMIT_QR_CREATE_MAX,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler: rateLimitHandler('QR Creation')
});

/**
 * 3. Strict Webhook Ingestion Limiter
 * Protects webhook endpoint from state-machine spam while allowing legitimate gateway retries.
 */
const webhookLimiter = rateLimit({
  windowMs: env.RATE_LIMIT_WEBHOOK_WINDOW_MS,
  max: env.RATE_LIMIT_WEBHOOK_MAX,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler: rateLimitHandler('Payment Webhook')
});

module.exports = {
  globalLimiter,
  createQrLimiter,
  webhookLimiter
};
