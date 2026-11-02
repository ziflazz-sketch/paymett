/**
 * Payment API Routes Definition
 * Chains endpoint-specific security middlewares, rate limiters, and schema validators.
 */

const { Router } = require('express');
const { paymentController } = require('../controllers/payment.controller');
const { createQrLimiter, webhookLimiter } = require('../middlewares/rateLimiter');
const { ipWhitelist } = require('../middlewares/ipWhitelist');
const { idempotency } = require('../middlewares/idempotency');
const { validate } = require('../middlewares/validate');
const { memoryUpload, validateMagicBytes, scanForMalware } = require('../middlewares/upload');
const {
  createQrSchema,
  webhookSchema,
  orderStatusParamSchema,
  uploadProofBodySchema
} = require('../validators/payment.validator');

const router = Router();

/**
 * 1. Create QRIS Transaction Endpoint
 * Enforces strict rate limit, mandatory idempotency key, and input sanitization.
 */
router.post(
  '/create-qr',
  createQrLimiter,
  idempotency({ required: true, ttlMs: 180000 }),
  validate(createQrSchema, 'body'),
  paymentController.createQR
);

/**
 * 2. Gateway Webhook Callback Endpoint
 * Enforces IP Whitelisting, strict rate limit, schema validation, and HMAC signature check.
 */
router.post(
  '/webhook',
  webhookLimiter,
  ipWhitelist,
  validate(webhookSchema, 'body'),
  paymentController.handleWebhook
);

/**
 * 3. Payment Proof Ingestion Endpoint
 * Enforces 2MB size limit, in-memory buffering, magic bytes inspection, and ClamAV virus scan.
 */
router.post(
  '/upload-proof',
  createQrLimiter,
  memoryUpload.single('proofFile'),
  validate(uploadProofBodySchema, 'body'),
  validateMagicBytes,
  scanForMalware,
  paymentController.uploadProof
);

/**
 * 4. Order Payment Status Ingestion
 */
router.get(
  '/status/:orderId',
  validate(orderStatusParamSchema, 'params'),
  paymentController.getStatus
);

module.exports = {
  paymentRouter: router
};
