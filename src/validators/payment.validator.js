/**
 * Strict Zod Payment Schemas (Anti-Injection & XSS Defense)
 * Sanitizes input types, validates bounds on monetary amounts, and restricts ID formats.
 */

const { z } = require('zod');

// Regex for safe financial identifier (Prevents Path Traversal & SQL/NoSQL Injection)
const SAFE_ID_REGEX = /^[A-Za-z0-9_-]{8,64}$/;
// Regex for Indonesian phone formats (e.g., 082151025831, +62821...)
const PHONE_REGEX = /^(\+62|62|0)8[1-9][0-9]{6,10}$/;

/**
 * 1. Create QRIS Transaction Schema
 */
const createQrSchema = z.object({
  orderId: z
    .string()
    .trim()
    .regex(SAFE_ID_REGEX, {
      message: 'orderId must be 8-64 alphanumeric characters, underscores, or hyphens only.'
    }),
  amount: z
    .number({ required_error: 'amount is required and must be numeric.' })
    .int({ message: 'amount must be a whole integer without decimals (IDR).' })
    .min(1000, { message: 'Minimum allowable QRIS transaction is IDR 1,000.' })
    .max(50000000, { message: 'Maximum allowable QRIS transaction is IDR 50,000,000.' }),
  customerName: z
    .string()
    .trim()
    .min(2, { message: 'customerName must be at least 2 characters.' })
    .max(100, { message: 'customerName cannot exceed 100 characters.' })
    .transform(val => val.replace(/<[^>]*>?/gm, '')), // Strip HTML tags
  customerEmail: z
    .string()
    .trim()
    .email({ message: 'A valid email address is required.' })
    .max(120),
  customerPhone: z
    .string()
    .trim()
    .regex(PHONE_REGEX, {
      message: 'customerPhone must be a valid Indonesian phone number (e.g. 082151025831).'
    })
});

/**
 * 2. Gateway Webhook Payload Schema
 */
const webhookSchema = z.object({
  transactionId: z.string().trim().regex(SAFE_ID_REGEX),
  orderId: z.string().trim().regex(SAFE_ID_REGEX),
  amount: z.number().int().positive(),
  status: z.enum(['PAID', 'FAILED', 'EXPIRED']),
  timestamp: z.string().or(z.number()),
  signature: z.string().trim().min(32).max(128)
});

/**
 * 3. Order Status URL Parameter Schema
 */
const orderStatusParamSchema = z.object({
  orderId: z.string().trim().regex(SAFE_ID_REGEX)
});

/**
 * 4. Payment Proof Upload Body Schema
 */
const uploadProofBodySchema = z.object({
  orderId: z.string().trim().regex(SAFE_ID_REGEX)
});

module.exports = {
  createQrSchema,
  webhookSchema,
  orderStatusParamSchema,
  uploadProofBodySchema
};
