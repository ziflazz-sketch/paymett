/**
 * Environment Configuration & Strict Zod Schema Validation
 * Enforces fail-fast behavior if critical security or financial parameters are missing.
 */

const { z } = require('zod');
const dotenv = require('dotenv');

dotenv.config();

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().default(4000),
  HOST: z.string().default('0.0.0.0'),
  
  // Reverse Proxy Hops
  TRUST_PROXY: z.string().default('1'),
  
  // Allowed CORS Origins
  ALLOWED_ORIGINS: z.string().default('http://localhost:3000,http://localhost:8089'),

  // Financial Security & Webhook HMAC
  PAYMENT_GATEWAY_WEBHOOK_SECRET: z.string().min(32, {
    message: 'PAYMENT_GATEWAY_WEBHOOK_SECRET must be at least 32 characters high-entropy string'
  }),
  QRIS_MERCHANT_ID: z.string().min(3).default('ZIFLAZZ_STORE'),
  QRIS_NMID: z.string().min(5).default('ID1020030040050'),

  // Gateway IP Whitelist
  GATEWAY_WHITELISTED_IPS: z.string().default('127.0.0.1,::1'),

  // Rate Limits
  RATE_LIMIT_GLOBAL_MAX: z.coerce.number().default(100),
  RATE_LIMIT_GLOBAL_WINDOW_MS: z.coerce.number().default(15 * 60 * 1000),
  RATE_LIMIT_QR_CREATE_MAX: z.coerce.number().default(10),
  RATE_LIMIT_QR_CREATE_WINDOW_MS: z.coerce.number().default(5 * 60 * 1000),
  RATE_LIMIT_WEBHOOK_MAX: z.coerce.number().default(60),
  RATE_LIMIT_WEBHOOK_WINDOW_MS: z.coerce.number().default(60 * 1000),

  // Antivirus (ClamAV)
  CLAMAV_ENABLED: z.enum(['true', 'false']).transform(v => v === 'true').default('false'),
  CLAMAV_HOST: z.string().default('127.0.0.1'),
  CLAMAV_PORT: z.coerce.number().default(3310),
  CLAMAV_TIMEOUT: z.coerce.number().default(5000),
  PROOF_UPLOAD_DIR: z.string().default('./uploads/proofs')
});

const parsed = envSchema.safeParse(process.env);

if (!parsed.success) {
  console.error('❌ CRITICAL SECURITY ERROR: Invalid environment variables:');
  console.error(JSON.stringify(parsed.error.format(), null, 2));
  process.exit(1);
}

module.exports = {
  env: parsed.data,
  isProduction: parsed.data.NODE_ENV === 'production'
};
