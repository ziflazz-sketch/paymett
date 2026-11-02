/**
 * Financial Idempotency Middleware
 * Prevents Double-Spending, Transaction Replay Attacks, and Concurrent Race Conditions.
 */

const { db } = require('../config/database');

/**
 * Idempotency Key Processor Middleware
 * @param {Object} [options]
 * @param {boolean} [options.required=false] - Whether the header is mandatory
 * @param {number} [options.ttlMs=120000] - Lock duration in milliseconds (default: 2 mins)
 */
const idempotency = (options = { required: false, ttlMs: 120000 }) => {
  return async (req, res, next) => {
    // Only apply to state-modifying requests
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      return next();
    }

    const idempotencyKey = req.headers['idempotency-key'] || req.headers['x-idempotency-key'];

    if (!idempotencyKey) {
      if (options.required) {
        return res.status(400).json({
          success: false,
          error: {
            code: 'MISSING_IDEMPOTENCY_KEY',
            message: 'Idempotency-Key header is mandatory for this financial transaction endpoint.'
          }
        });
      }
      return next();
    }

    // Sanitize key format (letters, digits, dashes, underscores, 8-128 chars)
    if (!/^[a-zA-Z0-9_-]{8,128}$/.test(idempotencyKey)) {
      return res.status(400).json({
        success: false,
        error: {
          code: 'INVALID_IDEMPOTENCY_KEY_FORMAT',
          message: 'Idempotency-Key must be 8-128 alphanumeric characters with hyphens or underscores.'
        }
      });
    }

    try {
      // 1. Check existing idempotency record
      const checkResult = await db.query('SELECT * FROM IDEMPOTENCY_KEYS WHERE KEY = ?', [idempotencyKey]);

      if (checkResult.rowCount > 0) {
        const record = checkResult.rows[0];

        // Case A: Still in flight -> prevent race condition
        if (record.status === 'PROCESSING') {
          return res.status(409).json({
            success: false,
            error: {
              code: 'CONCURRENT_REQUEST_IN_FLIGHT',
              message: 'A transaction request with this Idempotency-Key is currently in progress. Avoid duplicate submissions.'
            }
          });
        }

        // Case B: Completed -> Replay cached financial outcome
        if (record.status === 'COMPLETED') {
          res.setHeader('X-Cache-Lookup', 'HIT-IDEMPOTENT');
          return res.status(record.response_code).json(record.response_body);
        }
      }

      // 2. Acquire lock (register as PROCESSING)
      await db.query('INSERT INTO IDEMPOTENCY_KEYS', [idempotencyKey, 'PROCESSING', options.ttlMs]);

      // 3. Intercept res.json to capture response and mark COMPLETED
      const originalJson = res.json.bind(res);

      res.json = (body) => {
        // Asynchronously update lock to COMPLETED
        db.query('UPDATE IDEMPOTENCY_KEYS SET STATUS = ?', [
          'COMPLETED',
          res.statusCode,
          body,
          idempotencyKey
        ]).catch(err => {
          console.error(`Failed to complete idempotency key ${idempotencyKey}:`, err.message);
        });

        res.setHeader('X-Cache-Lookup', 'MISS-IDEMPOTENT');
        return originalJson(body);
      };

      next();
    } catch (err) {
      console.error('Idempotency error:', err);
      next(err);
    }
  };
};

module.exports = {
  idempotency
};
