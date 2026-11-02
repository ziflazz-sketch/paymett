/**
 * Centralized Production Error Handling Middleware
 * Sanitizes errors, assigns incident tracking IDs, and prevents stack trace leakage.
 */

const crypto = require('crypto');
const { isProduction } = require('../config/env');

/**
 * Custom Operational Application Error Class
 */
class AppError extends Error {
  constructor(message, statusCode = 500, errorCode = 'INTERNAL_ERROR', details = null) {
    super(message);
    this.statusCode = statusCode;
    this.errorCode = errorCode;
    this.details = details;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Global Error Handler Middleware
 */
const errorHandler = (err, req, res, next) => {
  const errorId = `ERR-${crypto.randomBytes(6).toString('hex').toUpperCase()}`;
  const statusCode = err.status || err.statusCode || 500;

  // Handle Multer Size Limit (413 Payload Too Large)
  if (err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({
      success: false,
      error: {
        code: 'PAYLOAD_TOO_LARGE',
        message: 'File size exceeds the allowable 2MB limit.',
        errorId
      }
    });
  }

  // Handle JSON Syntax Errors / Body Parser limits
  if (err.type === 'entity.too.large') {
    return res.status(413).json({
      success: false,
      error: {
        code: 'PAYLOAD_TOO_LARGE',
        message: 'Request payload exceeds the allowable 10kb ceiling.',
        errorId
      }
    });
  }

  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'MALFORMED_JSON',
        message: 'Malformed JSON payload received.',
        errorId
      }
    });
  }

  // Log full error details internally with errorId
  console.error(`💥 [ERROR_INCIDENT:${errorId}] Status: ${statusCode} | Path: ${req.method} ${req.originalUrl}`);
  console.error(err.stack || err);

  // Return operational or sanitized response
  if (err.isOperational) {
    return res.status(statusCode).json({
      success: false,
      error: {
        code: err.errorCode || 'APPLICATION_ERROR',
        message: err.message,
        details: err.details || undefined,
        errorId
      }
    });
  }

  // Generic 500 Internal Error (Masked for Security)
  return res.status(500).json({
    success: false,
    error: {
      code: 'INTERNAL_SERVER_ERROR',
      message: 'An unexpected internal error occurred. Please contact support with the error ID.',
      errorId,
      // Stack trace NEVER included in production
      ...(isProduction ? {} : { debugMessage: err.message })
    }
  });
};

module.exports = {
  AppError,
  errorHandler
};
