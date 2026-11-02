/**
 * Input Schema Validation Middleware using Zod
 * Strips unknown fields, enforces strict types, and defends against Injection attacks.
 */

const { ZodError } = require('zod');

/**
 * Higher-order middleware to validate Express request segments
 * @param {import('zod').ZodSchema} schema 
 * @param {'body' | 'query' | 'params'} [source='body']
 */
const validate = (schema, source = 'body') => {
  return async (req, res, next) => {
    try {
      const parsedData = await schema.parseAsync(req[source]);
      // Assign sanitized and stripped data back to request object
      req[source] = parsedData;
      next();
    } catch (error) {
      if (error instanceof ZodError) {
        const issues = error.errors.map(err => ({
          field: err.path.join('.'),
          message: err.message
        }));

        return res.status(400).json({
          success: false,
          error: {
            code: 'VALIDATION_ERROR',
            message: 'Invalid input payload parameters.',
            details: issues
          }
        });
      }
      next(error);
    }
  };
};

module.exports = {
  validate
};
