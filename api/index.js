/**
 * Vercel Serverless Function Handler
 * Adapts Express app for Vercel's serverless environment
 */

const { app } = require('../src/app');

module.exports = app;
