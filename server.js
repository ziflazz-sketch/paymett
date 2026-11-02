/**
 * Production Server Entrypoint
 * Handles Graceful Shutdown, Unhandled Rejection Safeguards, and Port Binding.
 */

const { app } = require('./src/app');
const { env } = require('./src/config/env');

const server = app.listen(env.PORT, env.HOST, () => {
  console.log('================================================================');
  console.log(`🛡️  Rafa Payment (Ziflazz) Security Backend Online`);
  console.log(`📡  Listening on http://${env.HOST}:${env.PORT}`);
  console.log(`🔒  Environment: ${env.NODE_ENV.toUpperCase()} | Trust Proxy: ${env.TRUST_PROXY}`);
  console.log(`🛡️  Defense in Depth: Rate-Limiting, HMAC-SHA256, ClamAV, Zod Active`);
  console.log('================================================================');
});

/**
 * Graceful Shutdown Handler
 */
function handleGracefulShutdown(signal) {
  console.log(`\n🛑 [${signal}] Initiating graceful shutdown sequence...`);
  
  server.close((err) => {
    if (err) {
      console.error('Error during server close:', err);
      process.exit(1);
    }
    console.log('✅ Server connections terminated safely.');
    process.exit(0);
  });

  // Force termination after 10 seconds if connections hang
  setTimeout(() => {
    console.error('⚠️ Forcefully terminating hanging connections after 10s timeout.');
    process.exit(1);
  }, 10000).unref();
}

process.on('SIGTERM', () => handleGracefulShutdown('SIGTERM'));
process.on('SIGINT', () => handleGracefulShutdown('SIGINT'));

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 [CRITICAL_UNHANDLED_REJECTION]:', reason);
  // Do not crash silently in production
});

process.on('uncaughtException', (error) => {
  console.error('💥 [CRITICAL_UNCAUGHT_EXCEPTION]:', error);
  process.exit(1);
});
