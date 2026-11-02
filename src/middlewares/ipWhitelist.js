/**
 * Payment Gateway IP Whitelisting Middleware
 * Strictly restricts access to Webhook endpoints to verified Acquirer / Gateway IP addresses.
 */

const { env } = require('../config/env');
const { db } = require('../config/database');

/**
 * Extract true client IP considering Cloudflare WAF and Reverse Proxies
 * @param {import('express').Request} req 
 * @returns {string} Normalized IP address
 */
function getClientIp(req) {
  // 1. Cloudflare True Client IP header
  const cfIp = req.headers['cf-connecting-ip'];
  if (cfIp && typeof cfIp === 'string') {
    return cfIp.trim();
  }

  // 2. Standard X-Forwarded-For header (first hop)
  const forwardedFor = req.headers['x-forwarded-for'];
  if (forwardedFor && typeof forwardedFor === 'string') {
    return forwardedFor.split(',')[0].trim();
  }

  // 3. Fallback to Express connection IP
  return (req.ip || req.socket.remoteAddress || '').replace(/^.*:/, ''); // normalize IPv4-mapped IPv6
}

/**
 * IP Whitelisting Middleware for Webhook Endpoints
 */
const ipWhitelist = (req, res, next) => {
  const clientIp = getClientIp(req);
  const whitelistedIps = env.GATEWAY_WHITELISTED_IPS.split(',').map(ip => ip.trim());

  const isAllowed = whitelistedIps.some(allowedIp => {
    return allowedIp === clientIp || allowedIp === '127.0.0.1' || allowedIp === '::1';
  });

  if (!isAllowed) {
    console.warn(`🚨 [SECURITY_ALERT] Unauthorized Webhook Access Attempt from IP: ${clientIp} to ${req.originalUrl}`);
    
    // Asynchronously record security audit log
    db.query('INSERT INTO AUDIT_LOGS', [
      'UNAUTHORIZED_WEBHOOK_IP_ATTEMPT',
      clientIp,
      JSON.stringify({ path: req.originalUrl, method: req.method })
    ]).catch(err => console.error('Failed to log audit:', err.message));

    return res.status(403).json({
      success: false,
      error: {
        code: 'FORBIDDEN_ORIGIN_IP',
        message: 'Access denied: Origin IP address is not authorized for payment callbacks.'
      }
    });
  }

  req.verifiedGatewayIp = clientIp;
  next();
};

module.exports = {
  ipWhitelist,
  getClientIp
};
