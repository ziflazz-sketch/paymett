/**
 * Payment HTTP Controller
 * Encapsulates request orchestration and delegates to security & financial services.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { paymentService } = require('../services/payment.service');
const { db } = require('../config/database');
const { env } = require('../config/env');
const { AppError } = require('../middlewares/errorHandler');

class PaymentController {
  /**
   * POST /api/payments/create-qr
   * Generates a new QRIS payment order
   */
  async createQR(req, res, next) {
    try {
      const result = await paymentService.createPaymentSession(req.body);
      return res.status(201).json({
        success: true,
        data: result
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/payments/webhook
   * Ingests payment status updates from authorized payment gateway
   */
  async handleWebhook(req, res, next) {
    try {
      // Signature from header or body
      const signature = req.headers['x-signature'] || req.headers['x-signature-sha256'] || req.body.signature;
      
      // Use raw unparsed buffer captured by Express raw-body middleware
      const rawPayload = req.rawBody || JSON.stringify(req.body);

      const result = await paymentService.processWebhook(req.body, rawPayload, signature);

      return res.status(200).json({
        success: true,
        data: result
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * POST /api/payments/upload-proof
   * Ingests payment proof after Magic Bytes & ClamAV Antivirus clearance
   */
  async uploadProof(req, res, next) {
    try {
      const { orderId } = req.body;
      const file = req.file;

      if (!file) {
        throw new AppError('File upload missing.', 400, 'MISSING_FILE');
      }

      // Verify order exists before saving
      const orderRes = await db.query('SELECT * FROM ORDERS WHERE ORDER_ID = ?', [orderId]);
      if (orderRes.rowCount === 0) {
        throw new AppError(`Order ${orderId} does not exist.`, 404, 'ORDER_NOT_FOUND');
      }

      // Ensure upload directory exists
      const uploadDir = path.resolve(env.PROOF_UPLOAD_DIR);
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }

      // Generate cryptographically random secure filename (prevents directory traversal & filename spoofing)
      const ext = file.verifiedMimeType === 'image/jpeg' ? 'jpg' : file.verifiedMimeType === 'image/png' ? 'png' : 'pdf';
      const safeFilename = `proof_${orderId}_${crypto.randomBytes(12).toString('hex')}.${ext}`;
      const destPath = path.join(uploadDir, safeFilename);

      // Write verified buffer to disk
      fs.writeFileSync(destPath, file.buffer);

      // Nullify memory buffer to prevent memory leakage
      file.buffer = null;

      // Log successful upload audit
      await db.query('INSERT INTO AUDIT_LOGS', [
        'PROOF_FILE_STORED',
        req.ip,
        JSON.stringify({ orderId, filename: safeFilename, mimeType: file.verifiedMimeType })
      ]);

      return res.status(200).json({
        success: true,
        message: 'Payment proof successfully screened, validated, and stored.',
        data: {
          orderId,
          fileReference: safeFilename,
          verifiedMimeType: file.verifiedMimeType
        }
      });
    } catch (err) {
      next(err);
    }
  }

  /**
   * GET /api/payments/status/:orderId
   * Checks current payment reconciliation status
   */
  async getStatus(req, res, next) {
    try {
      const { orderId } = req.params;
      const result = await paymentService.getOrderStatus(orderId);
      return res.status(200).json({
        success: true,
        data: result
      });
    } catch (err) {
      next(err);
    }
  }
}

const paymentController = new PaymentController();

module.exports = {
  paymentController
};
