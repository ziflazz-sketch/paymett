/**
 * Core Financial Logic & Payment Security Service
 * Implements HMAC Timing-Safe Signature Validation and Server-Authoritative Price Reconciliation.
 */

const crypto = require('crypto');
const { db } = require('../config/database');
const { env } = require('../config/env');
const { AppError } = require('../middlewares/errorHandler');

class PaymentService {
  /**
   * Timing-Safe HMAC SHA-256 Webhook Signature Verification
   * Protects against Timing Side-Channel Attacks and Message Tampering.
   *
   * @param {string | Buffer} rawPayload - Exact unparsed incoming byte payload
   * @param {string} receivedSignature - Hex signature provided in header/payload
   * @returns {boolean} True if signature is cryptographically valid
   */
  verifyWebhookSignature(rawPayload, receivedSignature) {
    if (!rawPayload || !receivedSignature) return false;

    // Compute expected HMAC SHA-256 using server-held secret
    const hmac = crypto.createHmac('sha256', env.PAYMENT_GATEWAY_WEBHOOK_SECRET);
    hmac.update(rawPayload);
    const expectedSignature = hmac.digest('hex');

    // Both buffers must be of equal byte length for timingSafeEqual
    const expectedBuffer = Buffer.from(expectedSignature, 'utf8');
    const receivedBuffer = Buffer.from(receivedSignature, 'utf8');

    if (expectedBuffer.length !== receivedBuffer.length) {
      return false;
    }

    return crypto.timingSafeEqual(expectedBuffer, receivedBuffer);
  }

  /**
   * Helper: Generate a valid HMAC signature for testing and gateway simulations
   */
  generateTestSignature(payload) {
    const raw = typeof payload === 'string' ? payload : JSON.stringify(payload);
    return crypto.createHmac('sha256', env.PAYMENT_GATEWAY_WEBHOOK_SECRET).update(raw).digest('hex');
  }

  /**
   * Create New Payment Order & Formatted QRIS String
   */
  async createPaymentSession(data) {
    const { orderId, amount, customerName, customerEmail, customerPhone } = data;

    // Check if orderId already exists (Prevent duplicate order collision)
    const existing = await db.query('SELECT * FROM ORDERS WHERE ORDER_ID = ?', [orderId]);
    if (existing.rowCount > 0) {
      throw new AppError(`Order ID ${orderId} already exists.`, 409, 'DUPLICATE_ORDER_ID');
    }

    // Persist to database using Parameterized Query
    await db.query('INSERT INTO ORDERS', [
      orderId,
      amount,
      'PENDING',
      customerName,
      customerEmail,
      customerPhone
    ]);

    // Construct EMVCo / Standard Static-Dynamic QRIS payload structure
    const qrisPayload = this.constructQrisString({
      orderId,
      amount,
      merchantName: env.QRIS_MERCHANT_ID,
      nmid: env.QRIS_NMID
    });

    return {
      orderId,
      amount,
      currency: 'IDR',
      status: 'PENDING',
      merchant: env.QRIS_MERCHANT_ID,
      qrisString: qrisPayload,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000).toISOString() // 15 mins expiry
    };
  }

  /**
   * Process Gateway Webhook with Strict Anti-Tampering Reconciliation
   */
  async processWebhook(data, rawPayload, receivedSignature) {
    const { transactionId, orderId, amount: reportedAmount, status: reportedStatus } = data;

    // 1. Cryptographic HMAC Signature Verification
    const isSignatureValid = this.verifyWebhookSignature(rawPayload, receivedSignature);
    if (!isSignatureValid) {
      console.error(`🚨 [SIGNATURE_MISMATCH] Potential Tampering detected on order: ${orderId}`);
      await db.query('INSERT INTO AUDIT_LOGS', [
        'WEBHOOK_INVALID_SIGNATURE',
        'WEBHOOK_GATEWAY',
        JSON.stringify({ orderId, receivedSignature })
      ]);
      throw new AppError('Invalid cryptographic webhook signature.', 401, 'INVALID_SIGNATURE');
    }

    // 2. Authoritative Price Check (Never Trust Client or Gateway Amount blindly)
    const orderResult = await db.query('SELECT * FROM ORDERS WHERE ORDER_ID = ?', [orderId]);
    if (orderResult.rowCount === 0) {
      throw new AppError(`Order ${orderId} does not exist in server records.`, 404, 'ORDER_NOT_FOUND');
    }

    const authoritativeOrder = orderResult.rows[0];

    // CRITICAL: Amount Reconciliation
    if (Number(authoritativeOrder.amount) !== Number(reportedAmount)) {
      console.error(`🚨 [FINANCIAL_FRAUD_ALERT] Amount Tampering Mismatch! DB: ${authoritativeOrder.amount} vs Reported: ${reportedAmount}`);
      
      // Update order to SUSPICIOUS state and record audit log
      await db.query('UPDATE ORDERS SET STATUS = ? WHERE ORDER_ID = ?', ['FRAUD_SUSPECT', orderId]);
      await db.query('INSERT INTO AUDIT_LOGS', [
        'PAYMENT_AMOUNT_TAMPERING_ATTEMPT',
        'GATEWAY',
        JSON.stringify({ orderId, expected: authoritativeOrder.amount, received: reportedAmount })
      ]);

      throw new AppError(
        'Payment amount discrepancy detected. Transaction flagged for security review.',
        422,
        'AMOUNT_DISCREPANCY'
      );
    }

    // 3. Prevent Regressive State Machine Transitions
    if (authoritativeOrder.status === 'PAID') {
      return {
        success: true,
        message: 'Order was already previously marked as PAID.',
        orderId,
        status: 'PAID'
      };
    }

    // 4. Update Database Transaction Record & Order Status
    await db.query('INSERT INTO TRANSACTIONS', [
      transactionId,
      orderId,
      reportedAmount,
      reportedStatus,
      typeof rawPayload === 'string' ? rawPayload : rawPayload.toString('utf8')
    ]);

    await db.query('UPDATE ORDERS SET STATUS = ? WHERE ORDER_ID = ?', [reportedStatus, orderId]);

    console.log(`✅ [PAYMENT_PROCESSED] Order: ${orderId} successfully updated to status: ${reportedStatus}`);

    return {
      success: true,
      orderId,
      transactionId,
      status: reportedStatus
    };
  }

  /**
   * Retrieve Order Status by ID
   */
  async getOrderStatus(orderId) {
    const res = await db.query('SELECT * FROM ORDERS WHERE ORDER_ID = ?', [orderId]);
    if (res.rowCount === 0) {
      throw new AppError(`Order ${orderId} not found.`, 404, 'ORDER_NOT_FOUND');
    }
    const order = res.rows[0];
    return {
      orderId: order.order_id,
      amount: order.amount,
      status: order.status,
      customerName: order.customer_name,
      updatedAt: order.updated_at
    };
  }

  /**
   * Minimal EMVCo-compliant QRIS format constructor
   */
  constructQrisString({ orderId, amount, merchantName, nmid }) {
    // Standard National QRIS Payload (ID.CO.QRIS.WWW)
    const formattedAmount = String(amount);
    return `00020101021226${String(nmid.length + 8).padStart(2, '0')}0016ID.CO.QRIS.WWW0118${nmid}51440014ID.LINKAJA.WWW0215${nmid}52045812530336054${String(formattedAmount.length).padStart(2, '0')}${formattedAmount}5802ID59${String(merchantName.length).padStart(2, '0')}${merchantName}6007JAKARTA62${String(orderId.length + 8).padStart(2, '0')}01${String(orderId.length).padStart(2, '0')}${orderId}6304`;
  }
}

const paymentService = new PaymentService();

module.exports = {
  paymentService
};
