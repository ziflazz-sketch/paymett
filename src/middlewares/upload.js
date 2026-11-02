/**
 * Secure File Ingestion & Antivirus Middleware Pipeline
 * Multer In-Memory Storage -> Magic Bytes MIME Validation -> ClamAV Antivirus Scanner
 */

const multer = require('multer');
const { antivirusService } = require('../services/antivirus.service');
const { db } = require('../config/database');

// 1. In-memory temporary storage (File never touches filesystem prior to full clearance)
const memoryUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 2 * 1024 * 1024, // Strict 2MB ceiling
    files: 1
  }
});

/**
 * Known Magic Number Signatures (Header Bytes)
 */
const MAGIC_SIGNATURES = {
  JPEG: [0xFF, 0xD8, 0xFF],
  PNG: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
  PDF: [0x25, 0x50, 0x44, 0x46] // %PDF
};

/**
 * Inspect raw buffer header bytes to ascertain true MIME type
 * @param {Buffer} buffer 
 * @returns {'image/jpeg' | 'image/png' | 'application/pdf' | null}
 */
function detectRealMimeType(buffer) {
  if (!buffer || buffer.length < 8) return null;

  // Check JPEG
  if (
    buffer[0] === MAGIC_SIGNATURES.JPEG[0] &&
    buffer[1] === MAGIC_SIGNATURES.JPEG[1] &&
    buffer[2] === MAGIC_SIGNATURES.JPEG[2]
  ) {
    return 'image/jpeg';
  }

  // Check PNG
  let isPng = true;
  for (let i = 0; i < MAGIC_SIGNATURES.PNG.length; i++) {
    if (buffer[i] !== MAGIC_SIGNATURES.PNG[i]) {
      isPng = false;
      break;
    }
  }
  if (isPng) return 'image/png';

  // Check PDF
  if (
    buffer[0] === MAGIC_SIGNATURES.PDF[0] &&
    buffer[1] === MAGIC_SIGNATURES.PDF[1] &&
    buffer[2] === MAGIC_SIGNATURES.PDF[2] &&
    buffer[3] === MAGIC_SIGNATURES.PDF[3]
  ) {
    return 'application/pdf';
  }

  return null;
}

/**
 * Middleware: Verify Magic Bytes
 */
const validateMagicBytes = (req, res, next) => {
  if (!req.file) {
    return res.status(400).json({
      success: false,
      error: {
        code: 'MISSING_FILE',
        message: 'No payment proof file was provided in the upload request.'
      }
    });
  }

  const realMimeType = detectRealMimeType(req.file.buffer);

  if (!realMimeType) {
    console.warn(`🚨 [FILE_SECURITY] Rejected file with spoofed or unrecognized magic bytes. OriginalName: ${req.file.originalname}`);
    
    return res.status(415).json({
      success: false,
      error: {
        code: 'UNSUPPORTED_MEDIA_TYPE',
        message: 'Invalid file signature. Only authentic JPEG, PNG, and PDF files are accepted.'
      }
    });
  }

  req.file.verifiedMimeType = realMimeType;
  next();
};

/**
 * Middleware: ClamAV Antivirus Scan
 */
const scanForMalware = async (req, res, next) => {
  try {
    const scanResult = await antivirusService.scanBuffer(req.file.buffer);

    if (scanResult.isInfected) {
      console.error(`🛑 [MALWARE_INTERCEPTED] File: ${req.file.originalname} | Virus: ${scanResult.virusName} | IP: ${req.ip}`);
      
      // Log to database audit table
      await db.query('INSERT INTO AUDIT_LOGS', [
        'MALWARE_FILE_BLOCKED',
        req.ip,
        JSON.stringify({ virus: scanResult.virusName, filename: req.file.originalname })
      ]);

      // Release buffer memory immediately
      req.file.buffer = null;

      return res.status(422).json({
        success: false,
        error: {
          code: 'MALWARE_DETECTED',
          message: 'Security Alert: The submitted file failed antivirus screening and has been quarantined.'
        }
      });
    }

    next();
  } catch (err) {
    next(err);
  }
};

module.exports = {
  memoryUpload,
  validateMagicBytes,
  scanForMalware
};
