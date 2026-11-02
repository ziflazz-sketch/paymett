/**
 * ClamAV Antivirus Scanner Service
 * Streams in-memory buffers to ClamAV daemon socket for real-time malware analysis.
 */

const net = require('net');
const { env } = require('../config/env');

class AntivirusService {
  /**
   * Scan memory buffer using ClamAV INSTREAM protocol over TCP
   * @param {Buffer} buffer - In-memory file buffer
   * @returns {Promise<{ isInfected: boolean, virusName: string | null }>}
   */
  async scanBuffer(buffer) {
    if (!env.CLAMAV_ENABLED) {
      // In development or when disabled, log notice and bypass
      return { isInfected: false, virusName: null, bypassed: true };
    }

    return new Promise((resolve, reject) => {
      const socket = new net.Socket();
      let response = '';

      socket.setTimeout(env.CLAMAV_TIMEOUT);

      socket.connect(env.CLAMAV_PORT, env.CLAMAV_HOST, () => {
        // ClamAV INSTREAM protocol command
        socket.write('zINSTREAM\0');

        const chunkSize = 2048;
        for (let i = 0; i < buffer.length; i += chunkSize) {
          const chunk = buffer.subarray(i, i + chunkSize);
          const sizeBuffer = Buffer.alloc(4);
          sizeBuffer.writeUInt32BE(chunk.length, 0);
          socket.write(sizeBuffer);
          socket.write(chunk);
        }

        // Send 0-length chunk to indicate EOF
        const zeroChunk = Buffer.alloc(4);
        zeroChunk.writeUInt32BE(0, 0);
        socket.write(zeroChunk);
      });

      socket.on('data', (data) => {
        response += data.toString('utf8');
      });

      socket.on('end', () => {
        socket.destroy();
        // ClamAV response format: "stream: OK" or "stream: <VirusName> FOUND"
        if (response.includes('FOUND')) {
          const match = response.match(/stream:\s+(.+)\s+FOUND/);
          const virus = match ? match[1] : 'Unknown Malware';
          resolve({ isInfected: true, virusName: virus });
        } else {
          resolve({ isInfected: false, virusName: null });
        }
      });

      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('ClamAV scan timed out.'));
      });

      socket.on('error', (err) => {
        socket.destroy();
        console.warn(`⚠️ [ANTIVIRUS] ClamAV daemon unavailable at ${env.CLAMAV_HOST}:${env.CLAMAV_PORT}. Reason: ${err.message}`);
        // In local development, fallback gracefully with alert; in strict production fail-safe
        if (env.NODE_ENV === 'production') {
          reject(new Error('Security Scanner Service is currently unavailable. Upload aborted.'));
        } else {
          resolve({ isInfected: false, virusName: null, bypassed: true });
        }
      });
    });
  }
}

const antivirusService = new AntivirusService();

module.exports = {
  antivirusService
};
