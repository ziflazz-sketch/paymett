/**
 * Rafa Payment — Kartu Pembayaran (Versi Neon Gelap)
 * Clean, lightweight, and high-performance client logic.
 */

document.addEventListener('DOMContentLoaded', () => {
  const toast = document.getElementById('toastNotification');
  const toastMessage = document.getElementById('toastMessage');
  let toastTimeout = null;

  // ==========================================================================
  // 1. Toast Notification Helper
  // ==========================================================================
  function showToast(message) {
    if (!toast || !toastMessage) return;

    if (toastTimeout) {
      clearTimeout(toastTimeout);
    }

    toastMessage.textContent = message;
    toast.classList.add('show');
    toast.setAttribute('aria-hidden', 'false');

    toastTimeout = setTimeout(() => {
      toast.classList.remove('show');
      toast.setAttribute('aria-hidden', 'true');
    }, 2500);
  }

  // ==========================================================================
  // 2. Tab Switcher Navigation
  // ==========================================================================
  const tabButtons = document.querySelectorAll('.tab-btn');
  const boardQR = document.getElementById('boardQR');
  const boardTransfer = document.getElementById('boardTransfer');

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      tabButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const target = btn.getAttribute('data-target');

      if (target === 'qr') {
        boardQR.classList.remove('hidden');
        boardTransfer.classList.add('hidden');
        window.scrollTo({ top: 0, behavior: 'smooth' });
      } else if (target === 'transfer') {
        boardQR.classList.add('hidden');
        boardTransfer.classList.remove('hidden');
        window.scrollTo({ top: 0, behavior: 'smooth' });
      } else if (target === 'all') {
        boardQR.classList.remove('hidden');
        boardTransfer.classList.remove('hidden');
      }
    });
  });

  // ==========================================================================
  // 3. Clipboard Copy Handlers with Fallback
  // ==========================================================================
  async function copyToClipboard(text, successMessage, triggerBtn) {
    let copied = false;

    if (navigator.clipboard && window.isSecureContext) {
      try {
        await navigator.clipboard.writeText(text);
        copied = true;
      } catch (err) {
        console.warn('Clipboard API failed, trying fallback...', err);
      }
    }

    if (!copied) {
      try {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        copied = document.execCommand('copy');
        document.body.removeChild(textArea);
      } catch (err) {
        console.error('Fallback copy failed:', err);
      }
    }

    if (copied) {
      showToast(successMessage);

      if (triggerBtn) {
        const originalText = triggerBtn.getAttribute('data-original-text') || triggerBtn.innerHTML;
        if (!triggerBtn.hasAttribute('data-original-text')) {
          triggerBtn.setAttribute('data-original-text', originalText);
        }

        triggerBtn.innerHTML = `
          <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
            <polyline points="20 6 9 17 4 12"></polyline>
          </svg>
          Tersalin!
        `;

        setTimeout(() => {
          triggerBtn.innerHTML = originalText;
        }, 2000);
      }
    } else {
      showToast('Gagal menyalin teks.');
    }
  }

  const copyEwalletBtn = document.getElementById('copyEwalletBtn');
  if (copyEwalletBtn) {
    copyEwalletBtn.addEventListener('click', () => {
      copyToClipboard('082151025831', 'Nomor E-Wallet 0821 5102 5831 berhasil disalin!', copyEwalletBtn);
    });
  }

  const copySeabankBtn = document.getElementById('copySeabankBtn');
  if (copySeabankBtn) {
    copySeabankBtn.addEventListener('click', () => {
      copyToClipboard('901521115022', 'Nomor SeaBank 9015 2111 5022 berhasil disalin!', copySeabankBtn);
    });
  }

  // ==========================================================================
  // 4. Download QR Image
  // ==========================================================================
  const downloadQrBtn = document.getElementById('downloadQrBtn');
  if (downloadQrBtn) {
    downloadQrBtn.addEventListener('click', (e) => {
      e.preventDefault();
      const staticQrImg = document.getElementById('staticQrImage');
      if (!staticQrImg) return;

      const a = document.createElement('a');
      a.href = staticQrImg.getAttribute('src');
      a.download = 'QRIS-ZIFLAZZ-STORE.png';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);

      showToast('QRIS berhasil diunduh!');
    });
  }
});
