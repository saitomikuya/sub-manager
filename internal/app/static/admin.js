(() => {
  const toast = document.querySelector('[data-toast]');
  const showToast = (message) => {
    if (!toast) return;
    toast.textContent = message;
    toast.hidden = false;
    window.setTimeout(() => { toast.hidden = true; }, 1800);
  };

  const fallbackCopy = (value) => {
    const textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.readOnly = true;
    textarea.className = 'clipboard-helper';
    document.body.appendChild(textarea);
    textarea.focus();
    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);
    let copied = false;
    try {
      copied = document.execCommand('copy');
    } catch (_) {
      copied = false;
    }
    textarea.remove();
    return copied;
  };

  document.querySelectorAll('[data-copy]').forEach((button) => {
    button.addEventListener('click', async () => {
      let copied = false;
      if (window.isSecureContext && navigator.clipboard?.writeText) {
        try {
          await navigator.clipboard.writeText(button.dataset.copy);
          copied = true;
        } catch (_) {
          copied = false;
        }
      }
      if (!copied) copied = fallbackCopy(button.dataset.copy);
      showToast(copied ? '订阅地址已复制' : '复制失败，请手动复制');
    });
  });

  document.querySelectorAll('[data-go-back]').forEach((button) => {
    button.addEventListener('click', () => {
      let sameSiteReferrer = false;
      try {
        sameSiteReferrer = Boolean(document.referrer) && new URL(document.referrer).origin === window.location.origin;
      } catch (_) {
        sameSiteReferrer = false;
      }
      if (sameSiteReferrer && window.history.length > 1) {
        window.history.back();
      } else {
        window.location.assign(button.dataset.fallback || '/admin/');
      }
    });
  });

  const qrDialog = document.querySelector('#qr-dialog');
  const qrImage = document.querySelector('[data-qr-code]');
  const qrTitle = document.querySelector('[data-qr-title]');
  const qrDisplayURL = document.querySelector('[data-qr-display-url]');
  document.querySelectorAll('[data-open-qr]').forEach((button) => {
    button.addEventListener('click', () => {
      if (!qrDialog || !qrImage) return;
      qrTitle.textContent = `${button.dataset.qrName || '订阅'} · 二维码`;
      qrDisplayURL.textContent = button.dataset.qrUrl || '';
      qrImage.src = button.dataset.qrImage;
      qrDialog.showModal();
    });
  });
  document.querySelectorAll('[data-close-qr]').forEach((button) => {
    button.addEventListener('click', () => {
      qrDialog?.close();
      if (qrImage) qrImage.removeAttribute('src');
    });
  });

  document.querySelectorAll('form[data-confirm]').forEach((form) => {
    form.addEventListener('submit', (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  const pathInput = document.querySelector('[data-path-input]');
  const generatePath = document.querySelector('[data-generate-path]');
  if (pathInput && generatePath) {
    generatePath.addEventListener('click', () => {
      const bytes = new Uint8Array(9);
      window.crypto.getRandomValues(bytes);
      const token = btoa(String.fromCharCode(...bytes)).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
      pathInput.value = `/s-${token}`;
      pathInput.focus();
    });
  }

  const checks = [...document.querySelectorAll('[data-subscription-check]')];
  const selectAll = document.querySelector('[data-select-all]');
  const selectedCount = document.querySelector('[data-selected-count]');
  const dialogCount = document.querySelector('[data-dialog-count]');
  const openBatch = document.querySelector('[data-open-batch]');
  const dialog = document.querySelector('#batch-dialog');
  const updateSelection = () => {
    const count = checks.filter((check) => check.checked).length;
    if (selectedCount) selectedCount.textContent = String(count);
    if (dialogCount) dialogCount.textContent = String(count);
    if (openBatch) openBatch.disabled = count === 0;
    if (selectAll) {
      selectAll.checked = count > 0 && count === checks.length;
      selectAll.indeterminate = count > 0 && count < checks.length;
    }
  };
  checks.forEach((check) => check.addEventListener('change', updateSelection));
  selectAll?.addEventListener('change', () => {
    checks.forEach((check) => { check.checked = selectAll.checked; });
    updateSelection();
  });
  openBatch?.addEventListener('click', () => dialog?.showModal());
  document.querySelectorAll('[data-close-batch]').forEach((button) => button.addEventListener('click', () => dialog?.close()));
  document.querySelector('#batch-form')?.addEventListener('submit', (event) => {
    const count = checks.filter((check) => check.checked).length;
    if (count === 0 || !window.confirm(`确定把 ${count} 个订阅的节点内容全部替换为当前内容吗？`)) event.preventDefault();
  });
  updateSelection();
})();
