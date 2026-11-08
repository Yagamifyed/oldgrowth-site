// The password page. The password never leaves the browser: it is turned into
// the AES key here, checked against lock/meta.json, and the key's bytes are
// kept in IndexedDB for the service worker, which decrypts the site's files.
// (Bytes, not a CryptoKey object: Safari, on the iPhone above all, can't hand
// a stored CryptoKey to a service worker, so the site never opened there.)

const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const form = document.querySelector('[data-gate]');
const error = document.querySelector('[data-error]');

function keyStore(mode, op) {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('oldgrowth-lock', 1);
    open.onupgradeneeded = () => open.result.createObjectStore('keys');
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const tx = open.result.transaction('keys', mode);
      const req = op(tx.objectStore('keys'));
      tx.oncomplete = () => { open.result.close(); resolve(req?.result); };
      tx.onerror = () => reject(tx.error);
    };
  });
}

async function unlock(password) {
  const meta = await (await fetch('/lock/meta.json', { cache: 'no-cache' })).json();
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: unb64(meta.salt), iterations: meta.iterations, hash: 'SHA-256' }, base, 256));
  const key = await crypto.subtle.importKey('raw', bits, 'AES-GCM', false, ['decrypt']);
  const check = unb64(meta.check);
  await crypto.subtle.decrypt({ name: 'AES-GCM', iv: check.slice(0, 12) }, key, check.slice(12)); // throws if wrong
  return bits;
}

if (!('serviceWorker' in navigator) || !window.crypto?.subtle || !window.indexedDB) {
  document.querySelector('[data-unsupported]').hidden = false;
  form.querySelector('button').disabled = true;
} else {
  const ready = navigator.serviceWorker.register('/sw.js', { scope: '/' }).then(() => navigator.serviceWorker.ready);
  let failures = 0;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const button = form.querySelector('button');
    button.disabled = true;
    error.hidden = true;
    // each wrong guess makes the next one wait longer (1, 2, 4, 8 s)
    if (failures) await new Promise((r) => setTimeout(r, Math.min(1000 * 2 ** (failures - 1), 8000)));
    try {
      const bits = await unlock(form.password.value);
      await keyStore('readwrite', (s) => { s.delete('site'); return s.put(bits, 'raw'); });
      await ready;
      const here = new URL(location.href);
      here.searchParams.delete('lock'); // arriving from /?lock, the reload mustn't lock it again
      location.replace(here);
    } catch {
      failures++;
      error.hidden = false;
      button.disabled = false;
    }
  });
}
