// Decrypts the locked site for a device that has entered the password.
// Without the key (kept in IndexedDB by gate.js) every request goes to the
// network as usual, which serves the password page. /?lock forgets the key.

const PLAIN = new Set(['/sw.js', '/gate.js', '/CNAME']);
const TYPES = {
  html: 'text/html; charset=utf-8', css: 'text/css; charset=utf-8', js: 'text/javascript; charset=utf-8',
  json: 'application/json', svg: 'image/svg+xml', png: 'image/png', jpg: 'image/jpeg', webp: 'image/webp',
  gif: 'image/gif', woff2: 'font/woff2', txt: 'text/plain; charset=utf-8', gz: 'application/gzip', bin: 'application/octet-stream',
  mp4: 'video/mp4', ico: 'image/x-icon',
};

let key = null;
let salt = null;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (e) => e.waitUntil(self.clients.claim()));

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

// the key's bytes (gate.js); a device let in before 8 Nov 2026 has a CryptoKey
// under 'site' instead, which works everywhere but Safari
async function getKey() {
  if (key) return key;
  const raw = await keyStore('readonly', (s) => s.get('raw')).catch(() => null);
  if (raw) return (key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']));
  return (key = await keyStore('readonly', (s) => s.get('site')).catch(() => null));
}

async function forget() {
  key = null;
  await keyStore('readwrite', (s) => { s.delete('site'); s.delete('raw'); }).catch(() => {});
}

// the same name lock_site.mjs gave the file: sha256(salt + path), first 32 hex digits
async function sealedName(path) {
  salt ||= await fetch('/lock/meta.json', { cache: 'no-cache' }).then((r) => r.json()).then((m) => Uint8Array.from(atob(m.salt), (c) => c.charCodeAt(0)));
  const bytes = new Uint8Array([...salt, ...new TextEncoder().encode(path)]);
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return [...hash].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 32);
}

async function serve(request) {
  const url = new URL(request.url);
  if (request.mode === 'navigate' && url.searchParams.has('lock')) { await forget(); return fetch('/', { cache: 'no-cache' }); }
  const k = await getKey();
  if (!k) return fetch(request);

  let path = decodeURIComponent(url.pathname);
  if (path.endsWith('/')) path += 'index.html';
  const res = await fetch(`/lock/${await sealedName(path)}`);
  if (!res.ok && request.mode === 'navigate' && !path.split('/').pop().includes('.')) {
    // a folder asked for without its closing slash (/generator): send the visitor to /generator/
    const dir = await fetch(`/lock/${await sealedName(path + '/index.html')}`, { method: 'HEAD' });
    if (dir.ok) return Response.redirect(url.pathname + '/' + url.search, 302);
  }
  if (!res.ok) return request.mode === 'navigate' ? fetch(request) : new Response('Not found', { status: 404 });

  const sealed = new Uint8Array(await res.arrayBuffer());
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: sealed.slice(0, 12) }, k, sealed.slice(12));
    const ext = path.split('.').pop().toLowerCase();
    return new Response(plain, { headers: { 'Content-Type': TYPES[ext] || 'application/octet-stream' } });
  } catch {
    await forget(); // the password changed since this device was let in
    return fetch(request.mode === 'navigate' ? '/' : request);
  }
}

self.addEventListener('fetch', (e) => {
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin || e.request.method !== 'GET') return;
  if (PLAIN.has(url.pathname) || url.pathname.startsWith('/lock/')) return;
  e.respondWith(serve(e.request));
});
