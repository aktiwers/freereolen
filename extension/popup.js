const KEK_BYTES = new Uint8Array([
  30, 193, 150,  69,  32, 247,  35,  95,  92, 255, 193, 159, 121,  40, 151, 179,
  39, 159,  75, 110,  32, 205, 210,  58,  81,  55, 158,  33,   8, 149, 108,  74
]);
const ZERO_IV = new Uint8Array(16);
const METADATA_URL = 'https://bookstreaming.pubhub.dk/v1/order/metadata/';
const FILE_URL = 'https://bookstreaming.pubhub.dk/v1/order/file/';
const UUID_RE = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;

const $info = document.getElementById('info');
const $status = document.getElementById('status');
const $progress = document.getElementById('progress');

function setStatus(text, kind) {
  $status.textContent = text;
  $status.classList.remove('error', 'success');
  if (kind) $status.classList.add(kind);
}

function getOrderIdFromUrl(url) {
  if (!url) return null;
  try {
    const u = new URL(url);
    const q = u.searchParams.get('orderid') || u.searchParams.get('orderId');
    if (q && UUID_RE.test(q)) return q.match(UUID_RE)[0];
  } catch (_) {}
  const m = url.match(UUID_RE);
  return m ? m[0] : null;
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Decrypt a single 16-byte AES-CBC block with key K and IV=0, no padding.
// WebCrypto's AES-CBC requires PKCS7 padding on decrypt, so we synthesize a
// second ciphertext block C2 such that the second decrypted block is exactly
// 0x10 x 16 (valid PKCS7 padding for an empty plaintext, which the API strips).
//
//   block 1: AES_dec(C2) XOR C1 = 0x10 x 16
//   =>  C2  = AES_enc((0x10 x 16) XOR C1)
// We get AES_enc via subtle.encrypt with CBC + zero IV, taking the first block.
async function aesDecryptSingleBlockNoPad(rawKey, c1) {
  const keyHandle = await crypto.subtle.importKey(
    'raw', rawKey, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']
  );
  const xored = new Uint8Array(16);
  for (let i = 0; i < 16; i++) xored[i] = 0x10 ^ c1[i];
  const enc = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-CBC', iv: ZERO_IV }, keyHandle, xored
  ));
  const c2 = enc.slice(0, 16);
  const ct = new Uint8Array(32);
  ct.set(c1, 0);
  ct.set(c2, 16);
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv: ZERO_IV }, keyHandle, ct
  );
  return new Uint8Array(pt);
}

async function decryptWrappedKey(b64) {
  // Mirror reader.pubhub.dk's Base64Binary.decode quirk: a Uint16Array view
  // on a half-sized buffer means only the first 16 bytes ever reach AES.
  const block = base64ToBytes(b64).slice(0, 16);
  return await aesDecryptSingleBlockNoPad(KEK_BYTES, block);
}

async function decryptFile(cek, encryptedBuf) {
  const keyHandle = await crypto.subtle.importKey(
    'raw', cek, { name: 'AES-CTR' }, false, ['decrypt']
  );
  const dec = await crypto.subtle.decrypt(
    { name: 'AES-CTR', counter: ZERO_IV, length: 128 },
    keyHandle,
    encryptedBuf
  );
  return new Uint8Array(dec);
}

function safeFilename(s) {
  return (s || '').replace(/[\/\\:*?"<>|]/g, '_').trim() || 'book';
}

async function fetchWithProgress(url, onProgress) {
  const res = await fetch(url);
  if (!res.ok) throw new Error('HTTP ' + res.status + ' fetching ' + url);
  const total = Number(res.headers.get('content-length')) || 0;
  if (!res.body || !total) return new Uint8Array(await res.arrayBuffer());
  const reader = res.body.getReader();
  const chunks = [];
  let received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.length;
    onProgress(received, total);
  }
  const out = new Uint8Array(received);
  let offset = 0;
  for (const c of chunks) { out.set(c, offset); offset += c.length; }
  return out;
}

let CURRENT = null;

async function loadActiveBook() {
  let tab;
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    tab = tabs && tabs[0];
  } catch (e) {
    $info.textContent = 'Could not read the active tab.';
    return;
  }
  const orderId = getOrderIdFromUrl(tab && tab.url);
  if (!orderId) {
    $info.textContent =
      'No order-id found in the current tab. Open a borrowed book in your library reader (the URL contains "orderid=...") and try again.';
    return;
  }
  $info.textContent = 'Looking up book metadata...';
  let meta;
  try {
    const res = await fetch(METADATA_URL + orderId);
    if (!res.ok) throw new Error('HTTP ' + res.status);
    meta = await res.json();
  } catch (e) {
    $info.textContent = 'Could not fetch metadata: ' + e.message;
    return;
  }
  if (!meta.key) {
    $info.textContent = 'Metadata response had no encryption key.';
    return;
  }
  CURRENT = {
    orderId: orderId,
    title: meta.title || orderId,
    author: meta.author || '',
    key: meta.key,
  };
  $info.innerHTML = '';
  const t = document.createElement('div');
  t.className = 'title';
  t.textContent = CURRENT.title;
  const a = document.createElement('div');
  a.className = 'author';
  a.textContent = CURRENT.author;
  $info.appendChild(t);
  $info.appendChild(a);
  await downloadAndDecrypt();
}

async function downloadAndDecrypt() {
  if (!CURRENT) return;
  $progress.hidden = false;
  $progress.value = 0;
  setStatus('Decrypting key...');
  try {
    const cek = await decryptWrappedKey(CURRENT.key);
    setStatus('Downloading encrypted file...');
    const encrypted = await fetchWithProgress(
      FILE_URL + CURRENT.orderId,
      function(received, total) {
        $progress.value = Math.round((received / total) * 90);
        setStatus(
          'Downloading... ' +
          (received / 1048576).toFixed(1) + ' / ' +
          (total / 1048576).toFixed(1) + ' MB'
        );
      }
    );
    setStatus('Decrypting file...');
    $progress.value = 95;
    const epub = await decryptFile(cek, encrypted.buffer);
    if (!(epub[0] === 0x50 && epub[1] === 0x4b && epub[2] === 0x03 && epub[3] === 0x04)) {
      throw new Error('Decryption produced non-ZIP output (wrong key?)');
    }
    setStatus('Saving...');
    const blob = new Blob([epub], { type: 'application/epub+zip' });
    const blobUrl = URL.createObjectURL(blob);
    const filename =
      safeFilename(CURRENT.author || 'unknown') + ' - ' +
      safeFilename(CURRENT.title) + '.epub';
    // Trigger the download via an <a download> click instead of
    // chrome.downloads.download. With chrome.downloads, opening the Save-As
    // dialog steals focus from the popup, the popup closes, the blob URL gets
    // revoked, and the actual save then fails. <a> click hands the blob to
    // the browser's own download pipeline synchronously, so the file survives
    // the popup closing.
    const a = document.createElement('a');
    a.href = blobUrl;
    a.download = filename;
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    a.remove();
    $progress.value = 100;
    setStatus('Saved. You can close this popup.', 'success');
    // Keep the URL alive for a while in case the browser is still streaming
    // from it (some download managers re-fetch on retry/resume).
    setTimeout(function() { URL.revokeObjectURL(blobUrl); }, 5 * 60 * 1000);
  } catch (e) {
    setStatus(e.message || String(e), 'error');
  }
}

loadActiveBook();
