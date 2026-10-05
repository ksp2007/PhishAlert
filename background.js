// PhishAlert — Background Service Worker
// Acts as API gateway for all external calls (VirusTotal, RDAP, URL unshortening)

// ─── Registrable-domain helper (Public Suffix List) ──────────────────────────
// Taking the last two labels of a hostname breaks on multi-part suffixes
// (sbi.co.in and evil.co.in both became "co.in"). psl.js provides the real
// eTLD+1 lookup; the same file is loaded into the content scripts.
try { importScripts('psl.js'); } catch (e) { console.error('PhishAlert: psl.js failed to load', e); }
// idn.js (real punycode decoding + look-alike brand matching) and authres.js (per-message
// Authentication-Results parsing) both depend on psl.js, so they load after it.
try { importScripts('idn.js'); } catch (e) { console.error('PhishAlert: idn.js failed to load', e); }
try { importScripts('authres.js'); } catch (e) { console.error('PhishAlert: authres.js failed to load', e); }

// Root (registrable) domain: "mail.sbi.co.in" -> "sbi.co.in". If the helper is
// unavailable it degrades safely to the full hostname, so two different hosts
// are never treated as the same organisation by mistake.
function getRootDomain(host) {
  const h = String(host || '').toLowerCase().replace(/\.+$/, '');
  return (typeof self.paRootDomain === 'function') ? self.paRootDomain(h) : h;
}
function sameRootDomain(a, b) {
  return !!a && !!b && getRootDomain(a) === getRootDomain(b);
}

// ─── Constants ──────────────────────────────────────────────────────────────
const CACHE_EXPIRY_MS = 60 * 60 * 1000; // 1 hour cache TTL

// ─── UPGRADE 1: Persistent Cache (survives service worker restarts) ──────────
// Replaces the old in-memory Map with chrome.storage.local + TTL metadata.
// This means cached DNS/VT/RDAP results survive Chrome killing the SW.

async function getCached(key) {
  try {
    const storageKey = `phishalert_cache_${key}`;
    const result = await chrome.storage.local.get(storageKey);
    const entry = result[storageKey];
    if (!entry) return null;
    if (Date.now() - entry.timestamp > CACHE_EXPIRY_MS) {
      chrome.storage.local.remove(storageKey); // async cleanup, no await needed
      return null;
    }
    return entry.data;
  } catch (e) {
    return null;
  }
}

async function setCache(key, data) {
  try {
    const storageKey = `phishalert_cache_${key}`;
    await chrome.storage.local.set({
      [storageKey]: { data, timestamp: Date.now() }
    });
  } catch (e) {
    // Storage full or unavailable — fail silently
  }
}

// ─── UPGRADE 4: API Rate Limiter + Quota Tracker ──────────────────────────────
// Tracks daily VirusTotal usage and queues requests to stay under 500/day.

const VT_DAILY_LIMIT = 490; // stay safely under the 500/day free tier
const VT_QUEUE_INTERVAL_MS = 200; // min time between VT requests
let vtLastRequestTime = 0;

async function getVTQuota() {
  const today = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
  const data = await chrome.storage.local.get('phishalert_vt_quota');
  const quota = data.phishalert_vt_quota || { date: today, used: 0 };
  if (quota.date !== today) {
    // New day — reset counter
    const fresh = { date: today, used: 0 };
    await chrome.storage.local.set({ phishalert_vt_quota: fresh });
    return fresh;
  }
  return quota;
}

async function incrementVTQuota() {
  const quota = await getVTQuota();
  quota.used += 1;
  await chrome.storage.local.set({ phishalert_vt_quota: quota });
  return quota;
}

async function canUseVT() {
  const quota = await getVTQuota();
  return quota.used < VT_DAILY_LIMIT;
}

// Simple request throttle: ensures we don't fire VT requests too rapidly
function waitForVTSlot() {
  return new Promise(resolve => {
    const now = Date.now();
    const wait = Math.max(0, vtLastRequestTime + VT_QUEUE_INTERVAL_MS - now);
    vtLastRequestTime = now + wait;
    setTimeout(resolve, wait);
  });
}

// ─── Privacy: AI consent + email-content retention ───────────────────────────
// Email subject/body/thread text is personal data. Rules enforced here:
//   1. Nothing is sent to Groq unless the user has switched on "AI features"
//      (phishalert_settings.aiConsent === true). Default is OFF. This check lives
//      in callGroq(), the single choke point every Groq request goes through.
//   2. Subject/body/thread/AI-summary text is only kept when consent is on, only in
//      chrome.storage.session (memory, cleared when the browser closes) and only
//      for EMAIL_CONTENT_TTL_MS. It is never written to chrome.storage.local.
//   3. Anything left over from older versions in storage.local is purged.
const EMAIL_CONTENT_TTL_MS = 30 * 60 * 1000;
const EMAIL_CONTENT_KEYS = ['phishalert_email_content', 'phishalert_thread_messages', 'phishalert_ai_analysis'];
const LEGACY_PLAINTEXT_KEYS = [...EMAIL_CONTENT_KEYS, 'phishalert_prod_cache'];
const AI_CONSENT_MSG = 'AI features are off. To use them, turn on "Send email content to Groq" in Settings (nothing is sent until you do).';

async function getAiSettings() {
  try {
    const s = (await chrome.storage.local.get('phishalert_settings')).phishalert_settings || {};
    return { consent: s.aiConsent === true, autoClassify: s.aiConsent === true && s.aiAutoClassify === true };
  } catch { return { consent: false, autoClassify: false }; }
}
async function isAiConsented() { return (await getAiSettings()).consent; }

// Session store only — if the browser lacks it, content is simply not kept.
async function sessionSet(obj) { try { if (chrome.storage.session) await chrome.storage.session.set(obj); } catch { } }
async function sessionGetFresh(key) {
  try {
    if (!chrome.storage.session) return null;
    const v = (await chrome.storage.session.get(key))[key];
    if (!v) return null;
    if (!v.timestamp || Date.now() - v.timestamp > EMAIL_CONTENT_TTL_MS) { await chrome.storage.session.remove(key); return null; }
    return v;
  } catch { return null; }
}
async function purgeEmailContent({ legacyOnly = false } = {}) {
  try { await chrome.storage.local.remove(LEGACY_PLAINTEXT_KEYS); } catch { }
  if (legacyOnly) return;
  try { if (chrome.storage.session) await chrome.storage.session.remove([...LEGACY_PLAINTEXT_KEYS]); } catch { }
}

// ─── Groq AI Rate Limiting ──────────────────────────────────────────────────
// Groq free tier has strict RPM (Requests Per Minute) limits.
// We implement a queue to prevent parallel bursts from hitting 429 errors.

const GROQ_QUEUE_INTERVAL_MS = 2000; // 2 seconds between AI calls
let groqLastRequestTime = 0;

function waitForGroqSlot() {
  return new Promise(resolve => {
    const now = Date.now();
    const wait = Math.max(0, groqLastRequestTime + GROQ_QUEUE_INTERVAL_MS - now);
    groqLastRequestTime = now + wait;
    setTimeout(resolve, wait);
  });
}

// Does the actual HTTP call to Groq once, with whatever payload it's given.
// Returns { success, data } or { error, _status, _groqBody } — the raw
// status/body are attached (not shown to the user) so callGroq() above it
// can decide whether to retry, and so any error we DO surface can include
// Groq's own message instead of just a bare status code.
async function callGroqOnce(apiKey, payload) {
  try {
    const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify(payload)
    });

    // BUG FIX: previously any non-2xx became a bare `Groq API error: ${status}`
    // — Groq's actual error message (which names the bad parameter, or the
    // exact rate-limit reason) was read and thrown away. Read the body on
    // failure too so real errors are diagnosable instead of guessed at.
    let body = null;
    try { body = await res.json(); } catch { /* non-JSON error body */ }

    if (res.status === 401) return { error: 'Invalid Groq API key. Check your Settings.', _status: 401, _groqBody: body };
    if (res.status === 429) {
      const detail = body?.error?.message ? ` (${body.error.message})` : '';
      return { error: `Groq rate limit reached. Please wait a moment.${detail}`, _status: 429, _groqBody: body };
    }
    if (!res.ok) {
      const detail = body?.error?.message ? `: ${body.error.message}` : '';
      return { error: `Groq API error ${res.status}${detail}`, _status: res.status, _groqBody: body };
    }
    return { success: true, data: body };
  } catch (e) {
    return { error: 'Network error reaching Groq API: ' + e.message };
  }
}

async function callGroq(apiKey, payload) {
  if (!(await isAiConsented())) return { error: AI_CONSENT_MSG, consentRequired: true };
  if (!apiKey) return { error: 'No Groq API key configured. Add it in Settings.' };
  await waitForGroqSlot();

  // BUG FIX (root cause of every AI tool failing — Tone, Calendar, Actions,
  // Digest, Labels, Coach — with "Invalid JSON from AI" / "unreadable
  // response"): openai/gpt-oss-120b is a REASONING model. Its hidden
  // "thinking" tokens are drawn from the SAME max_tokens budget as the
  // final answer. Every caller in this file set max_tokens for a plain
  // non-reasoning model (400-900), so the model's own reasoning silently
  // consumed the entire budget and the response was truncated before it
  // ever emitted the JSON. Force low reasoning effort (these are simple
  // extraction/classification tasks, not ones that benefit from deep
  // reasoning) and guarantee a token floor large enough to cover reasoning
  // + the actual answer.
  const isReasoningModel = /gpt-oss/i.test(payload.model || '');
  let attemptPayload = payload;
  if (isReasoningModel) {
    attemptPayload = {
      ...payload,
      reasoning_effort: payload.reasoning_effort || 'low',
      // BUG FIX: 1536 still wasn't enough — confirmed by a real response
      // that got cut off mid-string with no closing brace at all. Raised
      // to 4096; that's the reasoning budget PLUS the JSON answer combined,
      // and these are short structured outputs so there's plenty of margin.
      max_tokens: Math.max(payload.max_tokens || 0, 4096)
    };
  }

  let result = await callGroqOnce(apiKey, attemptPayload);

  // BUG FIX: if adding reasoning_effort causes Groq to reject the request
  // (400 — e.g. the account/API version doesn't accept that field), don't
  // let that turn into "every AI tool is now broken." Retry once with the
  // original reasoning_effort-free payload, still keeping the raised token
  // floor so truncation is at least less likely.
  if (result.error && result._status === 400 && isReasoningModel && attemptPayload.reasoning_effort) {
    const fallbackPayload = { ...payload, max_tokens: attemptPayload.max_tokens };
    delete fallbackPayload.reasoning_effort;
    result = await callGroqOnce(apiKey, fallbackPayload);
  }

  if (result.error) return { error: result.error };
  const data = result.data;

  // BUG FIX: the previous check only fired when `content` was completely
  // EMPTY. A real captured response showed Groq returning finish_reason
  // "length" together with a non-empty but mid-string, no-closing-brace
  // partial JSON body — that content is truthy, so it silently passed this
  // check and fell through to a generic downstream "Invalid JSON" error
  // instead of the clear, actionable one below. Check finish_reason
  // directly instead of inferring truncation from an empty string.
  const choice = data.choices?.[0];
  if (choice?.finish_reason === 'length') {
    return { error: 'Groq cut the response short before it finished (ran out of tokens mid-response). Try again — if it keeps happening on this email, the content may just be unusually long.' };
  }

  return { success: true, data };
}

// BUG FIX: shared, robust JSON extractor for every AI handler below.
// Previously only analyzeToneAndManipulation() had this hardened logic
// (strip fences, extract outermost {...}, sanitize stray control chars);
// classifyAndAnalyzeEmail, coachOutgoingEmail, extractCalendarEvents,
// extractActionItems, suggestGmailLabels, and generateInboxDigest all did a
// bare `text.replace(/```json|```/g,'').trim()` then JSON.parse — so any
// leading preamble text, trailing commentary, or literal newline inside a
// quoted string from the model would break them even once the response
// wasn't truncated. One shared helper now backs all of them.
function parseAIJson(text) {
  let clean = (text || '').replace(/```json|```/g, '').trim();
  const jsonStart = clean.indexOf('{');
  const jsonEnd = clean.lastIndexOf('}');
  if (jsonStart !== -1 && jsonEnd !== -1) {
    clean = clean.substring(jsonStart, jsonEnd + 1);
  }

  // BUG FIX: this used to regex-replace EVERY raw control character in the
  // whole string, including plain newlines the model uses only to
  // pretty-print indentation between tokens — e.g. a real newline right
  // after the opening brace in `{\n  "category": ...`. Converting that
  // formatting newline into a literal backslash+n put a bare backslash
  // OUTSIDE any quoted string, which is invalid JSON on its own — exactly
  // "Expected property name or '}'" at the position right after `{`. That
  // broke every response the model happened to pretty-print, regardless of
  // truncation. Control characters only need escaping when they appear
  // INSIDE a string value; outside strings they're insignificant
  // whitespace JSON.parse already ignores. Walk the text tracking whether
  // we're inside a string and only touch control chars there — and copy
  // existing backslash-escapes (\", \\, \n, etc.) through untouched rather
  // than re-processing the character after the backslash.
  let out = '';
  let inString = false;
  for (let i = 0; i < clean.length; i++) {
    const ch = clean[i];
    if (inString) {
      if (ch === '\\' && i + 1 < clean.length) {
        out += ch + clean[i + 1];
        i++;
        continue;
      }
      if (ch === '"') { inString = false; out += ch; continue; }
      const code = ch.charCodeAt(0);
      if (code <= 0x1F || code === 0x7F) {
        if (ch === '\n') out += '\\n';
        else if (ch === '\r') out += '\\r';
        else if (ch === '\t') out += '\\t';
        // else: drop other stray control chars
        continue;
      }
      out += ch;
    } else {
      if (ch === '"') inString = true;
      out += ch; // structural whitespace outside strings passes through untouched
    }
  }

  return JSON.parse(out); // throws on failure — caller decides the error message
}

// ─── Encrypted API Key Storage (AES-GCM, non-extractable key) ────────────────
// API keys live ONLY as AES-GCM ciphertext in chrome.storage.local
// (phishalert_enc_api_keys). The AES key is a NON-EXTRACTABLE CryptoKey held in
// IndexedDB: its raw bytes are never exposed to JavaScript and are never written
// to chrome.storage, so the storage blob alone cannot be decrypted by reading
// storage (the old design kept a raw seed right beside the ciphertext).
// Plaintext copies in phishalert_settings are migrated out and deleted.

const ENC_KEYS_STORAGE = 'phishalert_enc_api_keys';
const LEGACY_SEED_STORAGE = 'phishalert_enc_key_iv';   // old design: raw seed next to ciphertext
const KEYSTORE_DB = 'phishalert_keystore';
const KEYSTORE_STORE = 'keys';
const KEYSTORE_ID = 'api-key-wrap-v2';
const KEY_FIELDS = ['vtApiKey', 'groqApiKey', 'gsbApiKey', 'phishtankApiKey', 'canaryApiKey'];

function emptyApiKeys() {
  const o = {};
  KEY_FIELDS.forEach(f => { o[f] = ''; });
  return o;
}

function normalizeApiKeys(obj) {
  const o = emptyApiKeys();
  if (obj && typeof obj === 'object') {
    KEY_FIELDS.forEach(f => { if (typeof obj[f] === 'string') o[f] = obj[f]; });
  }
  return o;
}

// Remove every API-key field from a settings object (never persist / return them there).
function stripKeyFields(settings) {
  const out = { ...(settings || {}) };
  KEY_FIELDS.forEach(f => { delete out[f]; });
  return out;
}

// ── IndexedDB keystore ──
function openKeystore() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(KEYSTORE_DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(KEYSTORE_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('Keystore unavailable'));
  });
}

function idbRequest(db, mode, fn) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEYSTORE_STORE, mode);
    const req = fn(tx.objectStore(KEYSTORE_STORE));
    tx.oncomplete = () => resolve(req ? req.result : undefined);
    tx.onerror = () => reject(tx.error || new Error('Keystore transaction failed'));
    tx.onabort = () => reject(tx.error || new Error('Keystore transaction aborted'));
  });
}

let _wrapKeyPromise = null;
// createIfMissing=false lets decrypt paths avoid minting a fresh key that could never match old ciphertext.
async function getWrapKey(createIfMissing) {
  if (_wrapKeyPromise) return _wrapKeyPromise;
  _wrapKeyPromise = (async () => {
    const db = await openKeystore();
    try {
      let key = await idbRequest(db, 'readonly', st => st.get(KEYSTORE_ID));
      if (!key && createIfMissing) {
        key = await crypto.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          false,                       // non-extractable: raw key bytes can never be read back
          ['encrypt', 'decrypt']
        );
        await idbRequest(db, 'readwrite', st => st.put(key, KEYSTORE_ID));
      }
      return key || null;
    } finally {
      db.close();
    }
  })();
  try {
    const k = await _wrapKeyPromise;
    if (!k) _wrapKeyPromise = null;    // don't cache a miss
    return k;
  } catch (e) {
    _wrapKeyPromise = null;
    throw e;
  }
}

async function deleteKeystore() {
  _wrapKeyPromise = null;
  await new Promise(resolve => {
    try {
      const req = indexedDB.deleteDatabase(KEYSTORE_DB);
      req.onsuccess = req.onerror = req.onblocked = () => resolve();
    } catch (e) { resolve(); }
  });
}

// ── Serialize every read-modify-write of the key blob ──
let _keyLock = Promise.resolve();
function withKeyLock(fn) {
  const run = _keyLock.then(fn, fn);
  _keyLock = run.catch(() => { });
  return run;
}

async function writeEncryptedBlob(keys) {
  const key = await getWrapKey(true);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(normalizeApiKeys(keys)));
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  await chrome.storage.local.set({
    [ENC_KEYS_STORAGE]: { v: 2, iv: Array.from(iv), ct: Array.from(new Uint8Array(ciphertext)) }
  });
}

async function readEncryptedBlob() {
  const stored = await chrome.storage.local.get(ENC_KEYS_STORAGE);
  const enc = stored[ENC_KEYS_STORAGE];
  if (!enc || enc.v !== 2) return null;               // absent, or legacy blob handled by migration
  const key = await getWrapKey(false);
  if (!key) return null;                              // keystore wiped: ciphertext is unrecoverable
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(enc.iv) }, key, new Uint8Array(enc.ct)
  );
  return normalizeApiKeys(JSON.parse(new TextDecoder().decode(plain)));
}

// Decrypt a blob written by the old design (needs the on-disk seed; used only to migrate).
async function readLegacyBlob(enc, seedArr) {
  const seed = new Uint8Array(seedArr);
  const material = await crypto.subtle.importKey('raw', seed, { name: 'PBKDF2' }, false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: new TextEncoder().encode('PhishAlert-v3-salt'), iterations: 100000, hash: 'SHA-256' },
    material, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
  );
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(enc.iv) }, key, new Uint8Array(enc.ct)
  );
  return normalizeApiKeys(JSON.parse(new TextDecoder().decode(plain)));
}

// One-time migration: legacy seed+blob and plaintext settings -> non-extractable-key blob.
// Idempotent and safe to call on every read; does nothing once there is nothing legacy left.
async function migrateApiKeysIfNeeded() {
  const data = await chrome.storage.local.get([ENC_KEYS_STORAGE, LEGACY_SEED_STORAGE, 'phishalert_settings']);
  const settings = data.phishalert_settings || {};
  const hasPlaintext = KEY_FIELDS.some(f => typeof settings[f] === 'string' && settings[f]);
  const hasSettingsFields = KEY_FIELDS.some(f => f in settings);
  const blob = data[ENC_KEYS_STORAGE];
  const legacySeed = data[LEGACY_SEED_STORAGE];
  const blobIsLegacy = !!blob && blob.v !== 2;
  if (!hasSettingsFields && !legacySeed && !blobIsLegacy) return;

  // Gather everything we know, newest source last so an explicit plaintext value is not lost.
  let merged = emptyApiKeys();
  let current = null;
  try { current = await readEncryptedBlob(); } catch (e) { current = null; }
  if (current) merged = { ...merged, ...current };

  if (blobIsLegacy && legacySeed) {
    try {
      const old = await readLegacyBlob(blob, legacySeed);
      KEY_FIELDS.forEach(f => { if (old[f]) merged[f] = old[f]; });
    } catch (e) { /* undecryptable legacy blob: fall through, plaintext may still recover keys */ }
  }
  if (hasPlaintext) {
    KEY_FIELDS.forEach(f => { if (typeof settings[f] === 'string' && settings[f] && !settings[f].includes('•')) merged[f] = settings[f]; });
  }

  const anyKey = KEY_FIELDS.some(f => merged[f]);
  if (anyKey) await writeEncryptedBlob(merged);
  else if (blobIsLegacy) await chrome.storage.local.remove(ENC_KEYS_STORAGE);

  // Only after the new ciphertext is safely stored: remove plaintext + the raw seed.
  if (hasSettingsFields) await chrome.storage.local.set({ phishalert_settings: stripKeyFields(settings) });
  if (legacySeed) await chrome.storage.local.remove(LEGACY_SEED_STORAGE);
}

async function encryptApiKeys(keys) {
  // keys: any subset/superset of KEY_FIELDS; stored as the full normalized object
  try {
    await withKeyLock(async () => {
      await migrateApiKeysIfNeeded();
      await writeEncryptedBlob(keys);
    });
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// Atomic read-modify-write of the key blob: two overlapping saves can no longer
// overwrite each other's keys. mutate(currentKeys) returns the full new key object.
async function updateApiKeys(mutate) {
  try {
    await withKeyLock(async () => {
      await migrateApiKeysIfNeeded();
      const current = (await readEncryptedBlob().catch(() => null)) || emptyApiKeys();
      await writeEncryptedBlob(mutate(current));
    });
    return { success: true };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

async function decryptApiKeys() {
  try {
    return await withKeyLock(async () => {
      await migrateApiKeysIfNeeded();
      return await readEncryptedBlob();
    });
  } catch (e) {
    return null;
  }
}

// Helper: get API keys. Always returns every field; never falls back to plaintext settings
// (migration has already moved and erased any plaintext copies).
async function getApiKeys() {
  const decrypted = await decryptApiKeys();
  return decrypted ? normalizeApiKeys(decrypted) : emptyApiKeys();
}

// ─── RDAP Domain Age Lookup ──────────────────────────────────────────────────
async function getRDAPDomainAge(domain) {
  // Registries only know registrable domains: rdap.org answers 404 for "customers.gumroad.com",
  // which showed up as "Age unknown" for any sender on a subdomain. Ask about the root instead.
  domain = getRootDomain(domain) || domain;
  const cacheKey = `rdap:${domain}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  try {
    // Try the RDAP lookup via rdap.org (public, no auth needed)
    const res = await fetch(`https://rdap.org/domain/${domain}`, {
      headers: { 'Accept': 'application/json' }
    });
    if (!res.ok) return { ageInDays: null, registrationDate: null, error: 'RDAP lookup failed' };

    const data = await res.json();
    const events = data.events || [];
    const regEvent = events.find(e => e.eventAction === 'registration');
    if (!regEvent) return { ageInDays: null, registrationDate: null, error: 'No registration date found' };

    const regDate = new Date(regEvent.eventDate);
    const ageInDays = Math.floor((Date.now() - regDate.getTime()) / (1000 * 60 * 60 * 24));
    const result = { ageInDays, registrationDate: regEvent.eventDate, error: null };

    await setCache(cacheKey, result);
    return result;
  } catch (e) {
    return { ageInDays: null, registrationDate: null, error: e.message };
  }
}

// ─── VirusTotal Domain Lookup ────────────────────────────────────────────────
async function checkVirusTotal(domain, apiKey) {
  if (!apiKey) return { available: false, error: 'No API key configured' };

  const cacheKey = `vt:${domain}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  // UPGRADE 4: Quota check before making the request
  if (!(await canUseVT())) {
    return { available: false, error: 'Daily VirusTotal quota reached (500/day). Resets at midnight.' };
  }

  // UPGRADE 4: Throttle concurrent requests
  await waitForVTSlot();

  try {
    const res = await fetch(`https://www.virustotal.com/api/v3/domains/${domain}`, {
      headers: { 'x-apikey': apiKey }
    });

    if (res.status === 401) return { available: false, error: 'Invalid API key' };
    if (res.status === 429) return { available: false, error: 'API rate limit reached' };
    if (!res.ok) return { available: false, error: `VT error: ${res.status}` };

    const data = await res.json();
    const stats = data.data?.attributes?.last_analysis_stats || {};
    const totalEngines = (stats.malicious || 0) + (stats.suspicious || 0) +
      (stats.harmless || 0) + (stats.undetected || 0);
    const maliciousCount = (stats.malicious || 0) + (stats.suspicious || 0);

    const result = {
      available: true,
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      totalEngines,
      maliciousCount,
      isMalicious: maliciousCount > 2,
      reputation: data.data?.attributes?.reputation || 0,
      categories: data.data?.attributes?.categories || {},
      error: null
    };

    await incrementVTQuota();
    await setCache(cacheKey, result);
    return result;
  } catch (e) {
    return { available: false, error: e.message };
  }
}


// ─── FEATURE NEW 2: Abuse.ch URLhaus — Free Malware URL Feed ─────────────────
// No API key needed. Checks full URL + hostname against live malware database.
// 15-minute cache (feed updates constantly, unlike VirusTotal's daily quota).
const URLHAUS_LOOKUP = 'https://urlhaus-api.abuse.ch/v1/url/';
const URLHAUS_HOST_LK = 'https://urlhaus-api.abuse.ch/v1/host/';
const URLHAUS_CACHE_TTL = 15 * 60 * 1000; // 15 minutes

async function checkURLhaus(url) {
  const cacheKey = `urlhaus:${url}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  let result = { malicious: false, threat: null, tags: [], source: 'urlhaus' };

  try {
    // 1. Full URL lookup
    const body = new URLSearchParams({ url });
    const res = await fetch(URLHAUS_LOOKUP, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
      signal: AbortSignal.timeout(5000)
    });
    if (res.ok) {
      const data = await res.json();
      if (data.query_status === 'is_available' && data.url_status === 'online') {
        result = {
          malicious: true,
          threat: data.threat || 'Malware distribution URL',
          tags: data.tags || [],
          source: 'urlhaus',
          reporter: data.reporter,
          dateAdded: data.date_added
        };
      }
    }

    // 2. Hostname lookup if URL not found
    if (!result.malicious) {
      let hostname = '';
      try { hostname = new URL(url).hostname; } catch { hostname = ''; }
      if (hostname) {
        const hRes = await fetch(URLHAUS_HOST_LK, {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ host: hostname }).toString(),
          signal: AbortSignal.timeout(5000)
        });
        if (hRes.ok) {
          const hData = await hRes.json();
          if (hData.query_status === 'is_available' && hData.urls?.length) {
            const live = hData.urls.filter(u => u.url_status === 'online');
            if (live.length > 0) {
              result = {
                malicious: true,
                threat: `Host serves malware (${live.length} active URL${live.length > 1 ? 's' : ''})`,
                tags: [...new Set(live.flatMap(u => u.tags || []))],
                source: 'urlhaus_host'
              };
            }
          }
        }
      }
    }
  } catch (e) {
    console.warn('[PhishAlert] URLhaus check failed:', e.message);
  }

  // Short TTL so fresh threats are caught quickly
  try {
    const storageKey = `phishalert_cache_${cacheKey}`;
    await chrome.storage.local.set({ [storageKey]: { data: result, timestamp: Date.now() - (CACHE_EXPIRY_MS - URLHAUS_CACHE_TTL) } });
  } catch { }

  return result;
}

// ─── FEATURE NEW 6: Google Safe Browsing API ─────────────────────────────────
// One POST covers ALL links in an email. Free, no meaningful quota limit.
// Requires a GSB API key (stored alongside VT key in encrypted storage).
const GSB_API_BASE = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

async function checkGoogleSafeBrowsing(urls, gsbApiKey) {
  if (!gsbApiKey || !urls || urls.length === 0) {
    return { available: false, matches: [], error: gsbApiKey ? 'No URLs' : 'No GSB API key' };
  }

  // Deduplicate and limit to 500 URLs per request (GSB limit)
  const uniqueUrls = [...new Set(urls)].slice(0, 500);
  const cacheKey = `gsb:${uniqueUrls.slice(0, 3).join('|')}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  const body = {
    client: { clientId: 'PhishAlert', clientVersion: '5.0' },
    threatInfo: {
      threatTypes: [
        'MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE',
        'POTENTIALLY_HARMFUL_APPLICATION', 'THREAT_TYPE_UNSPECIFIED'
      ],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: uniqueUrls.map(url => ({ url }))
    }
  };

  try {
    const res = await fetch(`${GSB_API_BASE}?key=${gsbApiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(6000)
    });

    if (res.status === 400) return { available: false, matches: [], error: 'Invalid GSB request' };
    if (res.status === 403) return { available: false, matches: [], error: 'Invalid GSB API key' };
    if (!res.ok) return { available: false, matches: [], error: `GSB error: ${res.status}` };

    const data = await res.json();
    // If no matches, data.matches is absent (not an empty array)
    const matches = (data.matches || []).map(m => ({
      url: m.threat?.url || '',
      threatType: m.threatType,
      platformType: m.platformType
    }));

    const result = {
      available: true,
      matches,
      isMalicious: matches.length > 0,
      checkedCount: uniqueUrls.length,
      error: null
    };

    await setCache(cacheKey, result);
    return result;
  } catch (e) {
    return { available: false, matches: [], error: e.message };
  }
}

// ─── FEATURE NEW 7: BIMI Record Check ────────────────────────────────────────
// BIMI (Brand Indicators for Message Identification) — major brands almost
// always publish BIMI. A domain *claiming* to be a major brand but lacking
// BIMI is a phishing signal.
const BIMI_BRANDS = new Set([
  'google', 'microsoft', 'apple', 'amazon', 'paypal', 'netflix', 'facebook',
  'instagram', 'twitter', 'linkedin', 'dropbox', 'slack', 'zoom', 'adobe',
  'salesforce', 'github', 'spotify', 'walmart', 'ebay', 'chase', 'wellsfargo',
  'citibank', 'barclays', 'hsbc', 'mastercard', 'visa', 'stripe', 'shopify',
  'intuit', 'quickbooks', 'turbotax', 'fedex', 'ups', 'dhl', 'usps'
]);

// Genuine root domains of the brands above. A brand's OWN domain is never "impersonating"
// itself, even when it publishes no BIMI record (google.com has none at default._bimi).
const BIMI_OFFICIAL_DOMAINS = new Set([
  'google.com', 'gmail.com', 'youtube.com', 'googlemail.com', 'microsoft.com', 'outlook.com',
  'live.com', 'office.com', 'microsoftonline.com', 'apple.com', 'icloud.com', 'amazon.com',
  'amazon.in', 'amazon.co.uk', 'amazonaws.com', 'paypal.com', 'netflix.com', 'facebook.com',
  'facebookmail.com', 'instagram.com', 'twitter.com', 'x.com', 'linkedin.com', 'dropbox.com',
  'slack.com', 'zoom.us', 'adobe.com', 'salesforce.com', 'github.com', 'spotify.com',
  'walmart.com', 'ebay.com', 'chase.com', 'wellsfargo.com', 'citi.com', 'citibank.com',
  'barclays.com', 'hsbc.com', 'mastercard.com', 'visa.com', 'stripe.com', 'shopify.com',
  'intuit.com', 'quickbooks.com', 'turbotax.com', 'fedex.com', 'ups.com', 'dhl.com', 'usps.com'
]);

async function checkBIMI(domain) {
  if (!domain) return { hasBIMI: false, checked: false };

  const cacheKey = `bimi2:${domain}`;   // bumped: old cached results carried the false positive
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  try {
    // BIMI record lives at default._bimi.<domain>
    const res = await dnsLookup(`default._bimi.${domain}`, 'TXT');
    const answers = res?.Answer || [];
    const bimiRecord = answers
      .map(r => r.data || '')
      .find(d => d.includes('v=BIMI1'));

    // Extract logo URL if present
    let logoUrl = null;
    let vmcUrl = null;
    if (bimiRecord) {
      const lMatch = bimiRecord.match(/l=([^;]+)/i);
      const aMatch = bimiRecord.match(/a=([^;]+)/i);
      logoUrl = lMatch ? lMatch[1].trim().replace(/^"|"$/g, '') : null;
      vmcUrl = aMatch ? aMatch[1].trim().replace(/^"|"$/g, '') : null;
    }

    const hasBIMI = !!bimiRecord;
    const hasVMC = !!vmcUrl && vmcUrl !== 'none'; // Verified Mark Certificate = strongest signal

    // Determine if this domain is impersonating a BIMI-publishing brand
    // Use the registrable domain (mail.google.com -> google.com), skip the brand's own
    // domains, and only match when the label CONTAINS the brand. The old reverse check
    // (brand.includes(label)) flagged short labels like "a", "am" or "uni" as amazon etc.
    const lowerDomain = domain.toLowerCase();
    const rootDomain = (typeof getRootDomain === 'function' ? getRootDomain(lowerDomain) : null) || lowerDomain;
    const isOfficial = BIMI_OFFICIAL_DOMAINS.has(rootDomain) || BIMI_OFFICIAL_DOMAINS.has(lowerDomain);
    const domainBase = rootDomain.split('.')[0];
    const claimedBrand = isOfficial ? undefined : [...BIMI_BRANDS].find(brand => domainBase.includes(brand));
    const isImpersonatingBrand = !!claimedBrand && !hasBIMI;

    const result = {
      hasBIMI,
      hasVMC,
      record: bimiRecord || null,
      logoUrl,
      vmcUrl,
      isImpersonatingBrand,
      claimedBrand: isImpersonatingBrand ? claimedBrand : null,
      detail: hasBIMI
        ? `BIMI record found${hasVMC ? ' with VMC (verified brand)' : ' (no VMC)'}`
        : isImpersonatingBrand
          ? `No BIMI record — "${claimedBrand}" always publishes BIMI; this domain is likely an impostor`
          : 'No BIMI record',
      checked: true
    };

    await setCache(cacheKey, result);
    return result;
  } catch (e) {
    return { hasBIMI: false, checked: false, error: e.message };
  }
}

// ─── FEATURE NEW 8: Email Encryption / TLS Transport Detection ────────────────
// Parses Received headers for TLS/STARTTLS/SMTPS indicators.
// An email from a bank arriving without TLS is a significant red flag.
//
// FIX (Bug #2): TLS-in-transit detection has been removed entirely. It relied
// on headers.receivedChain, which is NEVER populated with real Received-header
// data — content.js (Gmail) only fills it with lowercased UI tooltip text like
// "via mail.google.com" or "mailed-by gmail.com" (see content.js extractHeaders,
// ~line 336-344), and Outlook/Proton/Yahoo never populate it at all (they pass
// headers: {}). Gmail's web UI does not expose Received-header TLS/cipher
// strings to page scripts, so there was no way for tlsPattern to ever match
// real transport data — hasTLS was always false whenever receivedChain had any
// tooltip hint, which fired the high-severity "no_tls / sent in plaintext" flag
// on nearly every email, including genuinely TLS-encrypted ones. Rather than
// keep a heuristic that can never be fed real signal, TLS transport detection
// is dropped for all clients. S/MIME and PGP detection (based on actual
// Content-Type/body markers, not fabricated tooltip text) are kept as-is.
function detectEmailEncryption(headers) {
  const result = {
    hasSMIME: false,
    hasPGP: false,
    encryptionType: 'none',
    issues: []
  };

  // ── S/MIME detection (Content-Type header) ──
  // S/MIME signed: multipart/signed; protocol="application/pkcs7-signature"
  // S/MIME encrypted: application/pkcs7-mime
  const contentType = headers.contentType || '';
  if (/pkcs7-signature|smime/i.test(contentType)) {
    result.hasSMIME = true;
    result.encryptionType = /pkcs7-mime/i.test(contentType) ? 's/mime-encrypted' : 's/mime-signed';
  }

  // ── PGP detection ──
  // PGP messages contain BEGIN PGP or Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"
  const body = headers.body || '';
  const rawHeaders = headers.raw || '';
  if (/BEGIN PGP|pgp-encrypted|application\/pgp/i.test(body + rawHeaders + contentType)) {
    result.hasPGP = true;
    result.encryptionType = result.encryptionType === 'none' ? 'pgp' : result.encryptionType + '+pgp';
  }

  if (result.hasSMIME || result.hasPGP) {
    result.encryptionType = result.hasSMIME ? (result.hasPGP ? 's/mime+pgp' : result.encryptionType) : 'pgp';
  }

  return result;
}

// ─── FEATURE NEW 3: Full Redirect-Chain Follower ──────────────────────────────
// Follows hop-by-hop using HEAD requests. Checks every hop via URLhaus.
// Replaces the old "shortener domains only" approach.
const REDIRECT_MAX_HOPS = 10;

// FIX: hop-by-hop following does a live fetch() of whatever domain is in
// the email link, which is why the manifest used to request host access
// to every site ("https://*/*") at install time — a broad, always-on grant
// that's an easy flag for reviewers of a security extension. That access
// is now "optional_host_permissions" instead, granted only if the user
// opts in from Settings. Check it here and degrade gracefully rather than
// silently failing: without it we still report the link's own domain
// reputation (URLhaus etc. below take the URL as a request parameter, not
// as a fetch target, so they don't need this permission), we just can't
// follow the hop chain to see where a shortener/redirect actually lands.
async function hasFullHostPermission() {
  try {
    return await chrome.permissions.contains({ origins: ['https://*/*'] });
  } catch {
    return false;
  }
}

async function followRedirectChain(startUrl) {
  const chain = [startUrl];
  let current = startUrl;

  if (!(await hasFullHostPermission())) {
    return { finalUrl: startUrl, chain, hops: 0, crossDomain: false, limited: true };
  }

  for (let hop = 0; hop < REDIRECT_MAX_HOPS; hop++) {
    try {
      const res = await fetch(current, {
        method: 'HEAD',
        redirect: 'manual',
        signal: AbortSignal.timeout(5000)
      });
      const loc = res.headers.get('location');
      if ((res.status >= 300 && res.status < 400) && loc) {
        const next = new URL(loc, current).href;
        if (chain.includes(next)) break; // redirect loop guard
        chain.push(next);
        current = next;
      } else {
        break;
      }
    } catch {
      break; // network error or timeout — treat as final
    }
  }

  return {
    finalUrl: current,
    chain,
    hops: chain.length - 1,
    crossDomain: chain.length > 1 &&
      (() => { try { return new URL(chain[0]).hostname !== new URL(current).hostname; } catch { return false; } })(),
    limited: false
  };
}

async function scanRedirectChain(url, vtApiKey) {
  const redirect = await followRedirectChain(url);
  const threatHops = [];

  for (const hopUrl of redirect.chain) {
    try {
      const uh = await checkURLhaus(hopUrl);
      if (uh.malicious) threatHops.push({ url: hopUrl, ...uh });
    } catch { }
  }

  // VirusTotal on final URL if key available
  let vtFinal = null;
  if (vtApiKey && redirect.finalUrl !== url) {
    vtFinal = await checkVirusTotal(redirect.finalUrl, vtApiKey).catch(() => null);
  }

  return { ...redirect, threatHops, vtFinal };
}

// ─── URL Unshortener ─────────────────────────────────────────────────────────
async function unshortURL(url) {
  const cacheKey = `unshort:${url}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  const shortenerDomains = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
    'dlvr.it', 'ift.tt', 'tiny.cc', 'is.gd', 'su.pr', 'snip.ly',
    'rebrand.ly', 'shorte.st', 'adf.ly', 'linktr.ee', 'short.io'
  ];

  try {
    const urlObj = new URL(url);
    const isShortened = shortenerDomains.some(d => urlObj.hostname.includes(d));
    if (!isShortened) {
      const result = { originalUrl: url, finalUrl: url, wasShortened: false, error: null };
      await setCache(cacheKey, result);
      return result;
    }

    // Use the unshorten.me service
    const res = await fetch(`https://unshorten.me/json/${encodeURIComponent(url)}`);
    if (!res.ok) throw new Error('Unshorten service unavailable');

    const data = await res.json();
    const result = {
      originalUrl: url,
      finalUrl: data.resolved_url || url,
      wasShortened: true,
      requestsCount: data.usage_count || 0,
      error: null
    };

    await setCache(cacheKey, result);
    return result;
  } catch (e) {
    return { originalUrl: url, finalUrl: url, wasShortened: false, error: e.message };
  }
}

// ─── Attachment Scanner ──────────────────────────────────────────────────────
// Detects malicious patterns in attachments passed as base64 or metadata
async function scanAttachment(fileName, mimeType, base64Data) {
  const result = {
    fileName,
    mimeType,
    risks: [],
    riskLevel: 'safe', // safe | suspicious | dangerous
    detail: ''
  };

  const name = (fileName || '').toLowerCase();
  const ext = name.split('.').pop();

  // Double-extension trick (e.g. invoice.pdf.exe)
  const doublExt = name.match(/\.(pdf|doc|docx|xls|xlsx|zip|rar)\.(exe|bat|cmd|scr|vbs|ps1|js|jar|com|pif)$/i);
  if (doublExt) {
    result.risks.push('Double extension detected — disguised executable');
    result.riskLevel = 'dangerous';
  }

  // Directly dangerous file types
  const dangerousExts = ['exe', 'bat', 'cmd', 'scr', 'vbs', 'ps1', 'jar', 'com', 'pif', 'hta', 'reg', 'lnk', 'msi', 'dll'];
  if (dangerousExts.includes(ext)) {
    result.risks.push(`Executable file type (.${ext}) — high risk`);
    result.riskLevel = 'dangerous';
  }

  // Macro-enabled Office documents
  const macroExts = ['docm', 'xlsm', 'pptm', 'dotm', 'xltm', 'potm'];
  if (macroExts.includes(ext)) {
    result.risks.push('Macro-enabled Office document — can run malicious code');
    result.riskLevel = result.riskLevel === 'dangerous' ? 'dangerous' : 'suspicious';
  }

  // Password-protected ZIPs (common in malware delivery — we can only detect by name/context)
  if ((ext === 'zip' || ext === 'rar' || ext === '7z') && name.includes('password')) {
    result.risks.push('Password-protected archive — common malware delivery technique');
    result.riskLevel = result.riskLevel === 'dangerous' ? 'dangerous' : 'suspicious';
  }

  // Scan base64 content for script/macro signatures if provided
  if (base64Data) {
    try {
      // Decode a sample of the base64 for signature scanning
      const sample = atob(base64Data.substring(0, 2000));
      const macroSignatures = [
        'AutoOpen', 'AutoExec', 'Shell(', 'WScript.Shell',
        'powershell', 'cmd.exe', 'CreateObject', 'XMLHTTP',
        'eval(', 'document.write(', '<script', 'ActiveXObject'
      ];
      for (const sig of macroSignatures) {
        if (sample.toLowerCase().includes(sig.toLowerCase())) {
          result.risks.push(`Suspicious code signature: "${sig}"`);
          result.riskLevel = 'dangerous';
          break;
        }
      }
    } catch (e) { /* ignore decode errors */ }
  }

  if (result.risks.length === 0) {
    result.detail = 'No suspicious patterns detected';
  } else {
    result.detail = result.risks[0];
  }

  return result;
}

// ─── Email Header Analyzer (legacy wrapper → deep analyzer) ──────────────────
function analyzeEmailHeaders(headers) {
  return analyzeHeadersDeep(headers);
}

// ─── Pixel Tracker Detector ──────────────────────────────────────────────────
function detectPixelTrackers(htmlContent) {
  const trackers = [];
  // Known tracker domains
  const trackerDomains = [
    'trk.', 'track.', 'open.', 'pixel.', 'e.', 'click.',
    'sendgrid.net', 'mailchimp.com', 'mandrillapp.com',
    'mailgun.org', 'exacttarget.com', 'salesforce.com',
    'hubspot.com', 'marketo.net', 'pardot.com', 'eloqua.com',
    'constantcontact.com', 'campaignmonitor.com', 'klaviyo.com',
    'mailjet.com', 'sendinblue.com', 'getresponse.com',
    'aweber.com', 'convertkit.com', 'drip.com', 'intercom.io',
    'spy.1and1.com', 'r.email'
  ];

  // Pattern: tiny images (1x1, 0x0, or no dimension = hidden)
  const imgRegex = /<img[^>]*>/gi;
  const imgs = htmlContent.match(imgRegex) || [];

  for (const img of imgs) {
    const widthMatch = img.match(/width\s*=\s*["']?(\d+)/i);
    const heightMatch = img.match(/height\s*=\s*["']?(\d+)/i);
    const srcMatch = img.match(/src\s*=\s*["']([^"']+)["']/i);

    if (!srcMatch) continue;
    const src = srcMatch[1];

    const isTiny = (
      (widthMatch && parseInt(widthMatch[1]) <= 1) ||
      (heightMatch && parseInt(heightMatch[1]) <= 1) ||
      img.includes('width:0') || img.includes('height:0') ||
      img.includes('display:none') || img.includes('visibility:hidden')
    );

    const isTrackerDomain = trackerDomains.some(d => src.toLowerCase().includes(d));

    if (isTiny || isTrackerDomain) {
      let domain = '';
      try { domain = new URL(src.startsWith('http') ? src : 'https:' + src).hostname; } catch (e) { }
      trackers.push({
        src: src.substring(0, 100),
        domain,
        isTiny,
        isTrackerDomain,
        reason: isTiny ? '1×1 invisible pixel' : 'Known tracker domain'
      });
    }
  }

  return { trackerCount: trackers.length, trackers };
}

// ─── QR Code URL Extractor ────────────────────────────────────────────────────
// We don't decode QR images natively (no canvas in SW), but we detect QR
// image attachments and URLs embedded near "qr" context words in email HTML
function detectQRCodeLinks(htmlContent) {
  const findings = [];

  // Detect <img> tags that likely contain QR codes by alt/title/src hints
  const qrImgRegex = /<img[^>]*(qr[_-]?code|qrcode|scan[\s_-]?me|scan[\s_-]?to)[^>]*>/gi;
  const qrImgs = htmlContent.match(qrImgRegex) || [];
  for (const img of qrImgs) {
    findings.push({
      type: 'qr_image_detected',
      detail: 'QR code image found in email — destination URL cannot be previewed',
      severity: 'warning'
    });
  }

  // Detect data-URI QR codes (base64 embedded)
  // FIX: previously checked htmlContent.includes('data:image') && /qr/i.test(htmlContent)
  // as two INDEPENDENT checks over the whole email — so any email with any inline
  // image (logo, signature, tracking pixel — extremely common) plus the substring
  // "qr" appearing ANYWHERE else in the markup (hidden icon classes like
  // "icon-qrcode", tracking IDs, hashed params) triggered a false "QR detected"
  // banner even with zero actual QR codes present. Now scoped like qrImgRegex
  // above: the QR keyword must appear inside the SAME <img> tag as the data-URI.
  const dataImgRegex = /<img[^>]*src\s*=\s*["']data:image[^"']*["'][^>]*>/gi;
  const dataImgs = htmlContent.match(dataImgRegex) || [];
  for (const img of dataImgs) {
    if (/qr[_-]?code|qrcode|scan[\s_-]?(me|to|here)/i.test(img)) {
      findings.push({
        type: 'embedded_qr',
        detail: 'Embedded image with QR context detected — inspect before scanning',
        severity: 'warning'
      });
    }
  }

  // Detect text mentioning "scan QR" near a URL
  const scanQRPattern = /scan\s+(this\s+)?(qr|code|barcode)[^.]*?(https?:\/\/[^\s"'<>]+)/gi;
  let m;
  while ((m = scanQRPattern.exec(htmlContent)) !== null) {
    findings.push({
      type: 'qr_url_in_text',
      url: m[3].substring(0, 200),
      detail: `QR code mentions URL: ${m[3].substring(0, 80)}`,
      severity: 'suspicious'
    });
  }

  return { qrFindings: findings, qrCount: findings.length };
}

// ─── Sender History / Trust Score ─────────────────────────────────────────────
async function getSenderHistory(email, domain) {
  const emailKey = 'phishalert_sender_history';
  const domainKey = 'phishalert_domain_history';
  
  const [emailData, domainData] = await Promise.all([
    chrome.storage.local.get(emailKey),
    chrome.storage.local.get(domainKey)
  ]);
  
  const eHist = emailData[emailKey] || {};
  const dHist = domainData[domainKey] || {};
  
  return {
    email: eHist[email] || { replyCount: 0, seenCount: 0, firstSeen: null, lastSeen: null },
    domain: dHist[domain] || { replyCount: 0, seenCount: 0, firstSeen: null, lastSeen: null }
  };
}

async function recordSenderInteraction(email, type, domain) {
  // type: 'seen' | 'replied'
  const emailKey = 'phishalert_sender_history';
  const domainKey = 'phishalert_domain_history';
  
  const [emailData, domainData] = await Promise.all([
    chrome.storage.local.get(emailKey),
    chrome.storage.local.get(domainKey)
  ]);
  
  const eHist = emailData[emailKey] || {};
  const dHist = domainData[domainKey] || {};

  // Update Email History
  if (!eHist[email]) {
    eHist[email] = { replyCount: 0, seenCount: 0, firstSeen: Date.now(), lastSeen: Date.now() };
  }
  eHist[email].lastSeen = Date.now();
  if (type === 'replied') eHist[email].replyCount = (eHist[email].replyCount || 0) + 1;
  if (type === 'seen') eHist[email].seenCount = (eHist[email].seenCount || 0) + 1;

  // Update Domain History (Enterprise resilience)
  if (domain) {
    if (!dHist[domain]) {
      dHist[domain] = { replyCount: 0, seenCount: 0, firstSeen: Date.now(), lastSeen: Date.now() };
    }
    dHist[domain].lastSeen = Date.now();
    if (type === 'replied') dHist[domain].replyCount = (dHist[domain].replyCount || 0) + 1;
    if (type === 'seen') dHist[domain].seenCount = (dHist[domain].seenCount || 0) + 1;
  }

  await Promise.all([
    chrome.storage.local.set({ [emailKey]: eHist }),
    chrome.storage.local.set({ [domainKey]: dHist })
  ]);
  
  return eHist[email];
}

async function getSenderTrustFromHistory(email, domain) {
  const h = await getSenderHistory(email, domain);
  let trustBonus = 0;
  let label = 'First contact';

  const e = h.email;
  const d = h.domain;

  // Domain-level trust (harder to spoof by changing user part)
  if (d.replyCount >= 20) trustBonus += 15;
  else if (d.replyCount >= 5) trustBonus += 8;
  
  // Individual-level trust
  if (e.replyCount >= 10) { trustBonus += 20; label = 'Frequent contact'; }
  else if (e.replyCount >= 3) { trustBonus += 12; label = 'Known contact'; }
  else if (e.replyCount >= 1) { trustBonus += 6; label = 'Previously replied'; }
  else if (e.seenCount >= 5) { trustBonus += 3; label = 'Seen before'; }

  return { ...e, trustBonus, label, domainTrust: d.replyCount > 0 };
}

// ─── Community Report Storage ────────────────────────────────────────────────
async function saveCommunityReport(domain, reporterNote) {
  const key = 'phishalert_reports';
  const existing = await chrome.storage.local.get(key);
  const reports = existing[key] || {};

  if (!reports[domain]) {
    reports[domain] = { count: 0, firstReported: Date.now(), notes: [] };
  }
  reports[domain].count += 1;
  reports[domain].lastReported = Date.now();
  if (reporterNote) {
    reports[domain].notes.push({ note: reporterNote, time: Date.now() });
  }

  await chrome.storage.local.set({ [key]: reports });
  return reports[domain];
}

async function getCommunityReports() {
  const key = 'phishalert_reports';
  const existing = await chrome.storage.local.get(key);
  return existing[key] || {};
}

async function checkCommunityReport(domain) {
  const reports = await getCommunityReports();
  return reports[domain] || null;
}

// ─── DNS Lookup ──────────────────────────────────────────────────────────────
// FIX: dnsLookup used to have no timeout and no retry, and treated a failed
// request the same as a confirmed "no record" (both returned null). Under
// bursty concurrent load (e.g. 40 parallel DKIM selector checks) that meant
// a transient network hiccup or resolver throttle looked identical to the
// domain genuinely lacking a record — a real DKIM pass could get reported
// as a fail depending on network timing alone.
// Now a request failure/timeout returns { __networkError: true } instead of
// null, and gets one retry, so callers can tell "confirmed absent" apart
// from "couldn't check."
async function dnsLookup(name, type, opts = {}) {
  const { timeoutMs = 4000, retries = 1 } = opts;
  const cacheKey = `dns:${name}:${type}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  const url = `https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
      if (!res.ok) {
        if (attempt < retries) continue;
        return { __networkError: true };
      }
      const data = await res.json();
      await setCache(cacheKey, data);
      return data;
    } catch (e) {
      if (attempt < retries) continue;
      return { __networkError: true };
    }
  }
  return { __networkError: true }; // unreachable, but keeps the function total
}

// ─── Groq AI Chat ────────────────────────────────────────────────────────────
async function aiChatGroq(messages, scanContext, apiKey) {
  if (!apiKey) return { error: 'No Groq API key configured. Add it in Settings.' };

  // Build system prompt with injected scan context
  let systemPrompt = `You are PhishAlert AI, a friendly email security expert built into the PhishAlert browser extension.
Your job is to help users understand email threats in plain, simple English — no jargon unless asked.

Always:
- Be concise (2-4 sentences unless asked for detail)
- Give a clear recommendation (safe to ignore / report it / block sender)
- Explain technical terms only if the user asks
- Never be alarmist — be calm and helpful`;

  if (scanContext) {
    systemPrompt += `\n\nCurrent email scan results:
- Sender Domain: ${scanContext.domain || 'unknown'}
- Trust Score: ${scanContext.score !== undefined ? scanContext.score + '/100' : 'unknown'}
- SPF: ${scanContext.spf || 'unknown'}
- DKIM: ${scanContext.dkim || 'unknown'}
- DMARC: ${scanContext.dmarc || 'unknown'}
- Domain Age: ${scanContext.domainAge || 'unknown'}
- VirusTotal: ${scanContext.vtResult || 'not checked'}
- Threats Detected: ${scanContext.threats && scanContext.threats.length > 0 ? scanContext.threats.join(', ') : 'none'}
- Is Trusted: ${scanContext.isTrusted ? 'Yes' : 'No'}

Use this context to answer questions about this specific email. If no question is asked yet, give a brief plain-English summary of the risk and what the user should do.`;
  }

  // Groq uses OpenAI-compatible format
  const payload = {
    model: 'openai/gpt-oss-120b',
    max_tokens: 1024,
    temperature: 0.7,
    messages: [
      { role: 'system', content: systemPrompt },
      ...messages
    ]
  };

  const result = await callGroq(apiKey, payload);
  if (result.error) return result;

  const data = result.data;
  const text = data.choices && data.choices[0] && data.choices[0].message && data.choices[0].message.content;
  if (!text) return { error: 'Empty response from Groq.' };
  return { reply: text };
}

// ─── OpenClaw Email Intelligence ─────────────────────────────────────────────

async function classifyAndAnalyzeEmail(subject, body, apiKey) {
  if (!apiKey) return { error: 'No Groq API key configured. Add it in Settings.' };

  const truncated = body.substring(0, 2500);
  const prompt = `You are an AI email classifier. Analyze this email and respond ONLY with valid JSON — no markdown, no backticks, no explanation.

Subject: ${subject}
Body: ${truncated}

Return exactly this JSON structure:
{
  "category": "Work|Personal|Urgent|Spam|Promotional|Finance|Newsletter|Social",
  "priority": "High|Medium|Low",
  "priorityReason": "one concise sentence",
  "summary": "2-3 sentence plain English summary",
  "keyPoints": ["point1", "point2", "point3"],
  "actionItems": ["action1", "action2"],
  "deadline": "specific deadline string or null",
  "suggestedTone": "Formal|Friendly|Brief"
}`;

  const result = await callGroq(apiKey, {
    model: 'openai/gpt-oss-120b',
    max_tokens: 600,
    temperature: 0.3,
    messages: [{ role: 'user', content: prompt }]
  });
  if (result.error) return result;

  const text = result.data.choices?.[0]?.message?.content || '';
  try {
    return { success: true, ...parseAIJson(text) };
  } catch (parseErr) {
    return { error: "Analysis failed: the AI's response wasn't valid JSON. Try again.", _parseError: parseErr.message };
  }
}

async function draftEmailReply(subject, body, tone, apiKey) {
  if (!apiKey) return { error: 'No Groq API key configured. Add it in Settings.' };

  const toneMap = {
    formal: 'Write in a formal, professional tone with proper salutation and sign-off.',
    friendly: 'Write in a warm, friendly tone. Be conversational but still professional.',
    brief: 'Write an extremely brief reply — 2-3 sentences maximum. Get straight to the point.'
  };

  const prompt = `You are an expert email writer. Draft a reply to the following email.
${toneMap[tone] || toneMap.formal}
Write ONLY the reply text. No subject line, no explanation, no placeholders like [Your Name].

Original Subject: ${subject}
Original Email:
${body.substring(0, 2000)}`;

  const result = await callGroq(apiKey, {
    model: 'openai/gpt-oss-120b',
    max_tokens: 400,
    temperature: 0.7,
    messages: [{ role: 'user', content: prompt }]
  });
  if (result.error) return result;

  return { success: true, draft: result.data.choices?.[0]?.message?.content || '' };
}

// ─── FEATURE 1: Tone / Manipulation Analyzer ─────────────────────────────────
async function analyzeToneAndManipulation(subject, body, apiKey) {
  if (!apiKey) return { error: 'No Groq API key configured. Add it in Settings.' };

  const prompt = `You are a psychological manipulation detection expert. Analyze this email for manipulative tactics and respond ONLY with valid JSON — no markdown, no backticks.

Subject: ${subject}
Body: ${body.substring(0, 2500)}

Identify ALL manipulation tactics present. Return exactly this JSON:
{
  "tactics": [
    {
      "type": "urgency|fear|authority|scarcity|social_proof|guilt|flattery|none",
      "label": "short human-readable name",
      "severity": "high|medium|low",
      "evidence": "exact phrase or sentence from the email that shows this tactic",
      "explanation": "one sentence explaining why this is manipulative"
    }
  ],
  "overallRisk": "high|medium|low|safe",
  "summary": "2-sentence plain English verdict on whether this email is trying to manipulate the reader",
  "recommendation": "what the reader should do"
}

If no manipulation tactics are found, return tactics as an empty array and overallRisk as "safe".`;

  const result = await callGroq(apiKey, {
    model: 'openai/gpt-oss-120b',
    max_tokens: 800,
    temperature: 0.2,
    messages: [{ role: 'user', content: prompt }]
  });
  if (result.error) return result;

  const text = result.data.choices?.[0]?.message?.content || '';
  try {
    const parsed = parseAIJson(text);
    return { success: true, ...parsed };
  } catch (parseErr) {
    // FIX: this used to return `success: true` with `overallRisk: 'safe'` and
    // `tactics: []` hardcoded — i.e. a parse failure was disguised as a
    // confident, clean analysis. content.js only shows an error state when
    // `.error` is set, so this fake-success result rendered as a genuine
    // "Risk Level: SAFE / No manipulation tactics detected" verdict — even
    // while the rule-based scan above it had already flagged real urgency
    // language. A tool that reports on manipulation should never turn "I
    // couldn't read the AI's answer" into "this is safe." Every other
    // JSON-parsing AI handler in this file already returns { error } here;
    // this one now matches them.
    return { error: 'Tone analysis failed: the AI returned an unreadable response. Try again.', _parseError: parseErr.message };
  }
}

// ─── FEATURE 2: Phishing Plain-English Explanation ────────────────────────────
async function explainPhishingThreat(subject, body, scanData, apiKey) {
  if (!apiKey) return { error: 'No Groq API key configured. Add it in Settings.' };

  const threats = scanData?.threatList?.join(', ') || 'none detected';
  const score = scanData?.score ?? 'unknown';

  const prompt = `You are PhishAlert AI. A user is looking at a suspicious email and wants to understand WHY it is dangerous, explained like they are not a tech expert.

Email subject: ${subject}
Email body (excerpt): ${body.substring(0, 1500)}
PhishAlert trust score: ${score}/100
Detected threats: ${threats}
SPF: ${scanData?.checks?.spf?.detail || 'unknown'}
DKIM: ${scanData?.checks?.dkim?.detail || 'unknown'}
DMARC: ${scanData?.checks?.dmarc?.detail || 'unknown'}
Domain age: ${scanData?.checks?.age?.detail || 'unknown'}

Write a plain-English explanation (3-5 sentences) of exactly why this email is dangerous or suspicious. Use simple language — no jargon. End with one clear, specific action the user should take. Do NOT use bullet points. Write in flowing paragraphs.`;

  const result = await callGroq(apiKey, {
    model: 'openai/gpt-oss-120b',
    max_tokens: 400,
    temperature: 0.4,
    messages: [{ role: 'user', content: prompt }]
  });
  if (result.error) return result;

  return { success: true, explanation: result.data.choices?.[0]?.message?.content || '' };
}

// ─── FEATURE 3: Thread-Aware Draft Reply ─────────────────────────────────────
async function draftThreadAwareReply(subject, threadMessages, tone, apiKey) {
  if (!apiKey) return { error: 'No Groq API key configured. Add it in Settings.' };

  const toneMap = {
    formal: 'Write in a formal, professional tone with proper salutation and sign-off.',
    friendly: 'Write in a warm, friendly tone. Be conversational but still professional.',
    brief: 'Write an extremely brief reply — 2-3 sentences maximum. Get straight to the point.'
  };

  // Build thread context from all messages
  const threadContext = threadMessages.map((m, i) => {
    const label = i === threadMessages.length - 1 ? 'MOST RECENT MESSAGE' : `Earlier message ${i + 1}`;
    return `--- ${label} ---\nFrom: ${m.sender || 'Unknown'}\n${m.body.substring(0, 600)}`;
  }).join('\n\n');

  const prompt = `You are an expert email writer. You are reading an email thread and must draft a reply that is aware of the full conversation context — not just the last message.

${toneMap[tone] || toneMap.formal}
Write ONLY the reply text. No subject line, no explanation, no placeholders like [Your Name].
Reference earlier parts of the thread where relevant to show you have read the full conversation.

Subject: ${subject}

Full thread (oldest to newest):
${threadContext}`;

  const result = await callGroq(apiKey, {
    model: 'openai/gpt-oss-120b',
    max_tokens: 600,
    temperature: 0.7,
    messages: [{ role: 'user', content: prompt }]
  });
  if (result.error) return result;

  return { success: true, draft: result.data.choices?.[0]?.message?.content || '', threadAware: true };
}

// ─── FEATURE 4: Outgoing Email Coach ─────────────────────────────────────────
async function coachOutgoingEmail(subject, body, apiKey) {
  if (!apiKey) return { error: 'No Groq API key configured. Add it in Settings.' };

  const prompt = `You are an expert email writing coach. Review this outgoing email and provide constructive feedback. Respond ONLY with valid JSON — no markdown, no backticks.

Subject: ${subject}
Body: ${body.substring(0, 2500)}

Return exactly this JSON:
{
  "overallScore": 0-100,
  "grade": "A|B|C|D|F",
  "strengths": ["strength1", "strength2"],
  "improvements": [
    {
      "area": "Clarity|Tone|Length|Structure|Subject Line|Call to Action|Grammar|Professionalism",
      "issue": "specific problem found",
      "suggestion": "concrete fix"
    }
  ],
  "rewrittenSubject": "improved subject line if needed, or null",
  "toneAssessment": "one sentence describing the current tone",
  "readabilityNote": "one sentence on how easy it is to read",
  "summary": "2-sentence overall verdict"
}`;

  const result = await callGroq(apiKey, {
    model: 'openai/gpt-oss-120b',
    max_tokens: 800,
    temperature: 0.3,
    messages: [{ role: 'user', content: prompt }]
  });
  if (result.error) return result;

  const text = result.data.choices?.[0]?.message?.content || '';
  try {
    return { success: true, ...parseAIJson(text) };
  } catch (parseErr) {
    return { error: "Email coaching failed: the AI's response wasn't valid JSON. Try again.", _parseError: parseErr.message };
  }
}

// ─── PRODUCTIVITY: Calendar Extraction ───────────────────────────────────────
async function extractCalendarEvents(subject, body, apiKey) {
  if (!apiKey) return { error: 'No Groq API key configured. Add it in Settings.' };

  const prompt = `You are a calendar assistant. Extract ALL meeting times, deadlines, and scheduled events from this email. Respond ONLY with valid JSON — no markdown, no backticks.

Subject: ${subject}
Body: ${body.substring(0, 2500)}

Return exactly this JSON:
{
  "events": [
    {
      "title": "event name",
      "date": "YYYY-MM-DD or descriptive date string",
      "time": "HH:MM 24h or descriptive time string or null",
      "duration": "estimated duration in minutes or null",
      "location": "location or video link or null",
      "description": "brief context from the email",
      "googleCalendarUrl": ""
    }
  ],
  "hasEvents": true or false,
  "summary": "one sentence summary of what was found"
}

For googleCalendarUrl, build a https://calendar.google.com/calendar/render?action=TEMPLATE URL with text, details, dates encoded properly. Use ISO 8601 for dates when known (YYYYMMDDTHHMMSS), use a 1-hour default duration if unknown.
If no events found, return events as empty array and hasEvents as false.`;

  const result = await callGroq(apiKey, {
    model: 'openai/gpt-oss-120b',
    max_tokens: 800,
    temperature: 0.2,
    messages: [{ role: 'user', content: prompt }]
  });
  if (result.error) return result;

  const text = result.data.choices?.[0]?.message?.content || '';
  try {
    return { success: true, ...parseAIJson(text) };
  } catch (parseErr) {
    return { error: "Calendar extraction failed: the AI's response wasn't valid JSON. Try again.", _parseError: parseErr.message };
  }
}

// ─── PRODUCTIVITY: Action Item Extractor ─────────────────────────────────────
async function extractActionItems(subject, body, apiKey) {
  if (!apiKey) return { error: 'No Groq API key configured. Add it in Settings.' };

  const prompt = `You are a productivity assistant. Extract ALL action items, tasks, and to-dos from this email. Respond ONLY with valid JSON — no markdown, no backticks.

Subject: ${subject}
Body: ${body.substring(0, 2500)}

Return exactly this JSON:
{
  "tasks": [
    {
      "title": "clear task name (imperative verb form)",
      "deadline": "deadline string or null",
      "priority": "high|medium|low",
      "assignedTo": "person name or 'me' or null",
      "context": "brief context sentence from email"
    }
  ],
  "hasTasks": true or false,
  "summary": "one sentence of what actions are needed"
}

Extract only concrete action items (things someone must DO), not just information. If no tasks, return empty array and hasTasks as false.`;

  const result = await callGroq(apiKey, {
    model: 'openai/gpt-oss-120b',
    max_tokens: 900,
    temperature: 0.2,
    messages: [{ role: 'user', content: prompt }]
  });
  if (result.error) return result;

  const text = result.data.choices?.[0]?.message?.content || '';
  try {
    return { success: true, ...parseAIJson(text) };
  } catch (parseErr) {
    return { error: "Action extraction failed: the AI's response wasn't valid JSON. Try again.", _parseError: parseErr.message };
  }
}

// ─── PRODUCTIVITY: Smart Gmail Labels ────────────────────────────────────────
async function suggestGmailLabels(subject, body, sender, apiKey) {
  if (!apiKey) return { error: 'No Groq API key configured. Add it in Settings.' };

  const prompt = `You are a Gmail organization expert. Suggest smart labels for this email. Respond ONLY with valid JSON — no markdown, no backticks.

From: ${sender}
Subject: ${subject}
Body: ${body.substring(0, 1500)}

Return exactly this JSON:
{
  "primaryLabel": "one main Gmail label name (e.g. Work/Invoices, Personal, Newsletters, etc.)",
  "additionalLabels": ["label2", "label3"],
  "suggestedFolder": "INBOX|archive|starred",
  "reasoning": "one sentence explaining the labeling",
  "shouldUnsubscribe": true or false,
  "unsubscribeReason": "reason if shouldUnsubscribe is true, else null",
  "isImportant": true or false,
  "importanceReason": "why it's important or null"
}

Use Gmail-style label hierarchy with / for nested labels. Common patterns: Work/Meetings, Work/Invoices, Finance/Receipts, Travel/Bookings, Personal/Health, etc. Keep label names short and actionable.`;

  const result = await callGroq(apiKey, {
    model: 'openai/gpt-oss-120b',
    max_tokens: 400,
    temperature: 0.2,
    messages: [{ role: 'user', content: prompt }]
  });
  if (result.error) return result;

  const text = result.data.choices?.[0]?.message?.content || '';
  try {
    return { success: true, ...parseAIJson(text) };
  } catch (parseErr) {
    return { error: "Label suggestion failed: the AI's response wasn't valid JSON. Try again.", _parseError: parseErr.message };
  }
}

// ─── PRODUCTIVITY: Daily Inbox Digest ────────────────────────────────────────
async function generateInboxDigest(emails, apiKey) {
  if (!apiKey) return { error: 'No Groq API key configured. Add it in Settings.' };
  if (!emails || emails.length === 0) return { error: 'No email data to digest.' };

  const emailSummaries = emails.slice(0, 20).map((e, i) =>
    `Email ${i + 1}: From: ${e.sender || 'Unknown'} | Subject: ${e.subject || '(no subject)'} | Score: ${e.score}/100 | Trusted: ${e.isTrusted}`
  ).join('\n');

  const prompt = `You are an AI inbox assistant. Generate a concise daily digest of these ${emails.length} emails. Respond ONLY with valid JSON — no markdown, no backticks.

Emails scanned today:
${emailSummaries}

Return exactly this JSON:
{
  "digest": "2-4 paragraph plain English summary of all emails. Mention key themes, urgent items, and anything suspicious. Write like a smart personal assistant briefing their boss.",
  "urgentCount": number of emails that seem urgent,
  "suspiciousCount": number of low-trust score emails,
  "topSenders": ["sender1", "sender2", "sender3"],
  "keyThemes": ["theme1", "theme2", "theme3"],
  "recommendedActions": ["action1", "action2"],
  "overallInboxHealth": "healthy|busy|cluttered|under_attack"
}`;

  const result = await callGroq(apiKey, {
    model: 'openai/gpt-oss-120b',
    max_tokens: 700,
    temperature: 0.5,
    messages: [{ role: 'user', content: prompt }]
  });
  if (result.error) return result;

  const text = result.data.choices?.[0]?.message?.content || '';
  try {
    return { success: true, ...parseAIJson(text) };
  } catch (parseErr) {
    return { error: "Digest generation failed: the AI's response wasn't valid JSON. Try again.", _parseError: parseErr.message };
  }
}

// ─── Domain Breach Check (multi-source, free, no API key) ───────────────────
// Strategy:
//   1. XposedOrNot /v1/breaches catalog — returns all known breaches, filter by domain.
//      This is the public "what breaches exist" endpoint (no key, CORS-friendly).
//   2. Curated local known-breach list — covers the most common high-profile domains.
//   3. Graceful fallback — clean UI message, no raw HTTP codes exposed to users.
async function checkHIBPDomain(domain) {
  const cacheKey = `breach:${domain}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  // Normalise the root domain (strip subdomains) for matching
  const rootDomain = getRootDomain(domain);

  // ── Attempt 1: XposedOrNot public breaches catalog (no key required) ────────
  // GET /v1/breaches returns an array of all known breach objects, each with a
  // "Domain" field. We filter client-side for our target domain.
  try {
    const res = await fetch(
      'https://api.xposedornot.com/v1/breaches',
      { signal: AbortSignal.timeout(8000) }
    );

    if (res.ok) {
      const data = await res.json();
      // The catalog is under data.exposedBreaches or data.breaches or directly an array
      const catalog = Array.isArray(data) ? data :
        (Array.isArray(data?.exposedBreaches) ? data.exposedBreaches :
         (Array.isArray(data?.breaches) ? data.breaches :
          (Array.isArray(data?.Breaches) ? data.Breaches : null)));

      if (catalog) {
        // Match entries where the breach Domain contains our root domain
        const matched = catalog.filter(b => {
          const bd = (b.Domain || b.domain || '').toLowerCase();
          return bd === rootDomain || bd.endsWith('.' + rootDomain);
        }).slice(0, 6);

        const breaches = matched.map(b => ({
          name:        b.breachID || b.Name    || b.breach  || b.Title || 'Unknown breach',
          date:        b.breachedDate || b.breachDate || b.BreachDate || b.AddedDate || b.date || '',
          pwnCount:    b.exposedRecords || b.PwnCount  || b.pwnCount   || 0,
          dataClasses: (b.exposedData || b.DataClasses || b.dataClasses || b.fields || []).slice(0, 4)
        }));

        const result = {
          found: breaches.length > 0,
          breachCount: breaches.length,
          breaches,
          error: null
        };
        await setCache(cacheKey, result);
        return result;
      }
    }
  } catch (_) { /* fall through to attempt 2 */ }

  // ── Attempt 2: Curated local dataset of high-profile breach domains ──────────
  // This covers the most frequently seen sender domains so users get useful
  // results even when live APIs are down.
  const KNOWN_BREACHES = {
    'linkedin.com':   [{ name: 'LinkedIn 2012', date: '2012-06-05', pwnCount: 164611595, dataClasses: ['Passwords', 'Email addresses'] },
                       { name: 'LinkedIn 2021', date: '2021-06-22', pwnCount: 700000000, dataClasses: ['Email addresses', 'Phone numbers', 'Professional info'] }],
    'adobe.com':      [{ name: 'Adobe 2013',    date: '2013-10-04', pwnCount: 152445165, dataClasses: ['Email addresses', 'Passwords', 'Usernames'] }],
    'myspace.com':    [{ name: 'MySpace 2008',  date: '2008-07-01', pwnCount: 359420698, dataClasses: ['Email addresses', 'Passwords', 'Usernames'] }],
    'yahoo.com':      [{ name: 'Yahoo 2013',    date: '2013-08-01', pwnCount: 3000000000,dataClasses: ['Email addresses', 'Passwords', 'Security Q&A', 'Dates of birth'] },
                       { name: 'Yahoo 2014',    date: '2014-01-01', pwnCount: 500000000, dataClasses: ['Email addresses', 'Passwords', 'Names', 'Phone numbers'] }],
    'dropbox.com':    [{ name: 'Dropbox 2012',  date: '2012-07-01', pwnCount: 68648009,  dataClasses: ['Email addresses', 'Passwords'] }],
    'twitter.com':    [{ name: 'Twitter 2022',  date: '2022-07-22', pwnCount: 5485636,   dataClasses: ['Email addresses', 'Phone numbers'] }],
    'facebook.com':   [{ name: 'Facebook 2021', date: '2021-04-03', pwnCount: 533313128, dataClasses: ['Email addresses', 'Phone numbers', 'Locations'] }],
    'canva.com':      [{ name: 'Canva 2019',    date: '2019-05-24', pwnCount: 137272116, dataClasses: ['Email addresses', 'Names', 'Usernames', 'Passwords'] }],
    'uber.com':       [{ name: 'Uber 2016',     date: '2016-10-01', pwnCount: 57000000,  dataClasses: ['Email addresses', 'Names', 'Phone numbers'] }],
    'marriott.com':   [{ name: 'Marriott 2018', date: '2018-09-08', pwnCount: 500000000, dataClasses: ['Email addresses', 'Names', 'Passport numbers', 'Dates of birth'] }],
    'equifax.com':    [{ name: 'Equifax 2017',  date: '2017-05-13', pwnCount: 147900000, dataClasses: ['Email addresses', 'SSNs', 'Dates of birth', 'Names'] }],
    'target.com':     [{ name: 'Target 2013',   date: '2013-11-27', pwnCount: 110000000, dataClasses: ['Credit cards', 'Email addresses', 'Names'] }],
    'ebay.com':       [{ name: 'eBay 2014',     date: '2014-02-01', pwnCount: 145000000, dataClasses: ['Dates of birth', 'Email addresses', 'Passwords'] }],
    'substack.com':   [{ name: 'Substack 2023', date: '2023-01-01', pwnCount: 0,          dataClasses: ['Email addresses'] }]
  };

  const localBreaches = KNOWN_BREACHES[rootDomain] || KNOWN_BREACHES[domain.toLowerCase()];
  if (localBreaches) {
    const result = {
      found: true,
      breachCount: localBreaches.length,
      breaches: localBreaches,
      error: null,
      source: 'local'
    };
    await setCache(cacheKey, result);
    return result;
  }

  // ── Fallback: unknown domain, service unavailable ─────────────────────────────
  // Return a clean "unavailable" result — do NOT expose raw HTTP status codes.
  // The UI will show a manual check link to xposedornot.com.
  // If no breaches found in catalog OR local list, return clean "none found"
  return { found: false, breachCount: 0, breaches: [], error: null };
}

// ─── Desktop Notifications ────────────────────────────────────────────────────
async function sendDesktopNotification(scanEntry) {
  // Respect user's notification preference
  const settingsData = await chrome.storage.local.get('phishalert_settings');
  const settings = settingsData.phishalert_settings || {};
  if (settings.notificationsEnabled === false) return;

  const { domain, score, isTrusted, threatList = [], sender } = scanEntry;

  const hasCritical = threatList.length > 0 || score < 30;
  const isUrgent = !isTrusted && score < 60;

  if (!hasCritical && !isUrgent) return; // Only notify for suspicious/critical

  const isCritical = hasCritical || score < 30;

  const title = isCritical ? '🚨 PhishAlert: Critical Threat!' : '⚠️ PhishAlert: Suspicious Email';
  const message = isCritical
    ? `Threat detected from ${domain}.\n${threatList[0] || 'Multiple red flags found.'}`
    : `Suspicious sender: ${domain} (Score: ${score}/100).\nVerify before clicking any links.`;

  chrome.notifications.create(`phishalert_${Date.now()}`, {
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title,
    message,
    priority: isCritical ? 2 : 1,
    requireInteraction: isCritical // Critical alerts stay until dismissed
  });
}


// ─── FEATURE NEW 4: Outgoing Email Scanner ────────────────────────────────────
// Called from content.js before Gmail/other clients send an email.
// Checks recipient domains against URLhaus, MX, IDN/punycode patterns,
// and scans body for sensitive data patterns.
async function scanOutgoingEmail({ to, subject, body }) {
  const issues = [];
  const domains = [...new Set(
    (to || []).map(addr => {
      const m = addr.match(/@([\w.-]+)$/);
      return m ? m[1].toLowerCase() : null;
    }).filter(Boolean)
  )];

  // FEATURE 12: Record recipient domains so we can detect lookalikes in future
  // incoming emails. Fire-and-forget — don't block outgoing send on this.
  for (const domain of domains) {
    addContactDomain(domain).catch(() => { });
  }

  for (const domain of domains) {
    // URLhaus host check
    try {
      const hRes = await fetch(URLHAUS_HOST_LK, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ host: domain }).toString(),
        signal: AbortSignal.timeout(5000)
      });
      if (hRes.ok) {
        const hData = await hRes.json();
        if (hData.query_status === 'is_available' && (hData.urls || []).length > 0) {
          const live = hData.urls.filter(u => u.url_status === 'online');
          if (live.length > 0) {
            issues.push({ type: 'urlhaus_host', domain, detail: `⚠️ Recipient domain "${domain}" hosts active malware URLs (URLhaus)` });
          }
        }
      }
    } catch { }

    // MX record check — no MX = likely fake/spoofed domain
    try {
      const mx = await dnsLookup(domain, 'MX');
      if (!mx?.Answer?.length) {
        issues.push({ type: 'no_mx', domain, detail: `⚠️ "${domain}" has no MX record — domain may not exist or is spoofed` });
      }
    } catch { }

    // IDN / Punycode in recipient domain
    if (domain.startsWith('xn--') || /[^\x00-\x7F]/.test(domain)) {
      issues.push({ type: 'idn', domain, detail: `⚠️ "${domain}" uses punycode/IDN — possible homograph attack` });
    }
  }

  // Sensitive content patterns in body / subject
  const patterns = [
    { re: /password|passwd|pwd/i, label: 'Contains "password" in email body' },
    { re: /ssn|social.?security/i, label: 'Contains Social Security Number reference' },
    { re: /credit.?card|cvv|card.?number/i, label: 'Contains credit card reference' },
    { re: /wire.?transfer|iban|swift.?code/i, label: 'Contains wire transfer / banking details' },
    { re: /private.?key|api.?key|secret.?key/i, label: 'Contains API or private key reference' },
  ];
  const combined = (subject || '') + ' ' + (body || '');
  for (const p of patterns) {
    if (p.re.test(combined)) {
      issues.push({ type: 'sensitive', detail: `⚠️ ${p.label}` });
    }
  }

  return { domains, issues, safe: issues.length === 0 };
}

// ─── Block Sender ─────────────────────────────────────────────────────────────
async function blockSender(email, domain, reason) {
  const key = 'phishalert_blocked';
  const data = await chrome.storage.local.get(key);
  const blocked = data[key] || {};

  blocked[email] = {
    domain,
    reason: reason || 'Manually blocked',
    blockedAt: Date.now()
  };

  await chrome.storage.local.set({ [key]: blocked });

  // NOTE: Community report is intentionally separate from blocking.
  // "Report as Phishing" handles community reporting independently.
  // Block & Report calls COMMUNITY_REPORT explicitly from content.js,
  // so we do NOT auto-report here to avoid double-counting.

  return { success: true, blockedCount: Object.keys(blocked).length };
}

async function getBlockedSenders() {
  const data = await chrome.storage.local.get('phishalert_blocked');
  return data.phishalert_blocked || {};
}

async function unblockSender(email) {
  const data = await chrome.storage.local.get('phishalert_blocked');
  const blocked = data.phishalert_blocked || {};
  delete blocked[email];
  await chrome.storage.local.set({ phishalert_blocked: blocked });
  return { success: true };
}

async function isSenderBlocked(email) {
  const blocked = await getBlockedSenders();
  return !!blocked[email];
}

// ─── Export Threat Report ─────────────────────────────────────────────────────
async function buildExportData(mode, scanEntry) {
  // mode: 'current' = single email scan | 'all' = full history
  if (mode === 'current' && scanEntry) {
    return [scanEntry];
  }
  const ld = await chrome.storage.local.get('phishalert_scanlog');
  return ld.phishalert_scanlog || [];
}

function exportToCSV(entries) {
  const headers = [
    'Timestamp', 'Domain', 'Sender', 'Score', 'Trusted',
    'SPF', 'DKIM', 'DMARC', 'Domain Age (days)', 'VT Malicious',
    'Threats', 'Display Name Spoof', 'Homograph'
  ];

  const rows = entries.map(e => {
    const checks = e.checks || {};
    const threats = e.threats || {};
    const spoof = threats.displayNameSpoof || {};
    const homog = threats.homograph || {};
    const vt = checks.vt || {};
    const age = checks.age || {};

    const clean = (v) => `"${String(v || '').replace(/"/g, '""')}"`;

    return [
      clean(e.timestamp ? new Date(e.timestamp).toISOString() : ''),
      clean(e.domain || ''),
      clean(e.sender || ''),
      e.score ?? '',
      e.isTrusted ? 'Yes' : 'No',
      checks.spf?.pass ? 'Pass' : 'Fail',
      checks.dkim?.pass ? 'Pass' : (checks.dkim?.inconclusive ? 'Unverified' : 'Fail'),
      checks.dmarc?.pass ? `Pass (${checks.dmarc.policy || ''})` : 'Fail',
      age.ageInDays ?? '',
      vt.available ? (vt.maliciousCount ?? 0) : 'N/A',
      clean((e.threatList || e.threats || []).join('; ')),
      spoof.spoofing ? clean(spoof.detail || 'Yes') : 'No',
      homog.detected ? clean(homog.detail || 'Yes') : 'No'
    ].join(',');
  });

  return [headers.join(','), ...rows].join('\r\n');
}

// ─── FEATURE: Weekly Threat Intelligence Report ───────────────────────────────
async function generateWeeklyReport() {
  const logData = await chrome.storage.local.get('phishalert_scanlog');
  const log = logData.phishalert_scanlog || [];

  const now = Date.now();
  const weekMs = 7 * 24 * 60 * 60 * 1000;
  const weekEntries = log.filter(e => now - e.timestamp < weekMs);

  if (weekEntries.length === 0) {
    return { hasData: false, message: 'No emails scanned in the past 7 days.' };
  }

  const totalScanned = weekEntries.length;
  const threats = weekEntries.filter(e => (e.threatList || e.threats || []).length > 0);
  const safe = weekEntries.filter(e => e.isTrusted);
  const suspicious = weekEntries.filter(e => !e.isTrusted && (e.threatList || e.threats || []).length === 0);

  // Top risky domains
  const domainRisk = {};
  weekEntries.forEach(e => {
    if (!e.isTrusted && e.domain) {
      domainRisk[e.domain] = (domainRisk[e.domain] || 0) + 1;
    }
  });
  const topRiskyDomains = Object.entries(domainRisk)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([domain, count]) => ({ domain, count }));

  // Attack type breakdown
  const attackTypes = {};
  weekEntries.forEach(e => {
    const tList = e.threatList || (Array.isArray(e.threats) ? e.threats : []);
    tList.forEach(t => {
      if (typeof t === 'string') {
        const key = t.substring(0, 40);
        attackTypes[key] = (attackTypes[key] || 0) + 1;
      }
    });
  });
  const topAttacks = Object.entries(attackTypes)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([type, count]) => ({ type, count }));

  // Personal threat score (0-100, higher = more threats)
  const threatRate = totalScanned > 0 ? Math.round((threats.length / totalScanned) * 100) : 0;
  const personalThreatScore = Math.min(100, threatRate);

  const avgScore = weekEntries.length > 0
    ? Math.round(weekEntries.reduce((s, e) => s + (e.score || 50), 0) / weekEntries.length)
    : 50;

  const report = {
    hasData: true,
    period: { from: new Date(now - weekMs).toLocaleDateString(), to: new Date(now).toLocaleDateString() },
    totalScanned,
    threatsCount: threats.length,
    safeCount: safe.length,
    suspiciousCount: suspicious.length,
    personalThreatScore,
    avgTrustScore: avgScore,
    topRiskyDomains,
    topAttacks,
    generatedAt: now
  };

  // Save report for retrieval
  await chrome.storage.local.set({ phishalert_weekly_report: report });
  return report;
}

async function getWeeklyReport() {
  const data = await chrome.storage.local.get('phishalert_weekly_report');
  return data.phishalert_weekly_report || null;
}

// ─── FEATURE: Adaptive Sender Learning ────────────────────────────────────────
// User actions (mark safe, report, block, reply) actively adjust the trust model.
async function adaptiveSenderAction(email, domain, action) {
  // action: 'mark_safe' | 'mark_phishing' | 'block' | 'replied'
  const key = 'phishalert_sender_history';
  const data = await chrome.storage.local.get(key);
  const history = data[key] || {};

  if (!history[email]) {
    history[email] = { replyCount: 0, seenCount: 0, firstSeen: Date.now(), lastSeen: Date.now(), adaptiveActions: [] };
  }

  const entry = history[email];
  entry.lastSeen = Date.now();
  entry.adaptiveActions = entry.adaptiveActions || [];

  // Record the action with timestamp
  entry.adaptiveActions.push({ action, time: Date.now() });
  // Keep last 20 actions only
  if (entry.adaptiveActions.length > 20) entry.adaptiveActions = entry.adaptiveActions.slice(-20);

  // Adjust trust signals based on action
  switch (action) {
    case 'mark_safe':
      entry.userMarkedSafe = (entry.userMarkedSafe || 0) + 1;
      // An explicit "safe" decision overrides any earlier report/block, fully
      // (it used to remove only one report per click, so a wrongly-reported
      // sender needed several clicks to recover).
      entry.userMarkedPhishing = 0;
      entry.userBlocked = false;
      break;
    case 'mark_phishing':
    case 'report':
      entry.userMarkedPhishing = (entry.userMarkedPhishing || 0) + 1;
      entry.userMarkedSafe = Math.max(0, (entry.userMarkedSafe || 0) - 1);
      break;
    case 'block':
      entry.userBlocked = true;
      entry.userMarkedPhishing = (entry.userMarkedPhishing || 0) + 1;
      break;
    case 'replied':
      entry.replyCount = (entry.replyCount || 0) + 1;
      break;
    case 'seen':
      entry.seenCount = (entry.seenCount || 0) + 1;
      break;
  }

  await chrome.storage.local.set({ [key]: history });

  // Return new adaptive trust bonus for this sender
  return getAdaptiveTrustBonus(entry);
}

function getAdaptiveTrustBonus(entry) {
  if (!entry) return { bonus: 0, label: 'Unknown', penalty: 0 };

  let bonus = 0;
  let penalty = 0;
  let label = 'First contact';

  // Positive signals
  if (entry.replyCount >= 10) { bonus += 20; label = 'Frequent contact'; }
  else if (entry.replyCount >= 3) { bonus += 12; label = 'Known contact'; }
  else if (entry.replyCount >= 1) { bonus += 6; label = 'Previously replied'; }
  else if (entry.seenCount >= 5) { bonus += 3; label = 'Seen before'; }

  // User explicitly marked safe — strong positive
  if (entry.userMarkedSafe > 0) { bonus += 15 * Math.min(entry.userMarkedSafe, 3); label = 'Trusted by you'; }

  // User reported as phishing — strong negative
  if (entry.userMarkedPhishing > 0) { penalty += 25 * Math.min(entry.userMarkedPhishing, 3); label = 'Reported by you'; }

  // User blocked — total distrust
  if (entry.userBlocked) { penalty += 50; label = 'Blocked by you'; }

  return { bonus, penalty, label, netEffect: bonus - penalty };
}

async function getAdaptiveSenderTrust(email) {
  const key = 'phishalert_sender_history';
  const data = await chrome.storage.local.get(key);
  const history = data[key] || {};
  const entry = history[email] || {};
  return { ...entry, ...getAdaptiveTrustBonus(entry) };
}

// ─── Undo a report / mark a domain safe ─────────────────────────────────────
// "Report as Phishing" had no way back. This removes the community report for a
// domain, clears the user-report / block penalties on every sender at that
// domain, unblocks them, and (optionally) whitelists the domain.
async function clearReportForDomain(domain, whitelist) {
  domain = String(domain || '').toLowerCase().trim();
  if (!domain) return { success: false, error: 'No domain' };
  const atDomain = '@' + domain;
  const matches = (v) => String(v || '').toLowerCase().replace(/[>\s]+$/, '').endsWith(atDomain);

  // 1. community report
  const rk = 'phishalert_reports';
  const rd = await chrome.storage.local.get(rk);
  const reports = rd[rk] || {};
  const hadReport = !!reports[domain];
  delete reports[domain];
  await chrome.storage.local.set({ [rk]: reports });

  // 2. adaptive sender history (report / block penalties)
  const hk = 'phishalert_sender_history';
  const hd = await chrome.storage.local.get(hk);
  const history = hd[hk] || {};
  let clearedSenders = 0;
  Object.keys(history).forEach(email => {
    if (!matches(email)) return;
    const e = history[email];
    if (e.userMarkedPhishing || e.userBlocked) clearedSenders++;
    e.userMarkedPhishing = 0;
    e.userBlocked = false;
    e.adaptiveActions = (e.adaptiveActions || []).concat([{ action: 'clear_report', time: Date.now() }]).slice(-20);
  });
  await chrome.storage.local.set({ [hk]: history });

  // 3. block list
  const bk = 'phishalert_blocked';
  const bd = await chrome.storage.local.get(bk);
  const blocked = bd[bk] || {};
  let unblocked = 0;
  Object.keys(blocked).forEach(email => {
    if (matches(email) || String(blocked[email] && blocked[email].domain || '').toLowerCase() === domain) {
      delete blocked[email]; unblocked++;
    }
  });
  await chrome.storage.local.set({ [bk]: blocked });

  // 4. optional whitelist
  if (whitelist) { try { await addWhitelistDomain(domain); } catch (e) {} }

  return { success: true, domain, hadReport, clearedSenders, unblocked, whitelisted: !!whitelist };
}

// ─── FEATURE: One-Click Phishing Reporting ────────────────────────────────────
async function reportPhishing(domain, sender, subject, reporterNote) {
  const results = { domain, sender, timestamp: Date.now(), reports: [] };

  // 1. Save to local community reports (existing system)
  try {
    await saveCommunityReport(domain, reporterNote || 'User reported as phishing');
    results.reports.push({ target: 'PhishAlert Community', status: 'success', message: 'Saved to local threat database' });
  } catch (e) {
    results.reports.push({ target: 'PhishAlert Community', status: 'error', message: e.message });
  }

  // 2. Google Safe Browsing report URL (opens in tab — no API needed)
  const gsbUrl = `https://safebrowsing.google.com/safebrowsing/report_phish/?url=${encodeURIComponent('https://' + domain)}&hl=en`;
  results.reports.push({
    target: 'Google Safe Browsing',
    status: 'link',
    url: gsbUrl,
    message: 'Click to report to Google Safe Browsing'
  });

  // 3. PhishTank report URL
  const ptUrl = `https://www.phishtank.com/add_web_phish.php?url=${encodeURIComponent('https://' + domain)}`;
  results.reports.push({
    target: 'PhishTank',
    status: 'link',
    url: ptUrl,
    message: 'Click to report to PhishTank database'
  });

  // 4. Abuse.ch / URLhaus
  const urlhausUrl = `https://urlhaus.abuse.ch/api/#submit`;
  results.reports.push({
    target: 'abuse.ch / URLhaus',
    status: 'link',
    url: urlhausUrl,
    message: 'Submit to URLhaus malware URL database'
  });

  // 5. Gmail abuse (provider abuse email)
  const gmailAbuseUrl = `https://support.google.com/mail/contact/abuse?hl=en`;
  results.reports.push({
    target: "Gmail Abuse Team",
    status: 'link',
    url: gmailAbuseUrl,
    message: 'Report to Gmail abuse team'
  });

  // Save report record
  const repKey = 'phishalert_phishing_reports';
  const existing = await chrome.storage.local.get(repKey);
  const reports = existing[repKey] || [];
  reports.unshift({ domain, sender, subject, note: reporterNote, timestamp: Date.now(), results: results.reports });
  if (reports.length > 100) reports.splice(100);
  await chrome.storage.local.set({ [repKey]: reports });

  // Also update adaptive sender learning — mark sender as phishing
  if (sender) await adaptiveSenderAction(sender, domain, 'mark_phishing');

  return results;
}


// ─── FEATURE 5: Custom Whitelist Management ───────────────────────────────────
// Users can permanently trust domains — those domains skip all scanning checks.

async function getWhitelist() {
  const data = await chrome.storage.local.get('phishalert_whitelist');
  return data.phishalert_whitelist || [];
}

async function addWhitelistDomain(domain) {
  const list = await getWhitelist();
  const clean = (domain || '').toLowerCase().trim()
    .replace(/^https?:\/\//, '').replace(/\/.*/, '').replace(/^www\./, '');
  if (!clean || !clean.includes('.')) return { success: false, error: 'Invalid domain', list };
  if (!list.includes(clean)) {
    list.push(clean);
    await chrome.storage.local.set({ phishalert_whitelist: list });
  }
  return { success: true, list };
}

async function removeWhitelistDomain(domain) {
  const list = await getWhitelist();
  const clean = (domain || '').toLowerCase().trim();
  const updated = list.filter(d => d !== clean);
  await chrome.storage.local.set({ phishalert_whitelist: updated });
  return { success: true, list: updated };
}

async function isWhitelisted(domain) {
  if (!domain) return false;
  const list = await getWhitelist();
  const d = domain.toLowerCase();
  return list.some(entry => d === entry || d.endsWith('.' + entry));
}

function makeWhitelistedAuthResult(domain) {
  return {
    whitelisted: true,
    domain,
    verifiedAt: Date.now(),
    spf: { pass: true, strict: true, detail: 'Whitelisted domain — skipped', record: null },
    dkim: { pass: true, detail: 'Whitelisted domain — skipped', selector: null },
    dmarc: {
      pass: true, policy: 'reject', spf_align: 'strict', dkim_align: 'strict',
      detail: 'Whitelisted domain — skipped', record: null
    },
    mx: { hasMX: true, count: 1, records: [], detail: 'Whitelisted domain', suspicious: false }
  };
}


// ─── FEATURE NEW 5: OAuth Consent-Grant Phishing Detection ───────────────────
// Dangerous OAuth scopes that grant sweeping account access
const DANGEROUS_OAUTH_SCOPES = [
  'https://mail.google.com/',
  'https://www.googleapis.com/auth/gmail.send',
  'https://www.googleapis.com/auth/gmail.modify',
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/contacts',
  'https://www.googleapis.com/auth/drive',
  'https://www.googleapis.com/auth/calendar',
  'offline_access',
];

function analyzeOAuthUrl(urlStr) {
  let u;
  try { u = new URL(urlStr); } catch { return null; }

  const isGoogle = u.hostname === 'accounts.google.com' && u.pathname.includes('/o/oauth2');
  const isMSFT = u.hostname === 'login.microsoftonline.com' && u.pathname.includes('/oauth2');
  if (!isGoogle && !isMSFT) return null;

  const scopeRaw = u.searchParams.get('scope') || '';
  const redirectUri = u.searchParams.get('redirect_uri') || '';
  const clientId = u.searchParams.get('client_id') || '';
  const scopes = scopeRaw.split(/[\s,+]+/).filter(Boolean);

  const dangerousScopes = scopes.filter(s => DANGEROUS_OAUTH_SCOPES.some(d => s.includes(d)));

  let suspiciousRedirect = false;
  try {
    const rUri = new URL(redirectUri);
    suspiciousRedirect = !rUri.hostname.endsWith('.google.com') &&
      !rUri.hostname.endsWith('.googleapis.com') &&
      !rUri.hostname.endsWith('.microsoft.com') &&
      !rUri.hostname.endsWith('localhost') &&
      redirectUri !== '';
  } catch { suspiciousRedirect = redirectUri !== ''; }

  const riskScore = Math.min(100,
    dangerousScopes.length * 30 +
    (suspiciousRedirect ? 25 : 0)
  );

  return {
    isOAuth: true,
    provider: isGoogle ? 'Google' : 'Microsoft',
    scopes,
    dangerousScopes,
    suspiciousRedirect,
    redirectUri,
    clientId,
    riskScore,
    verdict: riskScore >= 60 ? 'critical' : riskScore >= 30 ? 'suspicious' : 'low'
  };
}

// Listen for navigations to OAuth consent pages
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const oAuth = analyzeOAuthUrl(details.url);
  if (!oAuth || oAuth.verdict === 'low') return;

  await chrome.storage.local.set({
    phishalert_oauth_alert: { ...oAuth, tabId: details.tabId, url: details.url, ts: Date.now() }
  });

  const title = oAuth.verdict === 'critical'
    ? '🚨 Dangerous OAuth Permission Request!'
    : '⚠️ Suspicious OAuth Permission Request';
  const msg = oAuth.dangerousScopes.length
    ? `An app wants: ${oAuth.dangerousScopes.slice(0, 2).join(', ')} — this may be a phishing consent grant.`
    : `Suspicious redirect_uri: ${oAuth.redirectUri.slice(0, 60)}`;

  chrome.notifications.create('pa_oauth_' + Date.now(), {
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title,
    message: msg,
    priority: oAuth.verdict === 'critical' ? 2 : 1,
    requireInteraction: oAuth.verdict === 'critical'
  });
}, {
  url: [
    { hostEquals: 'accounts.google.com' },
    { hostEquals: 'login.microsoftonline.com' }
  ]
});

// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE 10: Reply-To Mismatch Detection
// ─────────────────────────────────────────────────────────────────────────────
// Checks whether the Reply-To header points to a completely different domain
// than the From address. This is a textbook BEC (Business Email Compromise)
// technique: the visible From looks legit, but replies go to the attacker.
// ═══════════════════════════════════════════════════════════════════════════════
function checkReplyToMismatch(from, replyTo) {
  if (!from || !replyTo) return { mismatch: false };

  // Strip display-name angle brackets: "Acme <ceo@acme.com>" → "ceo@acme.com"
  const stripBrackets = s => (s.match(/<([^>]+)>/) || [, s])[1];
  const fromEmail = stripBrackets(from);
  const replyEmail = stripBrackets(replyTo);

  const fromDomain = fromEmail.match(/@([\w.-]+)/)?.[1]?.toLowerCase().replace(/^www\./, '');
  const replyDomain = replyEmail.match(/@([\w.-]+)/)?.[1]?.toLowerCase().replace(/^www\./, '');

  if (!fromDomain || !replyDomain) return { mismatch: false };
  if (fromDomain === replyDomain) return { mismatch: false };

  // Allow subdomains of the same org: mail.company.com vs reply.company.com
  if (sameRootDomain(fromDomain, replyDomain)) return { mismatch: false };

  return {
    mismatch: true,
    fromDomain,
    replyToDomain: replyDomain,
    severity: 'high',
    detail: `Reply-To (${replyDomain}) is a completely different domain from From (${fromDomain}) — classic BEC redirect trick`
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE 11: Urgency / Scarcity Keyword Scorer (offline, zero API key needed)
// ─────────────────────────────────────────────────────────────────────────────
// Runs locally against subject + body text. Each matched keyword pattern adds
// to a risk score that is then applied as a penalty on the trust score.
// ═══════════════════════════════════════════════════════════════════════════════
const URGENCY_KEYWORDS = [
  // Time pressure
  { re: /\bact\s+now\b/i, weight: 15, label: 'Act now' },
  { re: /\bimmediately\b/i, weight: 10, label: 'Immediately' },
  { re: /\burgent(ly)?\b/i, weight: 10, label: 'Urgent' },
  { re: /\bwithin\s+\d+\s+(hour|minute|day)/i, weight: 12, label: 'Time limit' },
  { re: /\blast\s+chance\b/i, weight: 18, label: 'Last chance' },
  { re: /\bexpires?\s+(today|soon|now|in\s+\d+)/i, weight: 14, label: 'Expires soon' },
  { re: /\btime[\s-]sensitive\b/i, weight: 12, label: 'Time-sensitive' },
  { re: /\bdon'?t\s+(miss|delay|wait)\b/i, weight: 10, label: "Don't miss/delay" },
  // Account threat / fear
  { re: /\baccount\s+(suspend|terminat|clos|block|lock)/i, weight: 20, label: 'Account suspended/closed' },
  { re: /\b(verify|confirm)\s+(your\s+)?(account|identity|email|password)/i, weight: 15, label: 'Verify account' },
  { re: /\bunusual\s+(activity|sign-?in|login|access)\b/i, weight: 15, label: 'Unusual activity' },
  { re: /\bsecurity\s+alert\b/i, weight: 14, label: 'Security alert' },
  { re: /\byour\s+account\s+(has\s+been|will\s+be)\b/i, weight: 18, label: 'Account threatened' },
  { re: /\bfailed\s+(login|attempt|payment|transaction)/i, weight: 12, label: 'Failed attempt' },
  { re: /\bsuspicious\s+(activity|login|access|transaction)\b/i, weight: 14, label: 'Suspicious activity' },
  // Scarcity / reward
  { re: /\b(limited|exclusive)\s+(time|offer|deal|access)\b/i, weight: 10, label: 'Limited offer' },
  { re: /\byou('ve)?\s+(won|been\s+selected|been\s+chosen)\b/i, weight: 18, label: 'You won/selected' },
  { re: /\bclaim\s+(your|the)\s+(prize|reward|gift|winnings)\b/i, weight: 20, label: 'Claim prize' },
  { re: /\bfree\s+(gift|prize|money|reward|shipping)\b/i, weight: 12, label: 'Free prize/gift' },
  { re: /\bcongratulations?[,!]\s/i, weight: 8, label: 'Congratulations (bait)' },
  // Authority / legal threats
  { re: /\b(irs|fbi|interpol|police|government|federal)\b/i, weight: 14, label: 'Authority impersonation' },
  { re: /\bpenalt(y|ies)\b/i, weight: 12, label: 'Penalty threat' },
  { re: /\blegal\s+(action|notice|proceeding)\b/i, weight: 15, label: 'Legal action threat' },
  // Credential harvesting
  { re: /click\s+(here|below|the\s+link)\s+to\s+(verify|confirm|update|reset|access)/i, weight: 15, label: 'Click to verify/update' },
  { re: /\bupdate\s+(your\s+)?(payment|billing|credit\s+card|bank)\b/i, weight: 16, label: 'Update payment info' },
  { re: /\benter\s+(your\s+)?(password|credentials|login|pin|otp)\b/i, weight: 20, label: 'Enter credentials' },
];

function scoreUrgencyKeywords(subject, body) {
  const text = `${subject || ''} ${body || ''}`;
  let total = 0;
  const matched = [];

  for (const kw of URGENCY_KEYWORDS) {
    if (kw.re.test(text)) { total += kw.weight; matched.push(kw.label); }
  }
  total = Math.min(60, total); // cap at 60 so it doesn't overwhelm the base score

  return {
    score: total,
    matched,
    isHighRisk: total >= 30,
    isMediumRisk: total >= 15 && total < 30,
    detail: matched.length
      ? `Urgency/manipulation signals: ${matched.slice(0, 4).join(', ')}${matched.length > 4 ? ` +${matched.length - 4} more` : ''}`
      : 'No urgency signals detected'
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE 12: Lookalike Domain vs User's Own Contact Domains
// ─────────────────────────────────────────────────────────────────────────────
// Learns which domains the user regularly emails (via outgoing scan hooks).
// Incoming emails from domains 1-2 Levenshtein edits away from a known contact
// domain are flagged — catching "cornpany.com" when you email "company.com".
// ═══════════════════════════════════════════════════════════════════════════════
const CONTACT_DOMAINS_KEY = 'phishalert_contact_domains';
const MAX_CONTACT_DOMAINS = 500;
// Skip free email providers — we only want company/organisation domains
const SKIP_PROVIDER_DOMAINS = new Set([
  'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'icloud.com', 'me.com',
  'protonmail.com', 'proton.me', 'aol.com', 'live.com', 'msn.com', 'ymail.com',
  'mail.com', 'zoho.com', 'fastmail.com', 'gmx.com', 'tutanota.com', 'pm.me'
]);

async function addContactDomain(domain) {
  if (!domain) return;
  const d = domain.toLowerCase().trim().replace(/^www\./, '');
  if (d.length < 4 || !d.includes('.') || SKIP_PROVIDER_DOMAINS.has(d)) return;

  const stored = await chrome.storage.local.get(CONTACT_DOMAINS_KEY);
  const domains = stored[CONTACT_DOMAINS_KEY] || {};
  domains[d] = (domains[d] || 0) + 1; // frequency counts help rank importance

  if (Object.keys(domains).length > MAX_CONTACT_DOMAINS) {
    // Keep top MAX by frequency
    const trimmed = Object.fromEntries(
      Object.entries(domains).sort((a, b) => b[1] - a[1]).slice(0, MAX_CONTACT_DOMAINS)
    );
    await chrome.storage.local.set({ [CONTACT_DOMAINS_KEY]: trimmed });
  } else {
    await chrome.storage.local.set({ [CONTACT_DOMAINS_KEY]: domains });
  }
}

async function getContactDomains() {
  const stored = await chrome.storage.local.get(CONTACT_DOMAINS_KEY);
  return stored[CONTACT_DOMAINS_KEY] || {};
}

// Private Levenshtein helper (avoids collision with the one in content.js which
// runs in a different context)
function _bgLev(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[a.length][b.length];
}

async function checkContactLookalike(domain) {
  if (!domain) return { lookalike: false };

  const d = domain.toLowerCase().trim().replace(/^www\./, '');
  if (SKIP_PROVIDER_DOMAINS.has(d)) return { lookalike: false }; // don't compare against gmail etc.

  const dBase = d.split('.')[0]; // "cornpany" from "cornpany.com"

  const contactDomains = await getContactDomains();
  const contactList = Object.keys(contactDomains);
  if (contactList.length === 0) return { lookalike: false, reason: 'No contact history yet' };

  let best = null, bestDist = Infinity;

  for (const contact of contactList) {
    if (contact === d) return { lookalike: false }; // exact match — not a lookalike

    const cBase = contact.split('.')[0];

    // Only compare domains similar in length (typo-squats differ by ≤ 3 chars)
    if (Math.abs(cBase.length - dBase.length) > 3) continue;
    if (cBase.length < 4) continue; // avoid false positives on tiny names

    const dist = _bgLev(dBase, cBase);
    // Tighter threshold for short names to avoid false-positives
    const threshold = cBase.length <= 6 ? 1 : 2;

    if (dist > 0 && dist <= threshold && dist < bestDist) {
      bestDist = dist;
      best = { contact, cBase, dist, freq: contactDomains[contact] };
    }
  }

  if (!best) return { lookalike: false };

  return {
    lookalike: true,
    targetDomain: best.contact,
    distance: best.dist,
    contactFrequency: best.freq,
    severity: best.dist === 1 ? 'high' : 'medium',
    detail: `"${d}" is ${best.dist} character edit(s) away from your regular contact "${best.contact}" — possible lookalike impersonation`
  };
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE 13: Multi-Source Sender Reputation — DNS Blacklists (no API key)
// ─────────────────────────────────────────────────────────────────────────────
// Checks the sending domain's IP against:
//   • Spamhaus ZEN  (zen.spamhaus.org)  — covers SBL/XBL/PBL
//   • SpamCop BL    (bl.spamcop.net)
//   • Barracuda BRBL(b.barracudacentral.org)
// All are DNS-based and completely free with no API key required.
// ═══════════════════════════════════════════════════════════════════════════════
const DNSBLS = [
  {
    name: 'Spamhaus ZEN',
    host: 'zen.spamhaus.org',
    codes: {
      '127.0.0.2': 'SBL — confirmed spam source',
      '127.0.0.3': 'SBL-CSS — spam support service',
      '127.0.0.4': 'XBL — exploited/hacked host',
      '127.0.0.9': 'SBL — Spamhaus DROP',
      '127.0.0.10': 'PBL — end-user dynamic IP',
      '127.0.0.11': 'PBL — end-user dynamic IP (ISP listed)'
    }
  },
  {
    name: 'SpamCop',
    host: 'bl.spamcop.net',
    codes: { '127.0.0.2': 'SpamCop BL — reported spam source' }
  },
  {
    name: 'Barracuda BRBL',
    host: 'b.barracudacentral.org',
    codes: { '127.0.0.2': 'Barracuda BRBL — spam/malware source' }
  }
];

async function checkDNSBL(domain) {
  const cacheKey = `dnsbl:${domain}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  // FIX (Bug #3): DNSBLs list mail-SENDING server IPs, not website/hosting
  // IPs. Resolving the domain's A record and checking that against
  // Spamhaus/SpamCop/Barracuda tests the wrong host for any domain where
  // mail is hosted separately from the website — which is most domains,
  // since Google Workspace, Outlook 365, etc. run mail on totally different
  // infrastructure than the marketing site. That gave false "clean" results
  // for genuinely blacklisted mail servers (and could occasionally flag an
  // innocent web host instead).
  //
  // Step 1: Resolve the domain's MX record(s) and pick the highest-
  // precedence mail exchanger (lowest preference number).
  let mailHost = null;
  try {
    const mxRes = await dnsLookup(domain, 'MX');
    const mxRecords = (mxRes?.Answer || [])
      .filter(r => r.type === 15) // type 15 = MX in DNS JSON API
      .map(r => {
        const [prefStr, ...hostParts] = (r.data || '').trim().split(/\s+/);
        return { preference: parseInt(prefStr, 10) || 0, host: hostParts.join(' ').replace(/\.$/, '') };
      })
      .filter(r => r.host)
      .sort((a, b) => a.preference - b.preference);

    if (mxRecords.length > 0) mailHost = mxRecords[0].host;
  } catch { }

  // Step 2: Resolve THAT mail server's A record. Only fall back to the
  // bare domain's own A record if it genuinely has no MX (rare send-only
  // setups route mail through the domain itself) — and note that fallback
  // in the result so it's not confused with a real mail-server check.
  let ip = null;
  try {
    const aRes = await dnsLookup(mailHost || domain, 'A');
    // Type 1 = A record in DNS JSON API
    const aRec = (aRes?.Answer || []).find(r => r.type === 1);
    if (aRec?.data && /^\d{1,3}(\.\d{1,3}){3}$/.test(aRec.data)) ip = aRec.data;
  } catch { }

  if (!ip) {
    const result = {
      checked: false, listed: false, ip: null, listings: [], mailHost,
      reason: mailHost
        ? `Could not resolve a valid IPv4 address for mail server ${mailHost}`
        : 'Could not resolve a valid IPv4 address for DNSBL check (no MX record found)'
    };
    await setCache(cacheKey, result);
    return result;
  }

  // DNSBL queries use the reversed IP: 1.2.3.4 → 4.3.2.1.<bl-host>
  const reversed = ip.split('.').reverse().join('.');

  const listings = [];
  await Promise.allSettled(
    DNSBLS.map(async bl => {
      try {
        const res = await dnsLookup(`${reversed}.${bl.host}`, 'A');
        for (const ans of (res?.Answer || [])) {
          const code = (ans.data || '').trim();
          listings.push({
            source: bl.name,
            code,
            reason: bl.codes[code] || `Listed (response code: ${code})`
          });
        }
      } catch { /* NXDOMAIN = not listed, no action needed */ }
    })
  );

  const hostNote = mailHost ? ` (mail server ${mailHost})` : ' (no MX found — checked domain A record as fallback)';
  const result = {
    checked: true, ip, mailHost,
    listed: listings.length > 0,
    listings,
    severity: listings.length > 0 ? (listings.length >= 2 ? 'high' : 'medium') : 'clean',
    detail: listings.length
      ? `Sending IP ${ip}${hostNote} listed in: ${listings.map(l => `${l.source} (${l.reason})`).join(' | ')}`
      : `Sending IP ${ip}${hostNote} is clean across Spamhaus, SpamCop, and Barracuda`
  };

  await setCache(cacheKey, result);
  return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE 14: Thread Hijacking / BEC Thread Context Detection
// ─────────────────────────────────────────────────────────────────────────────
// Records all sender domains that participate in a thread. When a new email
// arrives in an existing thread from a domain not previously seen in that
// thread, it is flagged as a potential BEC thread hijacking.
// ═══════════════════════════════════════════════════════════════════════════════
const THREAD_STORE_KEY = 'phishalert_threads';
const MAX_THREADS = 300;
const THREAD_EXPIRY_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

async function recordThreadSender(threadId, senderEmail, senderDomain) {
  if (!threadId || !senderDomain) return { isNewThread: false };

  const stored = await chrome.storage.local.get(THREAD_STORE_KEY);
  const threads = stored[THREAD_STORE_KEY] || {};

  let isNewThread = false;
  if (!threads[threadId]) {
    isNewThread = true;
    threads[threadId] = { senders: [], domains: [], firstSeen: Date.now() };
  }

  const t = threads[threadId];
  t.lastSeen = Date.now();
  if (senderEmail && !t.senders.includes(senderEmail)) t.senders.push(senderEmail);
  if (!t.domains.includes(senderDomain)) t.domains.push(senderDomain);

  // Prune: drop threads older than 30 days, then cap total count
  const now = Date.now();
  const pruned = Object.fromEntries(
    Object.entries(threads)
      .filter(([, v]) => now - (v.lastSeen || v.firstSeen) < THREAD_EXPIRY_MS)
      .sort((a, b) => (b[1].lastSeen || 0) - (a[1].lastSeen || 0))
      .slice(0, MAX_THREADS)
  );

  await chrome.storage.local.set({ [THREAD_STORE_KEY]: pruned });
  return { isNewThread };
}

async function checkThreadHijacking(threadId, currentSenderDomain) {
  if (!threadId || !currentSenderDomain) return { hijacking: false };

  const stored = await chrome.storage.local.get(THREAD_STORE_KEY);
  const thread = (stored[THREAD_STORE_KEY] || {})[threadId];

  // No history for this thread yet — first message, nothing to compare
  if (!thread || thread.domains.length === 0) {
    return { hijacking: false, isNewThread: true };
  }

  const cur = currentSenderDomain.toLowerCase();
  const existing = thread.domains.map(d => d.toLowerCase());

  // Current domain already appeared in this thread — all good
  if (existing.includes(cur)) return { hijacking: false };

  // Allow same root domain (e.g. subdomain sender) — not a hijack
  if (existing.some(d => sameRootDomain(d, cur))) return { hijacking: false };

  // ── Guard: require the thread to have at least 2 prior unique senders
  // and be older than 5 minutes before flagging. This prevents false positives
  // on newsletters and the very first time a thread is scanned (where
  // RECORD_THREAD_SENDER and CHECK_THREAD_HIJACKING run in the same pass).
  const threadAgeMs = Date.now() - (thread.firstSeen || Date.now());
  const MIN_THREAD_AGE_MS = 5 * 60 * 1000; // 5 minutes
  const MIN_PRIOR_SENDERS = 2;              // must have seen ≥2 unique senders before

  if (threadAgeMs < MIN_THREAD_AGE_MS) {
    return { hijacking: false, reason: 'thread_too_new' };
  }
  if (thread.senders.length < MIN_PRIOR_SENDERS) {
    return { hijacking: false, reason: 'insufficient_thread_history' };
  }

  // New, unrelated domain appearing mid-thread — red flag
  return {
    hijacking: true,
    currentDomain: cur,
    threadDomains: existing,
    participantCount: thread.senders.length,
    severity: 'high',
    detail: `New domain "${cur}" appeared in a thread previously from [${existing.slice(0, 3).join(', ')}] — possible BEC thread hijacking`
  };
}

// ─── Message Router ──────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE NEW 3: Active Link Protection
// ─────────────────────────────────────────────────────────────────────────────
// Everything above only warns about a link sitting inside the email — the
// user still has to notice a badge and click it. This runs when the user
// actually clicks the link itself: it resolves the real destination (via
// scanRedirectChain, which already respects the optional broad-host
// permission and degrades gracefully without it), runs that destination
// through URLhaus + Google Safe Browsing + IDN/brand-impersonation +
// domain-age checks, and returns a single ALLOW / WARN / BLOCK verdict with
// plain-English reasons — all *before* the content script lets the browser
// navigate anywhere.
// ═══════════════════════════════════════════════════════════════════════════════

const ALP_TOP_BRANDS = [
  'google', 'microsoft', 'apple', 'amazon', 'facebook', 'meta', 'paypal', 'netflix',
  'instagram', 'twitter', 'linkedin', 'dropbox', 'slack', 'zoom', 'adobe',
  'salesforce', 'github', 'spotify', 'walmart', 'ebay', 'chase', 'wellsfargo',
  'citibank', 'barclays', 'hsbc', 'airbnb', 'uber', 'lyft', 'whatsapp',
  'outlook', 'office365', 'yahoo', 'protonmail', 'bankofamerica',
  'americanexpress', 'coinbase', 'binance', 'docusign'
];

// Reuses the same _bgLev() edit-distance helper Feature 12 (contact
// lookalike) already defines, so a link domain gets checked against real
// brand names the same way a sender domain gets checked against contacts.
function checkLinkBrandImpersonation(hostname) {
  if (!hostname) return { impersonating: false };
  const h = hostname.toLowerCase().replace(/^www\./, '');
  const base = h.split('.')[0];

  for (const brand of ALP_TOP_BRANDS) {
    if (h === `${brand}.com` || h.endsWith(`.${brand}.com`)) continue; // the real thing
    if (base === brand) continue; // e.g. brand.co.in — ccTLD alone isn't enough to flag

    if (base.length >= 4 && base.includes(brand)) {
      return {
        impersonating: true, brand, distance: 0,
        detail: `Domain "${hostname}" embeds "${brand}" in its name but isn't an official ${brand} domain`
      };
    }
    if (base.length >= 4 && Math.abs(base.length - brand.length) <= 3) {
      const dist = _bgLev(base, brand);
      const threshold = brand.length <= 6 ? 1 : 2;
      if (dist > 0 && dist <= threshold) {
        return {
          impersonating: true, brand, distance: dist,
          detail: `Domain "${hostname}" is ${dist} character${dist > 1 ? 's' : ''} away from "${brand}.com" — likely typosquat`
        };
      }
    }
  }
  return { impersonating: false };
}

// Cheap heuristic used only to phrase a warning more usefully — never on
// its own to move the score, since plenty of legitimate pages contain
// these words.
function linkLooksLikeLoginPage(url) {
  return /login|sign[-_]?in|verify|account|secure|password|auth|confirm/i.test(url);
}

// ─── PhishTank — community-verified phishing database ────────────────────────
// Unlike OpenPhish (a raw feed of submitted URLs), PhishTank distinguishes
// *submitted* from *community-verified* reports: `valid` means the vote
// concluded it's phishing, `verified` means enough trusted reviewers signed
// off on that vote. Only valid+verified counts as confirmed threat intel —
// an unverified submission is no stronger a signal than any other heuristic.
// Works without a key (lower rate limit); an app_key raises the limit.
const PHISHTANK_CACHE_TTL = 15 * 60 * 1000; // 15 minutes — verdicts get added/removed live

async function checkPhishTank(url, apiKey) {
  const cacheKey = `phishtank:${url}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  let result = { checked: false, verified: false, valid: false, confirmed: false, detail: null };

  try {
    const body = new URLSearchParams({ url, format: 'json' });
    if (apiKey) body.set('app_key', apiKey);

    const res = await fetch('https://checkurl.phishtank.com/checkurl/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
      signal: AbortSignal.timeout(6000)
    });

    if (res.ok) {
      const data = await res.json();
      const r = data?.results;
      if (r?.in_database) {
        // The API has returned both real booleans and "true"/"false"/"y"/"n" strings; !!"false" is true.
        const asBool = v => v === true || v === 1 || /^(true|yes|y|1)$/i.test(String(v));
        const verified = asBool(r.verified);
        const valid = asBool(r.valid);
        result = {
          checked: true,
          inDatabase: true,
          // Listed but the community vote hasn't concluded (what PhishTank's "Recent Submissions" are)
          pending: !verified,
          verified, valid,
          // Only a verified AND valid report is treated as confirmed —
          // matches PhishTank's own distinction between "submitted" and
          // "community-verified" phishing.
          confirmed: verified && valid,
          phishId: r.phish_id || null,
          detail: verified && valid
            ? `PhishTank: community-verified phishing report (ID ${r.phish_id})`
            : `PhishTank: submitted but not yet community-verified (ID ${r.phish_id || 'n/a'})`
        };
      }
    } else if (res.status === 509) {
      result.detail = 'PhishTank rate limit reached';
    }
  } catch (e) {
    result.detail = 'PhishTank lookup failed: ' + e.message;
  }

  try {
    const storageKey = `phishalert_cache_${cacheKey}`;
    await chrome.storage.local.set({ [storageKey]: { data: result, timestamp: Date.now() - (CACHE_EXPIRY_MS - PHISHTANK_CACHE_TTL) } });
  } catch { }

  return result;
}

async function analyzeLinkDestination({ url, senderDomain }) {
  if (!url || !/^https?:\/\//i.test(url)) {
    return { verdict: 'ALLOW', score: 100, reasons: [], finalUrl: url, domain: null, skipped: true };
  }

  const cacheKey = `alp:${url}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  let startHostname = '';
  try { startHostname = new URL(url).hostname; } catch { }

  const keys = await getApiKeys();

  const [uhResult, gsbResult, redirectResult, opResult, ptResult] = await Promise.allSettled([
    checkURLhaus(url),
    checkGoogleSafeBrowsing([url], keys.gsbApiKey || ''),
    scanRedirectChain(url, keys.vtApiKey || ''),
    checkOpenPhish(url),
    checkPhishTank(url, keys.phishtankApiKey || '')
  ]);

  const uh = uhResult.status === 'fulfilled' ? uhResult.value : null;
  const gsb = gsbResult.status === 'fulfilled' ? gsbResult.value : null;
  const rd = redirectResult.status === 'fulfilled' ? redirectResult.value
    : { finalUrl: url, chain: [url], hops: 0, crossDomain: false, limited: true, threatHops: [] };
  const op = opResult.status === 'fulfilled' ? opResult.value : null;
  const pt = ptResult.status === 'fulfilled' ? ptResult.value : null;

  const finalUrl = rd.finalUrl || url;
  let finalHostname = startHostname;
  try { finalHostname = new URL(finalUrl).hostname; } catch { }

  // A shortener/redirect can wrap a clean-looking link around a confirmed
  // phishing page — re-check the feeds against the *actual* landing page
  // too, not just the URL that appeared in the email.
  let uhFinal = uh, opFinal = op, ptFinal = pt;
  if (finalUrl !== url) {
    const [uhFinalResult, opFinalResult, ptFinalResult] = await Promise.allSettled([
      checkURLhaus(finalUrl),
      checkOpenPhish(finalUrl),
      checkPhishTank(finalUrl, keys.phishtankApiKey || '')
    ]);
    uhFinal = uhFinalResult.status === 'fulfilled' ? uhFinalResult.value : uh;
    opFinal = opFinalResult.status === 'fulfilled' ? opFinalResult.value : op;
    ptFinal = ptFinalResult.status === 'fulfilled' ? ptFinalResult.value : pt;
  }

  const [ageResult, punycode] = await Promise.all([
    getRDAPDomainAge(finalHostname).catch(() => ({ ageInDays: null })),
    Promise.resolve(detectPunycode(finalHostname))
  ]);
  const brandCheck = checkLinkBrandImpersonation(finalHostname);

  // ══════════════════════════════════════════════════════════════════════
  // LAYER 1 — Threat-intelligence override
  // A verified hit from a live feed (URLhaus, Google Safe Browsing,
  // OpenPhish, PhishTank, or a malicious hop mid-redirect) is a fundamentally
  // different kind of evidence than an accumulated heuristic score, and
  // must never get diluted into "merely suspicious" by averaging it in
  // with weaker signals. Any single confirmed match here locks the verdict
  // to BLOCK outright — heuristic scoring (Layer 2) never even runs.
  // Note: OpenPhish's own internal punycode/protocol pre-checks are
  // excluded from this layer — punycode is scored as a heuristic below
  // (it's a structural clue, not a feed match), so it can't silently
  // masquerade as "confirmed threat intelligence" here.
  // ══════════════════════════════════════════════════════════════════════
  const confirmed = [];
  if (uh?.malicious) confirmed.push({ severity: 'critical', detail: `URLhaus confirmed: ${uh.threat}` });
  if (uhFinal?.malicious && uhFinal !== uh) confirmed.push({ severity: 'critical', detail: `URLhaus confirmed at final destination: ${uhFinal.threat}` });
  if (rd.threatHops?.length) confirmed.push({ severity: 'critical', detail: `Redirect chain passes through a known-malicious domain (URLhaus): ${rd.threatHops[0].url.substring(0, 60)}` });
  if (gsb?.isMalicious) confirmed.push({ severity: 'critical', detail: `Google Safe Browsing confirmed: ${gsb.matches?.[0]?.threatType || 'malicious'}` });
  if (op?.isPhishing && op.source === 'openphish') confirmed.push({ severity: 'critical', detail: `OpenPhish confirmed: ${op.reason}` });
  if (opFinal?.isPhishing && opFinal.source === 'openphish' && opFinal !== op) confirmed.push({ severity: 'critical', detail: `OpenPhish confirmed at final destination: ${opFinal.reason}` });
  if (op?.isPhishing && op.source === 'protocol-check') confirmed.push({ severity: 'critical', detail: op.reason });
  // PhishTank: require BOTH verified and valid — a submission that hasn't
  // cleared community review is not confirmed, same standard as the feeds.
  if (pt?.verified === true && pt?.valid === true) confirmed.push({ severity: 'critical', detail: pt.detail });
  if (ptFinal?.verified === true && ptFinal?.valid === true && ptFinal !== pt) confirmed.push({ severity: 'critical', detail: `${ptFinal.detail} (final destination)` });

  if (confirmed.length > 0) {
    const supporting = [];
    if (brandCheck.impersonating) supporting.push({ severity: 'high', detail: brandCheck.detail });
    if (punycode?.suspicious) supporting.push({ severity: 'high', detail: punycode.detail });
    if (typeof ageResult?.ageInDays === 'number' && ageResult.ageInDays < 45) {
      supporting.push({ severity: 'medium', detail: `Domain registered only ${ageResult.ageInDays} day${ageResult.ageInDays === 1 ? '' : 's'} ago` });
    }
    if (linkLooksLikeLoginPage(finalUrl)) {
      supporting.push({ severity: 'medium', detail: 'Destination is a credential-harvesting-style login page' });
    }

    const result = {
      verdict: 'BLOCK',
      confirmed: true,
      score: 0,
      reasons: [...confirmed, ...supporting],
      originalUrl: url,
      finalUrl,
      domain: startHostname,
      finalDomain: finalHostname,
      redirect: { chain: rd.chain, hops: rd.hops, crossDomain: rd.crossDomain, limited: rd.limited },
      ageInDays: ageResult?.ageInDays ?? null,
      threatType: 'Confirmed phishing (threat intelligence match)'
    };
    try {
      const storageKey = `phishalert_cache_${cacheKey}`;
      await chrome.storage.local.set({ [storageKey]: { data: result, timestamp: Date.now() - (CACHE_EXPIRY_MS - 15 * 60 * 1000) } });
    } catch { }
    return result;
  }

  // ══════════════════════════════════════════════════════════════════════
  // LAYER 2 — Heuristic scoring
  // Nothing hit a live threat feed. Weigh the weaker, individually
  // circumstantial signals (no TLS, deep/cross-domain redirects, punycode,
  // brand-lookalike domain, a freshly-registered domain, login-page
  // wording) into a score. Several of these stacking together can still
  // reach BLOCK — that's "multiple strong signals," a different and lower
  // bar than a single confirmed feed hit — but no single weak signal ever
  // can on its own.
  // ══════════════════════════════════════════════════════════════════════
  let score = 100;
  const reasons = [];

  const isNoTLS = /^http:\/\//i.test(finalUrl);
  if (isNoTLS) {
    score -= 20;
    reasons.push({ severity: 'medium', detail: 'Destination uses unencrypted HTTP — no TLS/SSL protection' });
  }

  if (rd.hops >= 3) {
    score -= 12;
    reasons.push({ severity: 'medium', detail: `Link redirects through ${rd.hops} hops before landing — obscures the real destination` });
  } else if (rd.crossDomain) {
    score -= 6;
    reasons.push({ severity: 'low', detail: `Redirects from "${startHostname}" to a different domain, "${finalHostname}"` });
  }

  if (punycode?.suspicious) {
    score -= 40;
    reasons.push({ severity: 'critical', detail: punycode.detail });
  }

  if (brandCheck.impersonating) {
    score -= 35;
    reasons.push({ severity: 'critical', detail: brandCheck.detail });
  }

  if (senderDomain && finalHostname && (brandCheck.impersonating || punycode.suspicious) &&
      !finalHostname.endsWith(senderDomain.replace(/^www\./, ''))) {
    reasons.push({ severity: 'low', detail: `Also doesn't match the sender's own domain "${senderDomain}"` });
  }

  if (typeof ageResult?.ageInDays === 'number') {
    if (ageResult.ageInDays < 14) {
      score -= 20;
      reasons.push({ severity: 'high', detail: `Domain registered only ${ageResult.ageInDays} day${ageResult.ageInDays === 1 ? '' : 's'} ago — very common for phishing infrastructure` });
    } else if (ageResult.ageInDays < 45) {
      score -= 10;
      reasons.push({ severity: 'medium', detail: `Domain is only ${Math.round(ageResult.ageInDays / 7)} week(s) old` });
    }
  }

  if (linkLooksLikeLoginPage(finalUrl) && (isNoTLS || brandCheck.impersonating || punycode.suspicious)) {
    // Deliberately NOT triggered by login-page wording alone (see note
    // above the function) — only counts alongside at least one other
    // structural red flag.
    reasons.push({ severity: 'high', detail: 'Destination looks like a login/credential page combined with the issue(s) above — treat with extra caution' });
  }

  score = Math.max(0, Math.min(100, score));
  const verdict = score < 40 ? 'BLOCK' : score < 75 ? 'WARN' : 'ALLOW';

  const result = {
    verdict, score, reasons,
    confirmed: false,
    originalUrl: url,
    finalUrl,
    domain: startHostname,
    finalDomain: finalHostname,
    redirect: { chain: rd.chain, hops: rd.hops, crossDomain: rd.crossDomain, limited: rd.limited },
    ageInDays: ageResult?.ageInDays ?? null,
    threatType: brandCheck.impersonating ? 'Brand impersonation'
      : punycode.suspicious ? 'IDN/punycode spoof'
      : verdict !== 'ALLOW' ? 'Multiple risk indicators'
      : null
  };

  // Short TTL like URLhaus — a takedown or a freshly-weaponized redirect
  // should be reflected quickly, not stuck behind the 1-hour default cache.
  try {
    const storageKey = `phishalert_cache_${cacheKey}`;
    await chrome.storage.local.set({ [storageKey]: { data: result, timestamp: Date.now() - (CACHE_EXPIRY_MS - 15 * 60 * 1000) } });
  } catch { }

  return result;
}

// ═══════════════════════════════════════════════════════════════════════════════
// FEATURE NEW 4: Phishing DNA — Attack Campaign Detection
// ─────────────────────────────────────────────────────────────────────────────
// Everything above judges ONE email/link in isolation. This correlates every
// email PhishAlert has scanned (across all four clients) into a graph and
// looks for clusters that share infrastructure — the pattern of a
// coordinated campaign rather than a one-off message. Each scanned email
// contributes a lightweight fingerprint (sender domain, reply-to domain,
// link hostnames, subject template, brand impersonated); campaigns are
// clusters of fingerprints connected by at least one shared signal.
// ═══════════════════════════════════════════════════════════════════════════════

const PD_STORE_KEY = 'phishalert_campaign_fingerprints';
const PD_MAX_FINGERPRINTS = 800;
const PD_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function pdHostname(url) {
  try { return new URL(url).hostname.toLowerCase().replace(/^www\./, ''); } catch { return ''; }
}

// Collapses a subject line down to its "template" shape so that
// "Action Required: Verify account #48213" and "Action Required: Verify
// account #91027" hash to the same signature, while unrelated subjects don't.
function pdSubjectSignature(subject) {
  if (!subject) return '';
  return subject
    .toLowerCase()
    .replace(/[0-9]+/g, '#')
    .replace(/[^\w\s#]/g, '')
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 6)
    .join(' ');
}

// Reuses the same brand list / edit-distance heuristic as Active Link
// Protection (checkLinkBrandImpersonation) so a sender domain and a link
// domain are judged against brands the same way.
function pdDetectBrand(hostname) {
  const r = checkLinkBrandImpersonation(hostname);
  return r.impersonating ? r.brand : null;
}

async function pdGetFingerprints() {
  const stored = await chrome.storage.local.get(PD_STORE_KEY);
  return stored[PD_STORE_KEY] || [];
}

async function pdSaveFingerprints(list) {
  const cutoff = Date.now() - PD_MAX_AGE_MS;
  const pruned = list.filter(f => f.timestamp >= cutoff).slice(0, PD_MAX_FINGERPRINTS);
  await chrome.storage.local.set({ [PD_STORE_KEY]: pruned });
}

// Records one scanned email as a fingerprint. Called by every content
// script right after it resolves the sender domain — non-blocking, best
// effort, never affects the scan/banner shown to the user.
async function recordCampaignFingerprint(fp) {
  const domain = (fp.domain || '').toLowerCase();
  if (!domain) return { success: false };

  const replyToDomain = fp.replyTo ? (fp.replyTo.match(/@([\w.-]+)/)?.[1] || '').toLowerCase() : '';
  const linkDomains = [...new Set((fp.links || []).map(pdHostname).filter(Boolean).filter(h => h !== domain))].slice(0, 12);

  let brand = pdDetectBrand(domain);
  if (!brand) {
    for (const h of linkDomains) { brand = pdDetectBrand(h); if (brand) break; }
  }

  const record = {
    id: `${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    timestamp: Date.now(),
    client: fp.client || 'unknown',
    from: fp.from || '',
    domain,
    replyToDomain: replyToDomain && replyToDomain !== domain ? replyToDomain : '',
    linkDomains,
    brand,
    subjectSig: pdSubjectSignature(fp.subject || ''),
    subjectRaw: (fp.subject || '').slice(0, 140)
  };

  const list = await pdGetFingerprints();
  // De-dupe: same domain + same subject signature within the last hour is
  // almost certainly the same email re-scanned (DOM mutation re-triggers).
  const isDupe = list.some(f => f.domain === record.domain && f.subjectSig === record.subjectSig &&
    record.timestamp - f.timestamp < 60 * 60 * 1000);
  if (!isDupe) {
    list.unshift(record);
    await pdSaveFingerprints(list);
  }
  return { success: true };
}

// Union-Find over fingerprint indices, connected whenever two fingerprints
// share a signal. Kept intentionally simple (small N — capped at 800) over
// a proper graph DB.
function pdUnionFind(n) {
  const parent = Array.from({ length: n }, (_, i) => i);
  function find(x) { while (parent[x] !== x) { parent[x] = parent[parent[x]]; x = parent[x]; } return x; }
  function union(a, b) { const ra = find(a), rb = find(b); if (ra !== rb) parent[ra] = rb; }
  return { find, union };
}

function pdShareLinkDomain(a, b) {
  return a.linkDomains.some(d => b.linkDomains.includes(d));
}

// Two sender domains that are close edit-distance variants of each other
// (typosquat siblings) — same idea as checkLinkBrandImpersonation, but
// comparing scanned domains against each other instead of against a fixed
// brand list, so campaigns using a *new* impersonated brand still cluster.
function pdDomainsAreSiblings(a, b) {
  if (a === b) return false;
  const baseA = a.split('.')[0], baseB = b.split('.')[0];
  if (baseA.length < 5 || baseB.length < 5) return false;
  if (Math.abs(baseA.length - baseB.length) > 3) return false;
  const dist = _bgLev(baseA, baseB);
  return dist > 0 && dist <= 2;
}

function pdSignalsBetween(a, b) {
  const signals = [];
  if (a.brand && b.brand && a.brand === b.brand) signals.push('brand');
  if (a.replyToDomain && a.replyToDomain === b.replyToDomain) signals.push('reply-to');
  if (pdShareLinkDomain(a, b)) signals.push('shared-url');
  if (a.subjectSig && a.subjectSig === b.subjectSig) signals.push('subject');
  if (pdDomainsAreSiblings(a.domain, b.domain)) signals.push('typosquat');
  return signals;
}

// Builds every campaign cluster currently visible in the stored
// fingerprints. Recomputed on demand (cheap at this scale) rather than
// incrementally maintained, so it's always consistent with what's stored.
async function computeCampaigns() {
  const list = await pdGetFingerprints();
  const n = list.length;
  if (n < 2) return [];

  const uf = pdUnionFind(n);
  const edgeSignals = new Map();

  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      const signals = pdSignalsBetween(list[i], list[j]);
      if (signals.length) {
        uf.union(i, j);
        edgeSignals.set(`${i}|${j}`, signals);
      }
    }
  }

  const groups = new Map();
  for (let i = 0; i < n; i++) {
    const root = uf.find(i);
    if (!groups.has(root)) groups.set(root, []);
    groups.get(root).push(i);
  }

  const campaigns = [];
  for (const [root, idxs] of groups.entries()) {
    if (idxs.length < 2) continue; // a campaign needs at least 2 correlated emails
    const members = idxs.map(i => list[i]);

    const signalTypes = new Set();
    for (const [key, signals] of edgeSignals.entries()) {
      const [i, j] = key.split('|').map(Number);
      if (idxs.includes(i) && idxs.includes(j)) signals.forEach(s => signalTypes.add(s));
    }

    const domains = [...new Set(members.map(m => m.domain))];
    const urlDomains = [...new Set(members.flatMap(m => m.linkDomains))];
    const brands = members.map(m => m.brand).filter(Boolean);
    const brandCounts = brands.reduce((acc, b) => { acc[b] = (acc[b] || 0) + 1; return acc; }, {});
    const topBrand = Object.keys(brandCounts).sort((a, b) => brandCounts[b] - brandCounts[a])[0] || null;
    const timestamps = members.map(m => m.timestamp);
    const clients = [...new Set(members.map(m => m.client))];

    // Confidence: weighted mix of how many distinct kinds of evidence link
    // the cluster together, plus how many separate emails/domains it spans.
    // Capped at 97 — this is correlation, never treated as certainty.
    const signalWeight = { brand: 22, 'reply-to': 20, 'shared-url': 24, subject: 16, typosquat: 26 };
    let confidence = [...signalTypes].reduce((sum, s) => sum + (signalWeight[s] || 10), 0);
    confidence += Math.min(20, (members.length - 2) * 4) + Math.min(10, (domains.length - 1) * 3);
    confidence = Math.max(35, Math.min(97, confidence));

    campaigns.push({
      id: `campaign_${domains.slice().sort().join('_').slice(0, 40)}_${root}`,
      confidence,
      brand: topBrand,
      emailCount: members.length,
      domainCount: domains.length,
      urlCount: urlDomains.length,
      clients,
      signalTypes: [...signalTypes],
      domains,
      urlDomains,
      firstSeen: Math.min(...timestamps),
      lastSeen: Math.max(...timestamps),
      members: members
        .sort((a, b) => b.timestamp - a.timestamp)
        .map(m => ({ from: m.from, domain: m.domain, replyToDomain: m.replyToDomain, linkDomains: m.linkDomains, brand: m.brand, subject: m.subjectRaw, client: m.client, timestamp: m.timestamp }))
    });
  }

  return campaigns.sort((a, b) => b.confidence - a.confidence || b.lastSeen - a.lastSeen);
}

// ─── FEATURE NEW 5: Investigation Mode — IOC Extraction Engine ───────────────
// Turns everything a scan already gathered (sender, reply-to, links, redirect
// chains, DNSBL-resolved mail-server IP, attachments) into a single normalized
// Indicators-of-Compromise record. This is real extraction/normalization of
// data PhishAlert collected during scoring — nothing here is fabricated —
// and it's the foundation both the Investigation tab and incident reports
// read from.

const IOC_STORE_KEY = 'phishalert_ioc_store';
const IOC_STORE_MAX = 200;

function iocHostname(input) {
  if (!input) return null;
  const str = String(input).trim();
  if (str.includes('://')) {
    try { return new URL(str).hostname.toLowerCase(); } catch { /* fall through */ }
  }
  const atMatch = str.match(/@([\w.-]+\.[a-z]{2,})/i);
  if (atMatch) return atMatch[1].toLowerCase();
  const bareMatch = str.match(/^([\w.-]+\.[a-z]{2,})/i);
  return bareMatch ? bareMatch[1].toLowerCase() : null;
}

function iocEmailsFromText(text) {
  if (!text) return [];
  const matches = String(text).match(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/gi) || [];
  return [...new Set(matches.map(m => m.toLowerCase()))];
}

function iocIPsFromText(text) {
  if (!text) return [];
  const matches = String(text).match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  return [...new Set(matches.filter(ip => ip.split('.').every(o => Number(o) <= 255)))];
}

// Normalizes raw scan-time evidence into the IOC shape. `raw` fields are all
// optional — every content script supplies what it actually has access to.
function normalizeIOCs(raw) {
  const urls = new Set();
  const domains = new Set();
  const ipAddresses = new Set();
  const emailAddresses = new Set();
  const replyTo = new Set();
  const redirects = [];
  const attachments = [];

  if (raw.domain) domains.add(String(raw.domain).toLowerCase());

  if (raw.from) {
    emailAddresses.add(String(raw.from).toLowerCase());
    const d = iocHostname(raw.from);
    if (d) domains.add(d);
  }

  if (raw.replyTo) {
    const rt = String(raw.replyTo).toLowerCase();
    replyTo.add(rt);
    emailAddresses.add(rt);
    const d = iocHostname(raw.replyTo);
    if (d) domains.add(d);
  }

  (raw.links || []).forEach(url => {
    if (!url || typeof url !== 'string') return;
    urls.add(url);
    const d = iocHostname(url);
    if (d) domains.add(d);
  });

  // Redirect chains, already resolved via scanRedirectChain/UNSHORT_URL —
  // never invented here, only normalized.
  (raw.redirects || []).forEach(r => {
    if (!r) return;
    const chainHops = (r.chain || []).map(h => (typeof h === 'string' ? h : h.url)).filter(Boolean);
    chainHops.forEach(hop => { const d = iocHostname(hop); if (d) domains.add(d); });
    const finalDomain = iocHostname(r.finalUrl);
    if (finalDomain) domains.add(finalDomain);
    redirects.push({
      originalUrl: r.originalUrl || null,
      hops: r.hops || chainHops.length,
      chain: chainHops,
      finalUrl: r.finalUrl || null,
      finalDomain,
      crossDomain: !!r.crossDomain,
      flaggedHop: (r.threatHops && r.threatHops[0]) ? (r.threatHops[0].url || null) : null
    });
  });

  (raw.attachments || []).forEach(a => {
    if (!a) return;
    attachments.push({
      fileName: a.fileName || 'unknown',
      mimeType: a.mimeType || null,
      riskLevel: a.riskLevel || null
    });
  });

  if (raw.dnsblIp) ipAddresses.add(raw.dnsblIp);
  iocIPsFromText(raw.headerText).forEach(ip => ipAddresses.add(ip));
  iocEmailsFromText(raw.body).forEach(e => emailAddresses.add(e));

  return {
    urls: [...urls],
    domains: [...domains],
    ipAddresses: [...ipAddresses],
    emailAddresses: [...emailAddresses],
    replyTo: [...replyTo],
    redirects,
    attachments,
    client: raw.client || null,
    extractedAt: Date.now()
  };
}

async function extractAndStoreIOCs(message) {
  const iocs = normalizeIOCs(message.data || {});
  const scanKey = message.scanKey || `${message.data?.domain || 'unknown'}::${message.data?.from || ''}`;

  const stored = await chrome.storage.local.get(IOC_STORE_KEY);
  const store = stored[IOC_STORE_KEY] || {};
  store[scanKey] = iocs;
  const keys = Object.keys(store);
  if (keys.length > IOC_STORE_MAX) {
    keys.sort((a, b) => (store[a].extractedAt || 0) - (store[b].extractedAt || 0));
    delete store[keys[0]];
  }
  await chrome.storage.local.set({ [IOC_STORE_KEY]: store });

  // Attach to the "current scan" the popup already reads via GET_LAST_SCAN,
  // so the Investigation tab shows IOCs for whatever email is open right now.
  const cur = await chrome.storage.local.get('phishalert_current_scan');
  if (cur.phishalert_current_scan) {
    cur.phishalert_current_scan.iocs = iocs;
    cur.phishalert_current_scan.iocScanKey = scanKey;
    await chrome.storage.local.set({ phishalert_current_scan: cur.phishalert_current_scan });
  }

  return iocs;
}

async function getIOCsForScan(scanKey) {
  if (!scanKey) return null;
  const stored = await chrome.storage.local.get(IOC_STORE_KEY);
  return (stored[IOC_STORE_KEY] || {})[scanKey] || null;
}

// ═══════════════════════════════════════════════════════════════════════
// FEATURE NEW 6: Active Deception & Infrastructure Intelligence
// Stage 2 — extension side. Talks to the Stage 1 Cloudflare Worker
// (phishalert-canary) to deploy a canary against a flagged email and pull
// back classified telemetry. Never auto-sends anything and never visits
// the real phishing destination — see buildDecoyReply() and the privacy
// note below. Deployment only ever happens from an explicit user click
// on "Deploy Bait" in the Threats & Forensics tab.
// ═══════════════════════════════════════════════════════════════════════
const CANARY_STORE_KEY = 'phishalert_canary_deployments';
const CANARY_STORE_MAX = 100;

// ZERO-SETUP CANARY: the capture server is run once by the developer, and its
// address is built in here. Users never see a URL or an API key — on first use
// the extension registers itself and keeps its own private key (encrypted).
// Set automatically by canary-server/deploy-canary.js (or paste it once by hand).
const CANARY_WORKER_URL = 'https://phishalert-canary.phishalert-canary.workers.dev';

async function getCanaryConfig() {
  const s = await chrome.storage.local.get('phishalert_settings');
  const settings = s.phishalert_settings || {};
  const keys = await getApiKeys();
  return {
    // a custom worker saved by an older build still wins; otherwise the built-in one
    workerUrl: (settings.canaryWorkerUrl || CANARY_WORKER_URL).replace(/\/+$/, ''),
    apiKey: keys.canaryApiKey || ''
  };
}

// Returns a ready config, registering this install with the server if it has no key yet.
// forceNew=true discards the stored key first (used when the server rejects it).
async function ensureCanaryConfig(forceNew) {
  const cfg = await getCanaryConfig();
  if (!cfg.workerUrl || cfg.workerUrl.includes('YOUR-SUBDOMAIN')) {
    return { error: 'Canary server is not set up yet.' };
  }
  if (cfg.apiKey && !forceNew) return cfg;
  try {
    const res = await fetch(`${cfg.workerUrl}/api/register`, { method: 'POST' });
    if (res.status === 429) return { error: 'Canary service is busy right now — try again later.' };
    if (!res.ok) return { error: `Canary service unavailable (HTTP ${res.status}).` };
    const data = await res.json();
    if (!data.apiKey) return { error: 'Canary service unavailable.' };
    await updateApiKeys(cur => ({ ...cur, canaryApiKey: data.apiKey }));
    return { workerUrl: cfg.workerUrl, apiKey: data.apiKey };
  } catch (e) {
    return { error: 'Could not reach canary service: ' + e.message };
  }
}

async function getCanaryDeployments() {
  const stored = await chrome.storage.local.get(CANARY_STORE_KEY);
  return stored[CANARY_STORE_KEY] || {};
}

async function saveCanaryDeployment(scanKey, deployment) {
  const store = await getCanaryDeployments();
  store[scanKey] = deployment;
  const keys = Object.keys(store);
  if (keys.length > CANARY_STORE_MAX) {
    keys.sort((a, b) => (store[a].createdAtMs || 0) - (store[b].createdAtMs || 0));
    delete store[keys[0]];
  }
  await chrome.storage.local.set({ [CANARY_STORE_KEY]: store });
}

// Builds the decoy reply text the user can review and paste into a normal
// reply in their own webmail. Deliberately NOT auto-sent — see Stage 1
// README privacy boundary. The pixel is invisible; the link is disguised
// as a plausible, low-friction action (an "unsubscribe" style link) so it
// reads as an ordinary reply rather than tipping off the recipient that
// it's instrumented.
function buildDecoyReply(canary) {
  const pixelTag = `<img src="${canary.pixelUrl}" width="1" height="1" style="display:none" alt="" />`;
  const bodyHtml =
    `<p>Hi,</p>` +
    `<p>Thanks for reaching out — could you confirm this is legitimate? ` +
    `You can also <a href="${canary.linkUrl}">unsubscribe from future notices</a> if this reached me in error.</p>` +
    `<p>Thanks.</p>` +
    pixelTag;
  const bodyPlain =
    `Hi,\n\nThanks for reaching out — could you confirm this is legitimate? ` +
    `You can also unsubscribe from future notices if this reached me in error: ${canary.linkUrl}\n\nThanks.`;
  return { html: bodyHtml, plain: bodyPlain };
}

// FEATURE NEW 6: Active Defense — Test Connection. Lets the popup verify a
// worker URL + API key actually reach a live capture endpoint, so a
// misconfigured or unreachable worker is caught before the user tries
// Deploy Bait and gets a generic failure inside the Threats tab.
async function testCanaryConnection(message) {
  const workerUrl = (message.workerUrl || '').trim().replace(/\/+$/, '');
  const apiKey = (message.apiKey || '').trim();
  if (!workerUrl || !apiKey) {
    return { ok: false, error: 'Enter both the worker URL and API key first.' };
  }
  if (!/^https:\/\//i.test(workerUrl)) {
    return { ok: false, error: 'Worker URL must start with https://' };
  }
  try {
    const res = await fetch(`${workerUrl}/api/canary/ping`, {
      method: 'GET',
      headers: { 'x-api-key': apiKey }
    });
    if (res.status === 401 || res.status === 403) {
      return { ok: false, error: `Worker reachable but rejected the API key (HTTP ${res.status}).` };
    }
    if (!res.ok && res.status !== 404) {
      // A 404 still proves the worker itself answered — some deployments
      // may not implement a dedicated /ping route, so treat that as reachable.
      return { ok: false, error: `Worker responded with HTTP ${res.status}.` };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, error: 'Could not reach worker: ' + e.message };
  }
}

async function deployCanaryBait(message) {
  let cfg = await ensureCanaryConfig(false);
  if (cfg.error) return { error: cfg.error };

  const scanKey = message.scanKey;
  if (!scanKey) return { error: 'No scan context to deploy a canary against.' };

  // Reuse an existing campaign id from Phishing DNA if this domain is
  // already part of a correlated cluster, so canary telemetry folds
  // straight into the same campaign view instead of starting a new one.
  const campaigns = await computeCampaigns();
  const domain = (message.domain || '').toLowerCase();
  const matchedCampaign = (campaigns || []).find(c => (c.domains || []).includes(domain));
  const campaignId = matchedCampaign ? matchedCampaign.id : `AD-HOC-${domain || 'unknown'}`;

  const postCanary = () => fetch(`${cfg.workerUrl}/api/canary`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': cfg.apiKey },
    body: JSON.stringify({
      campaignId,
      emailId: scanKey,
      senderDomain: domain,
      riskScore: typeof message.riskScore === 'number' ? message.riskScore : null,
      baitType: message.baitType === 'link' ? 'link' : 'pixel'
    })
  });
  let res;
  try {
    res = await postCanary();
    if (res.status === 401) {
      // stored key no longer known to the server (expired / server reset) — get a fresh one, retry once
      cfg = await ensureCanaryConfig(true);
      if (cfg.error) return { error: cfg.error };
      res = await postCanary();
    }
  } catch (e) {
    return { error: 'Could not reach canary service: ' + e.message };
  }
  if (res.status === 429) {
    return { error: 'Daily canary limit reached — try again tomorrow.' };
  }
  if (!res.ok) {
    return { error: `Canary service returned ${res.status}` };
  }
  const canary = await res.json();

  const deployment = {
    ...canary,
    scanKey,
    domain,
    createdAtMs: Date.now(),
    decoyReply: buildDecoyReply(canary),
    events: []
  };
  await saveCanaryDeployment(scanKey, deployment);
  return deployment;
}

async function getCanaryDeploymentForScan(scanKey) {
  if (!scanKey) return null;
  const store = await getCanaryDeployments();
  return store[scanKey] || null;
}

// Polls the worker for fresh telemetry on a deployed canary and merges it
// into the stored deployment record. Called on demand from the popup —
// never on a background timer, so it only ever runs while the user is
// actually looking at the Forensics tab.
async function getCanaryEvents(scanKey) {
  const store = await getCanaryDeployments();
  const deployment = store[scanKey];
  if (!deployment) return null;

  const cfg = await getCanaryConfig();
  if (!cfg.workerUrl || !cfg.apiKey) return deployment;

  try {
    const res = await fetch(
      `${cfg.workerUrl}/api/canary/${deployment.canaryId}/events`,
      { headers: { 'x-api-key': cfg.apiKey } }
    );
    if (res.ok) {
      const data = await res.json();
      deployment.events = data.events || [];
      await saveCanaryDeployment(scanKey, deployment);
    }
  } catch { /* stale data is fine, never block the popup on a network blip */ }

  return deployment;
}

// ─── FEATURE NEW 5: One-Click Incident Report ────────────────────────────────
function iocClassifyAttack(scanEntry) {
  const t = scanEntry.threats || {};
  const c = scanEntry.checks || {};
  if (t.bimi?.isImpersonatingBrand || t.homograph?.targetBrand) return 'Brand Impersonation / Credential Phishing';
  if (t.contactLookalike) return 'Contact Lookalike Domain Phishing';
  if (t.replyToMismatch) return 'Reply-To Redirection Phishing';
  if (c.vt?.isMalicious || c.dnsbl?.listed) return 'Malware / Blacklisted Infrastructure';
  if (t.urgency) return 'Social-Engineering (Urgency) Phishing';
  return scanEntry.score < 45 ? 'Suspected Phishing' : 'Undetermined';
}

function iocScoreTier(score) {
  if (score >= 90) return 'TRUSTED';
  if (score >= 70) return 'LIKELY SAFE';
  if (score >= 45) return 'SUSPICIOUS';
  if (score >= 20) return 'HIGH RISK';
  return 'CRITICAL';
}

// ═══════════════════════════════════════════════════════════════════════
// REPORTS V2 — Persisted Case/Report Management
// Reports tab used to just re-read live scan/community data (nothing was
// ever saved as "a report I generated"). This store gives every generated
// report a permanent case record — id, status, snapshot of the evidence at
// generation time — so the Reports tab can be a case repository instead of
// a second copy of Threats & Forensics.
// ═══════════════════════════════════════════════════════════════════════
const CASE_STORE_KEY = 'phishalert_case_reports';
const CASE_STORE_MAX = 200;

async function getCaseReports() {
  const data = await chrome.storage.local.get(CASE_STORE_KEY);
  return data[CASE_STORE_KEY] || [];
}

async function saveCaseReports(list) {
  await chrome.storage.local.set({ [CASE_STORE_KEY]: list.slice(0, CASE_STORE_MAX) });
}

async function sha256Hex(str) {
  const enc = new TextEncoder().encode(str);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function caseBuildId(existingList) {
  const now = new Date();
  const dateStr = '' + now.getFullYear() + String(now.getMonth() + 1).padStart(2, '0') + String(now.getDate()).padStart(2, '0');
  const prefix = 'PA-' + dateStr + '-';
  const sameDay = (existingList || []).filter(r => r.id && r.id.indexOf(prefix) === 0);
  const seq = String(sameDay.length + 1).padStart(3, '0');
  return prefix + seq;
}

function caseDefaultStatus(tier) {
  return (tier === 'TRUSTED' || tier === 'LIKELY SAFE') ? 'RESOLVED' : 'OPEN';
}

function formatHeaderLabelBg(type) {
  return String(type || '').replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

// Reconstructs the same condensed "findings" list the Threats & Forensics
// Overview shows, straight from the stored scan + phase4 data, so a
// generated report's findings never drift from what the case actually
// showed when it was scanned.
function buildThreatFindings(entry, phase4) {
  const findings = [];
  const checks = entry.checks || {};
  const threats = entry.threats || {};
  const icons = { spf: '🔒', dkim: '✍️', dmarc: '📋' };
  const labels = { spf: 'SPF', dkim: 'DKIM', dmarc: 'DMARC' };

  ['spf', 'dkim', 'dmarc'].forEach(k => {
    const c = checks[k];
    if (c && !c.pass) findings.push({ icon: icons[k], title: labels[k] + ' Failure', level: 'warn' });
  });
  if (checks.mx && checks.mx.suspicious) findings.push({ icon: '📮', title: 'No MX Records', level: 'critical' });
  if (threats.displayNameSpoof?.spoofing) findings.push({ icon: '🎭', title: 'Display Name Spoofing', level: 'critical' });
  if (threats.punycode?.suspicious) findings.push({ icon: '🔤', title: 'Punycode / IDN Attack', level: 'critical' });
  if (threats.homograph?.detected) findings.push({ icon: '🔤', title: 'IDN Homograph: Mimics "' + (threats.homograph.targetBrand || '') + '"', level: 'critical' });
  if (checks.vt?.available && checks.vt?.isMalicious) findings.push({ icon: '🦠', title: 'VirusTotal: Malicious', level: 'critical' });
  if (threats.bimi?.isImpersonatingBrand) findings.push({ icon: '⚠️', title: 'BIMI: No record — likely impersonating ' + threats.bimi.claimedBrand, level: 'warn' });

  const issues = (phase4 && phase4.headerAnalysis && phase4.headerAnalysis.issues) || [];
  issues.forEach(issue => {
    findings.push({ icon: '📨', title: formatHeaderLabelBg(issue.type), level: issue.severity === 'high' ? 'critical' : 'warn' });
  });

  const atts = (phase4 && phase4.attachmentResults) || [];
  atts.filter(a => a.riskLevel === 'dangerous').forEach(a => {
    findings.push({ icon: '📎', title: 'Dangerous Attachment: ' + a.fileName, level: 'critical' });
  });

  const tList = entry.threatList || (Array.isArray(entry.threats) ? entry.threats : []) || [];
  tList.filter(t => typeof t === 'string').forEach(t => {
    const alreadyCovered = ['Display name spoofing', 'VirusTotal: Malicious'].some(k => t.includes(k));
    if (!alreadyCovered) findings.push({ icon: '⚠️', title: t, level: 'warn' });
  });

  return findings;
}

// ── Report type templates — same underlying snapshot, different depth ────
function buildIncidentLines(entry, iocs, tier, attackType, targetBrand, findings) {
  const lines = [];
  lines.push('PHISHALERT INCIDENT REPORT');
  lines.push('Generated: ' + new Date().toLocaleString());
  lines.push('');
  lines.push('Verdict: ' + tier + ' (' + (entry.score ?? 0) + '/100)');
  lines.push('Attack Type: ' + attackType);
  if (targetBrand) lines.push('Target Brand: ' + targetBrand);
  lines.push('');
  lines.push('Sender: ' + (entry.sender || 'unknown'));
  lines.push('Sender Domain: ' + (entry.domain || 'unknown'));
  lines.push('');
  lines.push('Threat Findings:');
  if (findings && findings.length) findings.forEach(f => lines.push('  - ' + f.title));
  else lines.push('  No specific issues detected.');
  lines.push('');
  lines.push('Indicators of Compromise:');
  lines.push('  Domains: ' + ((iocs.domains || []).join(', ') || 'none'));
  lines.push('  URLs extracted: ' + ((iocs.urls || []).length));
  lines.push('  Email Addresses: ' + ((iocs.emailAddresses || []).join(', ') || 'none'));
  lines.push('');
  lines.push('Recommended Response:');
  lines.push(tier === 'CRITICAL' || tier === 'HIGH RISK' ? '  ⛔ Block sender and report as phishing.' :
    tier === 'SUSPICIOUS' ? '  ⚠️ Verify sender through another channel before acting.' : '  ✅ No action required.');
  return lines;
}

function buildExecutiveLines(ctx) {
  const { entry, tier, attackType, targetBrand, iocs, blocked } = ctx;
  const indicatorCount = (iocs.urls || []).length + (iocs.domains || []).length + (iocs.ipAddresses || []).length + (iocs.emailAddresses || []).length;
  const lines = [];
  lines.push('PHISHALERT EXECUTIVE SUMMARY');
  lines.push('Generated: ' + new Date().toLocaleString());
  lines.push('');
  lines.push(targetBrand
    ? 'A ' + attackType.toLowerCase() + ' email impersonating ' + targetBrand + ' was detected from ' + (entry.domain || 'an unknown sender') + '.'
    : 'A ' + attackType.toLowerCase() + ' email was detected from ' + (entry.domain || 'an unknown sender') + '.');
  lines.push(indicatorCount > 0
    ? 'The message contained ' + indicatorCount + ' indicator' + (indicatorCount !== 1 ? 's' : '') + ' associated with this activity.' + (blocked ? ' PhishAlert has blocked the associated sender.' : '')
    : 'No further indicators of compromise were extracted from this message.');
  lines.push('');
  lines.push('Risk: ' + tier);
  lines.push('Action: ' + (blocked ? 'BLOCKED' : (tier === 'CRITICAL' || tier === 'HIGH RISK' ? 'RECOMMEND BLOCK' : tier === 'SUSPICIOUS' ? 'RECOMMEND CAUTION' : 'NO ACTION NEEDED')));
  lines.push('Affected Email: 1');
  lines.push('Indicators: ' + indicatorCount);
  return lines;
}

function buildThreatIntelLines(weekly, campaigns) {
  const lines = [];
  lines.push('PHISHALERT THREAT INTELLIGENCE REPORT');
  lines.push('Generated: ' + new Date().toLocaleString());
  lines.push('');
  if (!weekly || !weekly.hasData) {
    lines.push('No emails scanned in the past 7 days — insufficient data for this period.');
    return lines;
  }
  lines.push('Period: ' + weekly.period.from + ' – ' + weekly.period.to);
  lines.push('Emails Scanned: ' + weekly.totalScanned);
  lines.push('Threats Detected: ' + weekly.threatsCount);
  lines.push('Average Trust Score: ' + weekly.avgTrustScore + '/100');
  lines.push('');
  lines.push('Top Malicious / Risky Domains:');
  (weekly.topRiskyDomains || []).forEach(d => lines.push('  - ' + d.domain + ' (' + d.count + ' scan' + (d.count !== 1 ? 's' : '') + ')'));
  if (!weekly.topRiskyDomains || !weekly.topRiskyDomains.length) lines.push('  None');
  lines.push('');
  lines.push('Top Attack Techniques:');
  (weekly.topAttacks || []).forEach(a => lines.push('  - ' + a.type + ' (' + a.count + ')'));
  if (!weekly.topAttacks || !weekly.topAttacks.length) lines.push('  None');
  lines.push('');
  lines.push('Active Campaigns:');
  if (campaigns && campaigns.length) {
    campaigns.forEach(c => lines.push('  - ' + (c.brand ? c.brand + ' impersonation' : 'Coordinated cluster') + ' — ' + c.confidence + '% confidence, ' + c.emailCount + ' emails across ' + c.domainCount + ' domains'));
  } else {
    lines.push('  None detected');
  }
  return lines;
}

async function generateCaseReport(scanEntry, reportType) {
  const type = reportType || 'incident';

  if (type === 'threat_intel') {
    const weekly = await generateWeeklyReport();
    const campaigns = await computeCampaigns().catch(() => []);
    const lines = buildThreatIntelLines(weekly, campaigns);
    const reportText = lines.join('\n');
    const hash = await sha256Hex(reportText);
    const list = await getCaseReports();
    const id = caseBuildId(list);
    const record = {
      id, createdAt: Date.now(), reportType: type,
      domain: null, sender: null, score: weekly?.avgTrustScore ?? null,
      tier: 'INTEL', attackType: 'Threat Intelligence Summary', targetBrand: null,
      status: 'RESOLVED', findings: [], iocs: null, campaign: null,
      checks: null, timestamp: Date.now(), iocsExtractedAt: null, replyToMismatch: false,
      reportText, hash
    };
    list.unshift(record);
    await saveCaseReports(list);
    return { success: true, case: record };
  }

  if (!scanEntry) return { error: 'No scan data available yet — open an email first.' };

  const iocs = scanEntry.iocs || (scanEntry.iocScanKey ? await getIOCsForScan(scanEntry.iocScanKey) : null) || {
    urls: [], domains: [], ipAddresses: [], emailAddresses: [], replyTo: [], redirects: [], attachments: []
  };
  const tier = iocScoreTier(scanEntry.score ?? 0);
  const attackType = iocClassifyAttack(scanEntry);
  const t = scanEntry.threats || {};
  const targetBrand = t.bimi?.claimedBrand || t.homograph?.targetBrand || t.contactLookalike?.targetDomain || null;

  let campaign = null;
  try {
    const campaigns = await computeCampaigns();
    campaign = campaigns.find(cc => cc.domains?.includes(scanEntry.domain)) || null;
  } catch { /* best-effort */ }

  const p4d = await chrome.storage.local.get('phishalert_phase4');
  const phase4 = p4d.phishalert_phase4 || null;
  const findings = buildThreatFindings(scanEntry, phase4);

  const blockedData = await getBlockedSenders().catch(() => ({}));
  const isBlocked = !!(scanEntry.sender && blockedData && blockedData[scanEntry.sender]);

  let lines;
  if (type === 'executive') {
    lines = buildExecutiveLines({ entry: scanEntry, tier, attackType, targetBrand, iocs, blocked: isBlocked });
  } else if (type === 'forensic') {
    const inc = await generateIncidentReport(scanEntry);
    lines = (inc && inc.report ? inc.report : '').split('\n');
    lines[0] = 'PHISHALERT FORENSIC REPORT';
  } else {
    lines = buildIncidentLines(scanEntry, iocs, tier, attackType, targetBrand, findings);
  }

  let reportText = lines.join('\n');
  const hash = await sha256Hex(reportText);
  reportText += '\n\nEvidence Integrity (SHA-256): ' + hash;

  const list = await getCaseReports();
  const id = caseBuildId(list);
  const record = {
    id,
    createdAt: Date.now(),
    reportType: type,
    domain: scanEntry.domain || null,
    sender: scanEntry.sender || null,
    score: scanEntry.score ?? null,
    tier,
    attackType,
    targetBrand,
    status: caseDefaultStatus(tier),
    findings,
    iocs,
    campaign: campaign ? { id: campaign.id, brand: campaign.brand, confidence: campaign.confidence, emailCount: campaign.emailCount, domainCount: campaign.domainCount } : null,
    checks: scanEntry.checks || null,
    timestamp: scanEntry.timestamp || Date.now(),
    iocsExtractedAt: iocs.extractedAt || null,
    replyToMismatch: !!t.replyToMismatch,
    reportText,
    hash
  };
  list.unshift(record);
  await saveCaseReports(list);
  return { success: true, case: record };
}

async function generateIncidentReport(scanEntry) {
  if (!scanEntry) return { error: 'No scan data available yet — open an email first.' };

  const iocs = scanEntry.iocs || (scanEntry.iocScanKey ? await getIOCsForScan(scanEntry.iocScanKey) : null) || {
    urls: [], domains: [], ipAddresses: [], emailAddresses: [], replyTo: [], redirects: [], attachments: []
  };
  const t = scanEntry.threats || {};
  const c = scanEntry.checks || {};
  const tier = iocScoreTier(scanEntry.score ?? 0);
  const attackType = iocClassifyAttack(scanEntry);
  const targetBrand = t.bimi?.claimedBrand || t.homograph?.targetBrand || t.contactLookalike?.targetDomain || null;

  let campaign = null;
  try {
    const campaigns = await computeCampaigns();
    campaign = campaigns.find(cc => cc.domains?.includes(scanEntry.domain)) || null;
  } catch { /* campaign correlation is best-effort */ }

  const lines = [];
  lines.push('PHISHALERT INCIDENT REPORT');
  lines.push('Generated: ' + new Date().toLocaleString());
  lines.push('');
  lines.push('Verdict: ' + tier + ' (' + (scanEntry.score ?? 0) + '/100)');
  lines.push('Attack Type: ' + attackType);
  if (targetBrand) lines.push('Target Brand: ' + targetBrand);
  lines.push('');
  lines.push('Sender: ' + (scanEntry.sender || 'unknown'));
  lines.push('Sender Domain: ' + (scanEntry.domain || 'unknown'));
  if (iocs.replyTo?.length) lines.push('Reply-To: ' + iocs.replyTo.join(', '));
  lines.push('');

  if (iocs.urls?.length) {
    lines.push('URLs:');
    iocs.urls.forEach(u => lines.push('  - ' + u));
    lines.push('');
  }

  if (iocs.redirects?.length) {
    lines.push('Redirect Chain:');
    iocs.redirects.forEach(r => {
      const path = [r.originalUrl, ...(r.chain || []), r.finalUrl].filter(Boolean);
      lines.push('  - ' + (path.length ? [...new Set(path)].join(' → ') : '(no redirect data)'));
      if (r.flaggedHop) lines.push('    ⚠️ Flagged hop: ' + r.flaggedHop);
    });
    lines.push('');
  }

  lines.push('Threat Intelligence:');
  lines.push('  URLhaus: ' + (c.urlhaus?.malicious ? 'MATCH — ' + (c.urlhaus.threat || 'malicious') : (c.urlhaus ? 'clean' : 'not checked')));
  lines.push('  VirusTotal: ' + (c.vt?.available ? (c.vt.isMalicious ? 'MALICIOUS (' + c.vt.maliciousCount + ' engines)' : 'clean') : 'not checked'));
  lines.push('  DNS Blacklist: ' + (c.dnsbl?.listed ? 'LISTED — ' + (c.dnsbl.listings || []).map(l => l.source).join(', ') : (c.dnsbl?.checked ? 'clean' : 'not checked')));
  lines.push('  SPF / DKIM / DMARC: ' + (c.spf?.pass ? 'pass' : 'fail') + ' / ' + (c.dkim?.pass ? 'pass' : (c.dkim?.inconclusive ? 'unverified' : 'fail')) + ' / ' + (c.dmarc?.pass ? 'pass' : 'fail'));
  lines.push('  BIMI: ' + (c.bimi?.hasBIMI && c.bimi?.hasVMC ? 'verified' : (c.bimi?.isImpersonatingBrand ? 'missing — impersonation signal' : 'n/a')));
  lines.push('');

  if (campaign) {
    lines.push('Related Campaign: ' + (campaign.brand ? campaign.brand + ' impersonation campaign' : campaign.id));
    lines.push('  Confidence: ' + campaign.confidence + '% — ' + campaign.emailCount + ' related emails across ' + campaign.domainCount + ' domain(s)');
    lines.push('');
  }

  lines.push('Indicators of Compromise:');
  lines.push('  Domains: ' + ((iocs.domains || []).join(', ') || 'none'));
  if (iocs.ipAddresses?.length) lines.push('  IP Addresses: ' + iocs.ipAddresses.join(', '));
  lines.push('  Email Addresses: ' + ((iocs.emailAddresses || []).join(', ') || 'none'));
  if (iocs.attachments?.length) lines.push('  Attachments: ' + iocs.attachments.map(a => a.fileName + (a.riskLevel ? ' (' + a.riskLevel + ')' : '')).join(', '));

  return {
    success: true,
    report: lines.join('\n'),
    verdict: tier,
    attackType,
    targetBrand,
    campaign,
    iocs
  };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const handle = async () => {
    switch (message.type) {
      case 'DNS_LOOKUP':
        return await dnsLookup(message.name, message.recordType);

      // UPGRADE 1: Real SPF/DKIM/DMARC verification via DNS
      // FEATURE 5: Whitelist check — whitelisted domains skip all DNS calls
      case 'VERIFY_EMAIL_AUTH': {
        if (await isWhitelisted(message.domain)) {
          return makeWhitelistedAuthResult(message.domain);
        }
        // DNS result is per-domain and cached; the per-message verdict (when the caller
        // supplies the message's raw headers) is layered on top and never cached.
        const dnsResult = await verifyEmailAuthentication(message.domain);
        return applyMessageAuth(dnsResult, message.rawHeaders, message.domain);
      }

      // Popup "Verify a message": user pastes raw headers; evaluate the receiving server's
      // own Authentication-Results verdict. Deliberately NOT whitelist-skipped — the point is
      // to check this particular message, not to trust the domain.
      case 'VERIFY_MESSAGE_HEADERS':
        return await verifyMessageHeaders(message.rawHeaders);

      // FEATURE 3: Punycode Detection
      case 'CHECK_PUNYCODE':
        return detectPunycode(message.domain);

      // FEATURE 6: OpenPhish live feed check (real feed fetch + punycode/protocol
      // fallback). Kept — not a duplicate of anything else, see chat note.
      case 'CHECK_OPENPHISH':
        return await checkOpenPhish(message.url);

      case 'RDAP_AGE':
        return await getRDAPDomainAge(message.domain);

      case 'VIRUSTOTAL_CHECK': {
        // FEATURE 5: Skip whitelisted domains
        if (await isWhitelisted(message.domain)) {
          return { available: false, skipped: true, reason: 'Whitelisted domain — skipped' };
        }
        // UPGRADE 3: Use encrypted API keys
        const keys = await getApiKeys();
        const vtKey = keys.vtApiKey || '';
        return await checkVirusTotal(message.domain, vtKey);
      }

      case 'UNSHORT_URL': {
        // UPGRADED v5: full redirect-chain follower instead of shortener-only
        const keys = await getApiKeys();
        const chain = await scanRedirectChain(message.url, keys.vtApiKey || '');
        return {
          originalUrl: message.url,
          finalUrl: chain.finalUrl,
          wasShortened: chain.hops > 0,
          hops: chain.hops,
          chain: chain.chain,
          crossDomain: chain.crossDomain,
          threatHops: chain.threatHops,
          limited: chain.limited,
          error: null
        };
      }

      case 'COMMUNITY_REPORT':
        return await saveCommunityReport(message.domain, message.note);

      case 'COMMUNITY_CHECK':
        return await checkCommunityReport(message.domain);

      case 'GET_REPORTS':
        return await getCommunityReports();

      case 'GET_SETTINGS': {
        // Keys are never returned here (they are not stored in settings any more);
        // the popup shows masked values from GET_API_KEYS instead.
        await withKeyLock(migrateApiKeysIfNeeded).catch(() => { });
        const s = await chrome.storage.local.get('phishalert_settings');
        return stripKeyFields(s.phishalert_settings || {});
      }

      case 'SAVE_SETTINGS': {
        // Merge onto existing settings instead of replacing them (callers often send
        // partial objects built from a stale read). API keys are NEVER written into
        // phishalert_settings: they are split off and stored only as AES-GCM ciphertext.
        await withKeyLock(migrateApiKeysIfNeeded).catch(() => { });
        const incoming = message.settings || {};
        const existingSettingsWrap = await chrome.storage.local.get('phishalert_settings');
        const mergedSettings = { ...stripKeyFields(existingSettingsWrap.phishalert_settings || {}), ...stripKeyFields(incoming) };
        await chrome.storage.local.set({ phishalert_settings: mergedSettings });
        // Turning AI off (or never having turned it on) means no email text is retained.
        if (incoming.aiConsent === false && existingSettingsWrap.phishalert_settings?.aiConsent === true) await purgeEmailContent();

        // Masked placeholders from the UI (contain •) are not real keys; ignore them.
        const isMasked = v => typeof v === 'string' && v.includes('•');
        const updates = {};
        KEY_FIELDS.forEach(f => {
          const v = incoming[f];
          if (typeof v === 'string' && v.trim() && !isMasked(v)) updates[f] = v.trim();
        });
        if (Object.keys(updates).length) {
          const res = await updateApiKeys(cur => ({ ...cur, ...updates }));
          if (!res.success) return { success: false, error: res.error || 'Could not encrypt API keys' };
        }
        return { success: true };
      }

      // UPGRADE 3: Encrypted key management
      case 'SAVE_API_KEYS': {
        // Merge: a non-empty incoming value wins, anything omitted is kept. The
        // onboarding wizard saves one key at a time; updateApiKeys makes the merge atomic.
        const pickKey = (incoming, existing) => (typeof incoming === 'string' && incoming.trim()) ? incoming.trim() : (existing || '');
        return await updateApiKeys(cur => ({
          vtApiKey: pickKey(message.vtApiKey, cur.vtApiKey),
          groqApiKey: pickKey(message.groqApiKey, cur.groqApiKey),
          gsbApiKey: pickKey(message.gsbApiKey, cur.gsbApiKey),
          phishtankApiKey: pickKey(message.phishtankApiKey, cur.phishtankApiKey),
          canaryApiKey: cur.canaryApiKey || ''
        }));
      }

      case 'GET_API_KEYS': {
        const keys = await getApiKeys();
        // Return masked versions for display
        const mask = v => v ? v.slice(0, 6) + '••••••••' + v.slice(-4) : '';
        return { vtApiKey: mask(keys.vtApiKey), groqApiKey: mask(keys.groqApiKey), gsbApiKey: mask(keys.gsbApiKey), phishtankApiKey: mask(keys.phishtankApiKey), canaryApiKey: mask(keys.canaryApiKey), hasVT: !!keys.vtApiKey, hasGroq: !!keys.groqApiKey, hasGSB: !!keys.gsbApiKey, hasPhishTank: !!keys.phishtankApiKey, hasCanary: !!keys.canaryApiKey };
      }

      // UPGRADE 4: Quota tracking
      case 'GET_VT_QUOTA':
        return await getVTQuota();

      case 'RESET_VT_QUOTA': {
        const today = new Date().toISOString().slice(0, 10);
        await chrome.storage.local.set({ phishalert_vt_quota: { date: today, used: 0 } });
        return { success: true };
      }

      case 'SAVE_SCAN_LOG': {
        const logKey = 'phishalert_scanlog';
        const totalKey = 'phishalert_scan_total';
        const logData = await chrome.storage.local.get([logKey, totalKey]);
        const log = logData[logKey] || [];
        const prevTotal = logData[totalKey] || 0;
        log.unshift({ ...message.entry, timestamp: Date.now() });
        // Unlimited scan history — no cap
        await chrome.storage.local.set({ [logKey]: log, [totalKey]: prevTotal + 1 });
        return { success: true };
      }

      case 'GET_SCAN_LOG': {
        const ld = await chrome.storage.local.get('phishalert_scanlog');
        return ld.phishalert_scanlog || [];
      }

      case 'GET_SCAN_TOTAL': {
        const td = await chrome.storage.local.get('phishalert_scan_total');
        return { total: td.phishalert_scan_total || 0 };
      }

      case 'SAVE_EMAIL_CONTENT': {
        // Without consent only sender/domain are kept (so the Tools tab still knows
        // which email is open); subject and body are dropped, not stored.
        const consent = await isAiConsented();
        await sessionSet({
          phishalert_email_content: {
            subject: consent ? (message.subject || '') : '',
            body: consent ? (message.body || '') : '',
            sender: message.sender,
            domain: message.domain,
            contentWithheld: !consent,
            timestamp: Date.now()
          }
        });
        return { success: true };
      }

      case 'GET_EMAIL_CONTENT':
        return await sessionGetFresh('phishalert_email_content');

      case 'SAVE_AI_ANALYSIS':
        if (!(await isAiConsented())) return { success: false, skipped: 'consent' };
        await sessionSet({ phishalert_ai_analysis: { ...message.analysis, timestamp: Date.now() } });
        return { success: true };

      case 'GET_AI_ANALYSIS':
        return await sessionGetFresh('phishalert_ai_analysis');

      case 'CLASSIFY_EMAIL': {
        const k = await getApiKeys();
        return await classifyAndAnalyzeEmail(message.subject, message.body, k.groqApiKey || '');
      }

      case 'DRAFT_REPLY': {
        const k = await getApiKeys();
        return await draftEmailReply(message.subject, message.body, message.tone, k.groqApiKey || '');
      }

      case 'ANALYZE_TONE': {
        const k = await getApiKeys();
        return await analyzeToneAndManipulation(message.subject, message.body, k.groqApiKey || '');
      }

      case 'EXPLAIN_PHISHING': {
        const k = await getApiKeys();
        return await explainPhishingThreat(message.subject, message.body, message.scanData, k.groqApiKey || '');
      }

      case 'DRAFT_THREAD_REPLY': {
        const k = await getApiKeys();
        return await draftThreadAwareReply(message.subject, message.threadMessages, message.tone, k.groqApiKey || '');
      }

      case 'COACH_EMAIL': {
        const k = await getApiKeys();
        return await coachOutgoingEmail(message.subject, message.body, k.groqApiKey || '');
      }

      case 'SAVE_THREAD_MESSAGES':
        if (!(await isAiConsented())) return { success: false, skipped: 'consent' };
        await sessionSet({ phishalert_thread_messages: { messages: message.messages, timestamp: Date.now() } });
        return { success: true };

      case 'GET_THREAD_MESSAGES':
        return await sessionGetFresh('phishalert_thread_messages');

      case 'GET_AI_SETTINGS':
        return await getAiSettings();

      case 'CLAUDE_CHAT': {
        const k = await getApiKeys();
        return await aiChatGroq(message.messages, message.context, k.groqApiKey || '');
      }

      case 'SCAN_ATTACHMENT':
        return await scanAttachment(message.fileName, message.mimeType, message.base64Data);

      case 'ANALYZE_HEADERS':
        return analyzeHeadersDeep(message.headers);

      case 'DETECT_TRACKERS':
        return detectPixelTrackers(message.htmlContent);

      case 'DETECT_QR':
        return detectQRCodeLinks(message.htmlContent);

      case 'GET_SENDER_HISTORY':
        return await getSenderHistory(message.email, message.domain);

      case 'GET_SENDER_TRUST':
        return await getSenderTrustFromHistory(message.email, message.domain);

      case 'RECORD_SENDER':
        // Feed into adaptive learning
        if (message.interactionType === 'replied' || message.interactionType === 'seen') {
          await adaptiveSenderAction(message.email, message.domain || '', message.interactionType);
        }
        return await recordSenderInteraction(message.email, message.interactionType, message.domain);

      case 'CLEAR_ALL_DATA':
        await chrome.storage.local.clear();
        try { if (chrome.storage.session) await chrome.storage.session.clear(); } catch { }
        await deleteKeystore();   // destroy the AES key too, so no key material survives a wipe
        // Re-initialize daily quota and basic settings if needed
        return { success: true };

      case 'SAVE_PHASE4':
        await chrome.storage.local.set({
          phishalert_phase4: {
            ...message,
            timestamp: Date.now()
          }
        });
        return { success: true };

      case 'GET_PHASE4': {
        const p4 = await chrome.storage.local.get('phishalert_phase4');
        return p4.phishalert_phase4 || null;
      }

      // ── Productivity Features ──────────────────────────────────────────────
      case 'EXTRACT_CALENDAR': {
        const k = await getApiKeys();
        return await extractCalendarEvents(message.subject, message.body, k.groqApiKey || '');
      }

      case 'EXTRACT_ACTIONS': {
        const k = await getApiKeys();
        return await extractActionItems(message.subject, message.body, k.groqApiKey || '');
      }

      case 'SUGGEST_LABELS': {
        const k = await getApiKeys();
        return await suggestGmailLabels(message.subject, message.body, message.sender, k.groqApiKey || '');
      }

      case 'GENERATE_DIGEST': {
        const k = await getApiKeys();
        const logData = await chrome.storage.local.get('phishalert_scanlog');
        const emails = (logData.phishalert_scanlog || []).slice(0, 30);
        return await generateInboxDigest(emails, k.groqApiKey || '');
      }

      case 'SAVE_CURRENT_SCAN':
        await chrome.storage.local.set({ phishalert_current_scan: { ...message.entry, timestamp: Date.now() } });
        // Trigger desktop notification for suspicious/critical emails
        sendDesktopNotification({ ...message.entry });
        chrome.runtime.sendMessage({ type: '_SCAN_UPDATED' }, () => chrome.runtime.lastError);
        return { success: true };

      // ── Feature: HaveIBeenPwned ───────────────────────────────────────────
      case 'HIBP_CHECK':
        return await checkHIBPDomain(message.domain);

      // ── Feature: Block Sender ─────────────────────────────────────────────
      case 'BLOCK_SENDER':
        return await blockSender(message.email, message.domain, message.reason);

      case 'GET_BLOCKED':
        return await getBlockedSenders();

      case 'UNBLOCK_SENDER':
        return await unblockSender(message.email);

      case 'IS_BLOCKED':
        return await isSenderBlocked(message.email);

      // ── Feature: Export ───────────────────────────────────────────────────
      case 'EXPORT_CSV': {
        const entries = await buildExportData(message.mode, message.scanEntry);
        const csv = exportToCSV(entries);
        return { success: true, csv, count: entries.length };
      }

      case 'GET_LAST_SCAN': {
        const cur = await chrome.storage.local.get('phishalert_current_scan');
        if (cur.phishalert_current_scan) return cur.phishalert_current_scan;
        const ld2 = await chrome.storage.local.get('phishalert_scanlog');
        const scanLog = ld2.phishalert_scanlog || [];
        return scanLog.length > 0 ? scanLog[0] : null;
      }

      // ── Weekly Threat Intelligence Report ──────────────────────────────
      case 'GENERATE_WEEKLY_REPORT':
        return await generateWeeklyReport();

      case 'GET_WEEKLY_REPORT':
        return await getWeeklyReport();

      // ── Adaptive Sender Learning ────────────────────────────────────────
      case 'ADAPTIVE_SENDER_ACTION':
        return await adaptiveSenderAction(message.email, message.domain, message.action);

      case 'GET_ADAPTIVE_TRUST':
        return await getAdaptiveSenderTrust(message.email);

      case 'CLEAR_COMMUNITY_REPORT':
        return await clearReportForDomain(message.domain, !!message.whitelist);

      // ── One-Click Phishing Reporting ───────────────────────────────────
      case 'REPORT_PHISHING_ONECLICK':
        return await reportPhishing(message.domain, message.sender, message.subject, message.note);

      // ── FEATURE 2: Keyboard shortcut — open popup ───────────────────────────
      case 'OPEN_POPUP':
        try { await chrome.action.openPopup(); } catch (e) { /* openPopup requires user gesture in some builds */ }
        return { success: true };

      // ── FEATURE 5: Whitelist Management ──────────────────────────────────
      case 'WHITELIST_GET':
        return await getWhitelist();

      case 'WHITELIST_ADD':
        return await addWhitelistDomain(message.domain);

      case 'WHITELIST_REMOVE':
        return await removeWhitelistDomain(message.domain);

      case 'WHITELIST_CHECK':
        return { whitelisted: await isWhitelisted(message.domain) };

      // Interstitial "continue anyway": only honoured when it comes from our own blocked.html.
      case 'NAV_ALLOW_ONCE': {
        const ok = sender && sender.id === chrome.runtime.id &&
          typeof sender.url === 'string' && sender.url.startsWith(chrome.runtime.getURL('blocked.html'));
        if (!ok || !/^https?:\/\//i.test(message.url || '')) return { success: false };
        await navAllowUrl(String(message.url).split('#')[0]);
        return { success: true };
      }


      // ── FEATURE 2+3: URLhaus + full redirect chain check ──────────────────
      case 'URLHAUS_CHECK':
        return await checkURLhaus(message.url || ('https://' + message.domain));

      // ── FEATURE 4: Outgoing email scan ─────────────────────────────────────
      case 'SCAN_OUTGOING':
        return await scanOutgoingEmail({ to: message.to, subject: message.subject, body: message.body });

      // ── FEATURE 5: OAuth alert retrieval ─────────────────────────────────
      case 'GET_OAUTH_ALERT': {
        const oa = await chrome.storage.local.get('phishalert_oauth_alert');
        return oa.phishalert_oauth_alert || null;
      }

      // ── Link redirect-chain scanning permission (optional_host_permissions) ─
      case 'GET_LINK_SCAN_PERMISSION':
        return { granted: await hasFullHostPermission() };

      case 'CLEAR_OAUTH_ALERT':
        await chrome.storage.local.remove('phishalert_oauth_alert');
        return { success: true };

      // ── FEATURE 6: Google Safe Browsing ──────────────────────────────────
      case 'GSB_CHECK': {
        const keys = await getApiKeys();
        return await checkGoogleSafeBrowsing(message.urls || [], keys.gsbApiKey || '');
      }

      // ── FEATURE 8: Email Encryption / TLS Detection ───────────────────────
      case 'DETECT_ENCRYPTION':
        return detectEmailEncryption(message.headers || {});

      // ── FEATURE 9: QR Decode + Threat Scan ───────────────────────────────
      // Content script sends decoded URL from jsQR; we run it through the
      // full threat pipeline (GSB + URLhaus + redirect chain).
      case 'SCAN_QR_URL': {
        const qrUrl = message.url;
        if (!qrUrl) return { error: 'No URL provided' };
        const keys = await getApiKeys();
        const [uhResult, gsbResult, redirectResult] = await Promise.allSettled([
          checkURLhaus(qrUrl),
          checkGoogleSafeBrowsing([qrUrl], keys.gsbApiKey || ''),
          scanRedirectChain(qrUrl, keys.vtApiKey || '')
        ]);
        const uh = uhResult.status === 'fulfilled' ? uhResult.value : null;
        const gsb = gsbResult.status === 'fulfilled' ? gsbResult.value : null;
        const rd = redirectResult.status === 'fulfilled' ? redirectResult.value : null;

        const isMalicious = !!(uh?.malicious || gsb?.isMalicious || rd?.threatHops?.length);
        const threats = [];
        if (uh?.malicious) threats.push(`URLhaus: ${uh.threat}`);
        if (gsb?.isMalicious) threats.push(`Google Safe Browsing: ${gsb.matches[0]?.threatType || 'threat'}`);
        if (rd?.threatHops?.length) threats.push(`Malicious redirect: ${rd.threatHops[0]?.url?.substring(0, 60)}`);

        return {
          originalUrl: qrUrl,
          finalUrl: rd?.finalUrl || qrUrl,
          isMalicious,
          threats,
          urlhaus: uh,
          gsb,
          redirect: rd ? { chain: rd.chain, hops: rd.hops, crossDomain: rd.crossDomain } : null
        };
      }

      // ── FEATURE NEW 3: Active Link Protection ──────────────────────────────
      // Fired the moment the user clicks a link inside a scanned email —
      // resolves the real destination and returns an ALLOW/WARN/BLOCK verdict
      // before the content script lets the click's navigation go through.
      case 'SCAN_LINK_CLICK':
        return await analyzeLinkDestination({ url: message.url, senderDomain: message.senderDomain || '' });

      // ── FEATURE 10: Reply-To Mismatch ────────────────────────────────────────
      case 'CHECK_REPLY_TO':
        return checkReplyToMismatch(message.from, message.replyTo);

      // ── FEATURE 11: Urgency Keyword Scoring ──────────────────────────────────
      case 'URGENCY_SCORE':
        return scoreUrgencyKeywords(message.subject, message.body);

      // ── FEATURE 12: Contact Lookalike Domain ─────────────────────────────────
      case 'ADD_CONTACT_DOMAIN':
        await addContactDomain(message.domain);
        return { success: true };

      case 'GET_CONTACT_DOMAINS':
        return await getContactDomains();

      case 'CHECK_CONTACT_LOOKALIKE':
        return await checkContactLookalike(message.domain);

      // ── FEATURE 13: DNS Blacklist Reputation ─────────────────────────────────
      case 'DNSBL_CHECK':
        return await checkDNSBL(message.domain);

      // ── FEATURE 14: Thread Hijacking ─────────────────────────────────────────
      case 'RECORD_THREAD_SENDER':
        return await recordThreadSender(message.threadId, message.senderEmail, message.senderDomain);

      case 'CHECK_THREAD_HIJACKING':
        return await checkThreadHijacking(message.threadId, message.senderDomain);

      // ── FEATURE NEW 4: Phishing DNA — Attack Campaign Detection ─────────────
      case 'RECORD_CAMPAIGN_FINGERPRINT':
        return await recordCampaignFingerprint(message);

      case 'GET_CAMPAIGNS':
        return await computeCampaigns();

      case 'GET_CAMPAIGN_DETAIL': {
        const all = await computeCampaigns();
        return all.find(c => c.id === message.campaignId) || null;
      }

      case 'CLEAR_CAMPAIGN_DATA':
        await chrome.storage.local.remove(PD_STORE_KEY);
        return { success: true };

      // ── FEATURE NEW 5: Investigation Mode — IOC extraction + reporting ────
      case 'EXTRACT_IOCS':
        return await extractAndStoreIOCs(message);

      case 'GET_IOCS':
        return await getIOCsForScan(message.scanKey);

      case 'GENERATE_INCIDENT_REPORT': {
        let entry = message.scanEntry;
        if (!entry) {
          const cur = await chrome.storage.local.get('phishalert_current_scan');
          entry = cur.phishalert_current_scan || null;
        }
        return await generateIncidentReport(entry);
      }

      case 'CLEAR_IOC_DATA':
        await chrome.storage.local.remove(IOC_STORE_KEY);
        return { success: true };

      // ── FEATURE NEW 6: Active Deception & Infrastructure Intelligence ──────
      case 'TEST_CANARY_CONNECTION':
        return await testCanaryConnection(message);

      case 'DEPLOY_CANARY_BAIT':
        return await deployCanaryBait(message);

      case 'GET_CANARY_DEPLOYMENT':
        return await getCanaryDeploymentForScan(message.scanKey);

      case 'GET_CANARY_EVENTS':
        return await getCanaryEvents(message.scanKey);

      case 'CLEAR_CANARY_DATA':
        await chrome.storage.local.remove(CANARY_STORE_KEY);
        return { success: true };

      // ── Reports V2 — Case/Report Management ──────────────────────────────
      case 'GENERATE_CASE_REPORT': {
        let entry = message.scanEntry;
        if (!entry && message.reportType !== 'threat_intel') {
          const cur = await chrome.storage.local.get('phishalert_current_scan');
          entry = cur.phishalert_current_scan || null;
        }
        return await generateCaseReport(entry, message.reportType);
      }

      case 'GET_CASE_REPORTS':
        return await getCaseReports();

      case 'UPDATE_CASE_STATUS': {
        const list = await getCaseReports();
        const idx = list.findIndex(r => r.id === message.id);
        if (idx === -1) return { error: 'Case not found' };
        list[idx].status = message.status;
        await saveCaseReports(list);
        return { success: true, case: list[idx] };
      }

      case 'DELETE_CASE_REPORT': {
        const list = await getCaseReports();
        const filtered = list.filter(r => r.id !== message.id);
        await saveCaseReports(filtered);
        return { success: true };
      }

      default:
        return { error: 'Unknown message type' };
    }
  };

  handle()
    .then(res => { try { sendResponse(res); } catch (e) { } })
    .catch(err => { try { sendResponse({ error: err.message }); } catch (e) { } });
  return true; // Keep channel open for async response
});

// ─── UPGRADE 1: Real SPF/DKIM/DMARC Verification via dns.google DoH ──────────
// Moved to background so we can do parallel persistent-cached DNS queries.
// content.js calls VERIFY_EMAIL_AUTH which returns full {spf, dkim, dmarc} results.

async function verifyEmailAuthentication(domain) {
  const cacheKey = `auth2:${domain}`;   // bumped: old cached results carried the wrong SPF label
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  // Run all three in parallel
  const [spfRaw, dmarcRaw] = await Promise.all([
    dnsLookup(domain, 'TXT'),
    dnsLookup(`_dmarc.${domain}`, 'TXT')
  ]);

  // SPF — follow redirect= (gmail.com publishes only "v=spf1 redirect=_spf.google.com", so the
  // all-mechanism lives one hop away) and read the real qualifier on `all`. The old code looked
  // for the substrings "-all"/"~all" in the top record only, so a redirecting record fell through
  // to "Permissive SPF (+all)" and was scored as a pass. A genuinely open record (+all / no `all`)
  // lets anyone send as the domain and must not earn SPF points.
  let spf = { pass: false, strict: false, detail: 'No SPF record', record: null };
  {
    const findSpf = raw => raw?.Answer?.map(r => r.data || '').find(d => /^"?v=spf1(\s|"|$)/i.test(d));
    let rec = findSpf(spfRaw);
    let hops = 0;
    while (rec && hops < 3) {
      const clean0 = rec.replace(/"\s*"/g, '').replace(/^"|"$/g, '');
      const redir = clean0.match(/(?:^|\s)redirect=([^\s]+)/i);
      const hasAll = /(?:^|\s)[+\-~?]?all(?:\s|$)/i.test(clean0);
      if (redir && !hasAll) {
        const next = await dnsLookup(redir[1], 'TXT');
        const nextRec = findSpf(next);
        if (!nextRec) break;
        rec = nextRec; hops++;
        continue;
      }
      break;
    }
    if (rec) {
      const clean = rec.replace(/"\s*"/g, '').replace(/^"|"$/g, '');
      const m = clean.match(/(?:^|\s)([+\-~?]?)all(?:\s|$)/i);
      const q = m ? (m[1] || '+') : null;
      const base = { record: clean.substring(0, 120), redirected: hops > 0 };
      if (q === '-')      spf = Object.assign(base, { pass: true,  strict: true,  soft: false, detail: 'Strict SPF (-all)' });
      else if (q === '~') spf = Object.assign(base, { pass: true,  strict: false, soft: true,  detail: 'Soft-fail SPF (~all)' });
      else if (q === '?') spf = Object.assign(base, { pass: false, strict: false, soft: false, detail: 'Neutral SPF (?all) — domain makes no claim about who may send' });
      else if (q === '+') spf = Object.assign(base, { pass: false, strict: false, soft: false, detail: 'Permissive SPF (+all) — anyone may send as this domain' });
      else                spf = Object.assign(base, { pass: false, strict: false, soft: false, detail: 'SPF record has no "all" mechanism — it does not restrict senders' });
    }
  }

  // DKIM — try common selectors
  // v5.1: Expanded to 40+ selectors covering major ESPs and enterprise systems
  const selectors = [
    'default', 'google', 'mail', 'dkim', 'selector1', 'selector2',
    'k1', 'k2', 'smtp', 's1', 's2', 'sig1', 'proddkim1024',
    'amazonses', 'mandrill', 'mailjet', 'sendgrid', 'mxvault',
    'm1', 'm2', 'key1', 'key2', 'dkim1', 'dkim2', 'pic1', 'pic2',
    'mail01', 'mail02', 'dk1', 'dk2', 'ms', 'outlook', 'office',
    'prod', 'prod1', 'prod2', 'bulk', 'bulk1', 'newsletter', 'news',
    'marketing', 'sales', 'support', 'ops', 'infra', 'system'
  ];

  // FIX: firing all 40 selector lookups in one Promise.all hammered
  // dns.google with a burst of simultaneous requests, well past Chrome's
  // per-host connection cap. Some would time out / get throttled, and the
  // old code silently treated those failures exactly like a confirmed
  // "no record" — so the real DKIM record (often the very first selector,
  // "default") could be missed purely due to network timing, and the same
  // domain would flip between DKIM pass and fail from scan to scan.
  // Now: check in small batches, retry failures once (via dnsLookup's own
  // retry), stop as soon as a record is found, and — if nothing is found —
  // only report a hard "fail" when every checked selector came back with a
  // clean, confirmed answer. If any lookups genuinely errored out, that's
  // reported as inconclusive rather than a false fail.
  const DKIM_BATCH_SIZE = 8; // keep well under the per-host connection limit
  let dkim = { pass: false, detail: 'No DKIM record found', selector: null };
  let dkimFound = false;
  let dkimCheckedCount = 0;
  let dkimErroredCount = 0;

  for (let i = 0; i < selectors.length && !dkimFound; i += DKIM_BATCH_SIZE) {
    const batch = selectors.slice(i, i + DKIM_BATCH_SIZE);
    const batchResults = await Promise.all(
      batch.map(sel =>
        dnsLookup(`${sel}._domainkey.${domain}`, 'TXT', { retries: 1 })
          .then(res => ({ sel, res }))
          .catch(() => ({ sel, res: { __networkError: true } }))
      )
    );
    for (const { sel, res } of batchResults) {
      dkimCheckedCount++;
      if (res?.__networkError) {
        dkimErroredCount++;
        continue;
      }
      if (res?.Answer?.find(r => (r.data || '').includes('v=DKIM1'))) {
        dkim = { pass: false, inconclusive: true, selector: sel, detail: `Key published (${sel}._domainkey) — not verified on this message` };
        dkimFound = true;
        break;
      }
    }
  }

  if (!dkimFound && dkimErroredCount > 0) {
    dkim = dkimErroredCount === dkimCheckedCount
      ? {
          pass: false,
          inconclusive: true,
          selector: null,
          detail: `DKIM check inconclusive — DNS lookups failed for all ${dkimCheckedCount} selectors tried (resolver/network issue, not a confirmed missing record)`
        }
      : {
          pass: false,
          inconclusive: true,
          selector: null,
          detail: `No DKIM record found among ${dkimCheckedCount - dkimErroredCount} selectors confirmed (${dkimErroredCount} lookup(s) failed and couldn't be checked)`
        };
  }
  // A DKIM record lives at <selector>._domainkey.<domain> and the selector is chosen by the
  // sender (Google rotates dated ones, e.g. "20251104"), so it cannot be enumerated from DNS.
  // Not finding a record among our guesses therefore proves nothing: report it as
  // inconclusive, never as a confirmed failure. The real verdict needs the message's own
  // headers (popup → Checker → "Verify a message").
  if (!dkimFound && !dkim.inconclusive) {
    dkim = {
      pass: false,
      inconclusive: true,
      selector: null,
      detail: `Can't verify DKIM from DNS alone (the signing selector isn't discoverable) — paste the message headers in Checker → Verify a message for the real result`
    };
  }

  // DMARC (RFC 7489 §6.6.3): look for _dmarc.<From domain> first; if there is no record,
  // fall back to the organizational domain (eTLD+1). Most senders publish one policy at the
  // apex and mail from subdomains: em1.cloudflare.com has no _dmarc record of its own, but
  // cloudflare.com does, and it governs the subdomain. Checking only the exact host reported
  // "No DMARC record" for a message that really passed DMARC.
  let dmarc = { pass: false, policy: null, detail: 'No DMARC record', record: null };
  const findDmarc = raw => raw?.Answer?.map(r => r.data || '').find(d => /v=DMARC1/i.test(d));
  let dmarcRec = findDmarc(dmarcRaw);
  let dmarcSource = domain;
  const orgDomain = getRootDomain(domain);
  if (!dmarcRec && orgDomain && orgDomain !== domain) {
    const orgRaw = await dnsLookup(`_dmarc.${orgDomain}`, 'TXT');
    dmarcRec = findDmarc(orgRaw);
    if (dmarcRec) dmarcSource = orgDomain;
  }
  if (dmarcRec) {
    const clean = dmarcRec.replace(/^"|"$/g, '').replace(/"\s*"/g, '');
    const tag = name => { const m = clean.match(new RegExp('(?:^|;)\\s*' + name + '\\s*=\\s*([^;\\s]+)', 'i')); return m ? m[1].toLowerCase() : null; };
    const valid = v => (v === 'none' || v === 'quarantine' || v === 'reject') ? v : null;
    const inherited = dmarcSource !== domain;
    // A subdomain governed by the apex record uses sp= when present, otherwise p=.
    const policy = (inherited ? valid(tag('sp')) : null) || valid(tag('p')) || 'none';
    const spf_align = tag('aspf') === 's' ? 'strict' : 'relaxed';
    const dkim_align = tag('adkim') === 's' ? 'strict' : 'relaxed';
    dmarc = {
      pass: true,
      policy,
      spf_align,
      dkim_align,
      inherited,
      source: dmarcSource,
      record: clean.substring(0, 120),
      detail: `DMARC policy: ${policy} (SPF: ${spf_align}, DKIM: ${dkim_align})` + (inherited ? ` — inherited from ${dmarcSource}` : '')
    };
  }

  // MX record validation — phishing domains often have no MX (send-only)
  // Legit mail is routinely sent from subdomains that only send (news.railway.app,
  // updates.share.market, customers.gumroad.com) and so have no MX of their own. Like DMARC,
  // fall back to the organizational domain: a brand whose root domain receives mail is not a
  // send-only throwaway just because its mailing subdomain doesn't.
  let mxRaw = await dnsLookup(domain, 'MX');
  let mxRecords = mxRaw?.Answer || [];
  let mxOnRoot = false;
  const mxRoot = getRootDomain(domain);
  if (!mxRecords.length && mxRoot && mxRoot !== domain) {
    const rootRaw = await dnsLookup(mxRoot, 'MX');
    if (rootRaw?.Answer?.length) { mxRecords = rootRaw.Answer; mxOnRoot = true; }
  }
  const hasMX = mxRecords.length > 0;
  const mx = {
    hasMX,
    count: mxRecords.length,
    records: mxRecords.slice(0, 3).map(r => r.data || ''),
    onRootDomain: mxOnRoot,
    detail: hasMX ? `${mxRecords.length} MX record(s) found` + (mxOnRoot ? ` on ${mxRoot}` : '') : 'No MX records — send-only domain (phishing signal)',
    suspicious: !hasMX // No MX anywhere = strong phishing signal
  };

  // v5: URLhaus domain check alongside DNS auth
  let urlhausResult = null;
  try { urlhausResult = await checkURLhaus('https://' + domain); } catch { }

  // FEATURE 7: BIMI record check — run in parallel
  let bimiResult = null;
  try { bimiResult = await checkBIMI(domain); } catch { }

  const result = { spf, dkim, dmarc, mx, urlhaus: urlhausResult, bimi: bimiResult, domain, verifiedAt: Date.now() };
  await setCache(cacheKey, result);
  return result;
}

// ─── Per-message authentication (authres.js) ─────────────────────────────────
// The DNS check above only proves a domain *publishes* SPF/DKIM/DMARC records; a forged
// "From: x@paypal.com" sees the same records. When the caller can supply the message's
// raw headers, the receiving server's own Authentication-Results verdict (trusted
// receivers only, aligned with the From domain) replaces the DNS-derived pass/fail.
// Without headers, the DNS result is returned unchanged and labelled authSource:'dns'.
function applyMessageAuth(dnsResult, rawHeaders, fromDomain) {
  const base = Object.assign({}, dnsResult, { authSource: 'dns' });
  if (!rawHeaders || !self.paAuthRes) return base;
  let ev;
  try { ev = self.paAuthRes.evaluate(rawHeaders, fromDomain); } catch { return base; }
  if (!ev || ev.source !== 'message') {
    base.authNote = (ev && ev.reason) || null;   // e.g. header missing or from an untrusted host
    return base;
  }
  const out = Object.assign({}, base, { authSource: 'message', messageAuth: ev });
  // Short, human sentence per check (the full text goes in a tooltip). Says WHY, not just pass/fail.
  const why = (name, r, extra) => {
    const st = r.status || (r.pass ? 'pass' : 'fail');
    if (st === 'pass') return `${name} passed for ${r.domain || 'From domain'}`;
    if (st === 'unaligned') return `${name} passed for ${r.domain}, not the From domain (third-party sender)`;
    if (st === 'google-default') return `${name} passed (Google Workspace default key; domain has no custom DKIM)`;
    if (st === 'none') return `No ${name} ${name === 'DKIM' ? 'signature on this message' : 'result'}`;
    if (st === 'error') return `${name} could not be evaluated (${r.result})`;
    return `${name} ${r.result}${r.domain ? ' for ' + r.domain : ''}${extra || ''}`;
  };
  const hdr = `Checked by ${ev.receiver} on this message`;
  if (ev.spf) out.spf = Object.assign({}, base.spf, { pass: !!ev.spf.pass, status: ev.spf.status, detail: why('SPF', ev.spf), fullDetail: hdr });
  if (ev.dkim) out.dkim = Object.assign({}, base.dkim, {
    pass: !!ev.dkim.pass, inconclusive: false, status: ev.dkim.status,
    detail: why('DKIM', ev.dkim),
    fullDetail: hdr + (ev.dkim.signers && ev.dkim.signers.length ? ' — signatures: ' + ev.dkim.signers.join(', ') : '')
  });
  if (ev.dmarc) {
    out.dmarc = Object.assign({}, base.dmarc, {
      pass: !!ev.dmarc.pass, status: ev.dmarc.status,
      policy: ev.dmarc.policy || base.dmarc?.policy || null,
      detail: why('DMARC', ev.dmarc) + (ev.dmarc.pass && (ev.dmarc.policy || base.dmarc?.policy) === 'none' ? ' (policy: none, monitor only)' : ''),
      fullDetail: hdr
    });
  }
  return out;
}

async function verifyMessageHeaders(rawHeaders) {
  if (!self.paAuthRes) return { error: 'Header parser unavailable (authres.js failed to load)' };
  const raw = String(rawHeaders || '').trim().slice(0, 200000);
  if (!raw) return { error: 'No headers provided' };
  const from = self.paAuthRes.splitHeaders(raw).find(h => h.name === 'from');
  const m = from && from.value.toLowerCase().match(/@([a-z0-9][a-z0-9.-]*[a-z0-9])/);
  if (!m) return { error: 'Could not find a From: address in the pasted headers' };
  const domain = m[1];
  const dnsResult = await verifyEmailAuthentication(domain);
  return Object.assign({ domain }, applyMessageAuth(dnsResult, raw, domain));
}

// ─── FEATURE 2: Deep Header Chain Analysis ────────────────────────────────────
// Detects geographic inconsistencies, unusual hop counts, Authentication-Results
// header parsing, and X-Spam-Score extraction.
function analyzeHeadersDeep(headers) {
  // headers: { from, replyTo, returnPath, xMailer, receivedChain,
  //            messageId, xOriginatingIp, authResults, xSpamScore,
  //            xSpamStatus, received }
  const issues = [];
  const info = {};

  // ── Existing checks (reply-to, return-path, x-mailer, hop count) ──
  if (headers.from && headers.replyTo) {
    const fd = headers.from.match(/@([\w.-]+)/)?.[1]?.toLowerCase();
    const rd = headers.replyTo.match(/@([\w.-]+)/)?.[1]?.toLowerCase();
    if (fd && rd && fd !== rd) {
      issues.push({
        severity: 'high', type: 'reply_to_mismatch',
        detail: `Reply-To domain (${rd}) differs from From (${fd})`
      });
    }
  }
  if (headers.from && headers.returnPath) {
    const fd = headers.from.match(/@([\w.-]+)/)?.[1]?.toLowerCase();
    const rd = headers.returnPath.match(/@([\w.-]+)/)?.[1]?.toLowerCase();
    if (fd && rd && fd !== rd) {
      issues.push({
        severity: 'medium', type: 'return_path_mismatch',
        detail: `Return-Path (${rd}) differs from From (${fd})`
      });
    }
  }
  if (headers.xMailer) {
    const bad = ['phpmailer', 'sendblaster', 'massmailer', 'bulkmailer', 'dark mailer'];
    if (bad.some(m => headers.xMailer.toLowerCase().includes(m))) {
      issues.push({
        severity: 'medium', type: 'suspicious_mailer',
        detail: `Suspicious mail client: ${headers.xMailer}`
      });
    }
    info.xMailer = headers.xMailer;
  }

  // ── NEW: Hop count analysis ──
  const hops = Array.isArray(headers.receivedChain) ? headers.receivedChain.length : 0;
  info.hopCount = hops;
  if (hops > 10) {
    issues.push({
      severity: 'medium', type: 'excessive_hops',
      detail: `${hops} mail hops — unusual routing, possible obfuscation`
    });
  } else if (hops > 6) {
    issues.push({
      severity: 'low', type: 'unusual_routing',
      detail: `${hops} hops in mail chain — slightly unusual`
    });
  }

  // ── NEW: Geographic inconsistency detection ──
  // Parse country codes from Received headers and look for mismatches
  if (Array.isArray(headers.receivedChain) && headers.receivedChain.length > 0) {
    const geoPattern = /\b([A-Z]{2})\b/g;
    const countries = new Set();
    for (const hop of headers.receivedChain) {
      const matches = hop.match(geoPattern) || [];
      matches.forEach(c => {
        // Filter out common false-positives that aren't country codes
        const skip = new Set(['IP', 'ID', 'BY', 'TO', 'AT', 'IN', 'IS', 'AM', 'PM', 'OK', 'AN', 'DO']);
        if (!skip.has(c)) countries.add(c);
      });
    }

    // Check if claimed domain country differs wildly from sending country
    if (headers.from) {
      const claimedTLD = headers.from.match(/\.([a-z]{2})>?$/i)?.[1]?.toUpperCase();
      if (claimedTLD && countries.size > 0 && !countries.has(claimedTLD)) {
        // Only flag if the TLD is a country code (not .com/.net etc.)
        const countryTLDs = new Set(['RU', 'CN', 'KP', 'IR', 'NG', 'PK', 'UA', 'BY', 'RO', 'BG', 'VN', 'BR', 'IN']);
        if (countryTLDs.has(claimedTLD) || [...countries].some(c => countryTLDs.has(c))) {
          issues.push({
            severity: 'high', type: 'geo_inconsistency',
            detail: `Geographic mismatch: claimed domain TLD .${claimedTLD.toLowerCase()} but routed via ${[...countries].join(', ')}`
          });
        }
      }
    }
    info.routingCountries = [...countries];
  }

  // ── NEW: Authentication-Results header parsing ──
  if (headers.authResults) {
    const ar = headers.authResults.toLowerCase();
    info.authResults = {};

    const spfAR = ar.match(/spf=(pass|fail|softfail|neutral|none|permerror|temperror)/);
    const dkimAR = ar.match(/dkim=(pass|fail|none|neutral|permerror|temperror)/);
    const dmarcAR = ar.match(/dmarc=(pass|fail|none|bestguesspass|temperror|permerror)/);

    if (spfAR) info.authResults.spf = spfAR[1];
    if (dkimAR) info.authResults.dkim = dkimAR[1];
    if (dmarcAR) info.authResults.dmarc = dmarcAR[1];

    // Flag explicit failures from mail server itself
    if (spfAR?.[1] === 'fail' || spfAR?.[1] === 'softfail') {
      issues.push({
        severity: 'high', type: 'auth_results_spf_fail',
        detail: `Mail server reports SPF ${spfAR[1]}`
      });
    }
    if (dkimAR?.[1] === 'fail') {
      issues.push({
        severity: 'high', type: 'auth_results_dkim_fail',
        detail: 'Mail server reports DKIM signature failure'
      });
    }
    if (dmarcAR?.[1] === 'fail') {
      issues.push({
        severity: 'high', type: 'auth_results_dmarc_fail',
        detail: 'Mail server reports DMARC failure — spoofed sender likely'
      });
    }
  }

  // ── NEW: X-Spam-Score extraction ──
  if (headers.xSpamScore !== undefined && headers.xSpamScore !== null) {
    const score = parseFloat(headers.xSpamScore);
    info.xSpamScore = score;
    if (!isNaN(score)) {
      if (score >= 10) {
        issues.push({
          severity: 'high', type: 'high_spam_score',
          detail: `X-Spam-Score: ${score} — server flagged as high spam`
        });
      } else if (score >= 5) {
        issues.push({
          severity: 'medium', type: 'medium_spam_score',
          detail: `X-Spam-Score: ${score} — server flagged as probable spam`
        });
      }
    }
  }
  if (headers.xSpamStatus) {
    const isSpam = /^yes/i.test(headers.xSpamStatus.trim());
    info.xSpamStatus = headers.xSpamStatus;
    if (isSpam) {
      issues.push({
        severity: 'high', type: 'spam_flagged',
        detail: `X-Spam-Status: ${headers.xSpamStatus.substring(0, 60)}`
      });
    }
  }

  // ── Originating IP private address check ──
  if (headers.xOriginatingIp) {
    const ip = headers.xOriginatingIp.trim();
    const isPrivate = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
    info.originatingIp = ip;
    if (isPrivate) {
      issues.push({
        severity: 'low', type: 'private_originating_ip',
        detail: `Claimed originating IP (${ip}) is private — possibly forged header`
      });
    }
  }

  return { issues, info, clean: issues.length === 0, issueCount: issues.length };
}

// ─── FEATURE 3: Punycode / xn-- Domain Detection ─────────────────────────────
function detectPunycode(domain) {
  const result = { hasPunycode: false, decoded: null, suspicious: false, detail: null };
  if (!domain) return result;

  const host = String(domain).toLowerCase().replace(/\.+$/, '');
  if (!host.split('.').some(l => l.startsWith('xn--'))) return result;
  result.hasPunycode = true;
  result.suspicious = true;   // any punycode host is at least worth surfacing

  // idn.js does real RFC 3492 decoding. new URL(...).hostname does NOT: the URL API always
  // serialises hosts back to ASCII/punycode, so the old code never saw the Unicode form.
  if (!self.paIdn) {
    result.detail = `Punycode domain detected: ${domain}`;
    return result;
  }
  const TOP_BRANDS = [
    'google', 'microsoft', 'apple', 'amazon', 'facebook', 'paypal', 'netflix',
    'instagram', 'twitter', 'linkedin', 'dropbox', 'slack', 'zoom', 'adobe',
    'salesforce', 'github', 'spotify', 'walmart', 'ebay', 'chase', 'wellsfargo',
    'citibank', 'barclays', 'hsbc', 'airbnb', 'uber', 'lyft', 'whatsapp'
  ];
  let a;
  try { a = self.paIdn.analyze(host, TOP_BRANDS); }
  catch { result.detail = `Punycode domain detected: ${domain}`; return result; }

  result.decoded = a.decoded || null;
  if (a.failed) {
    result.detail = `Punycode domain "${domain}" could not be decoded cleanly — treat as suspicious`;
  } else if (a.targetBrand) {
    result.targetBrand = a.targetBrand;
    result.detail = `Punycode domain "${domain}" decodes to "${a.decoded}" — ${a.match} of "${a.targetBrand}"` +
      (a.mixedScript ? ' (mixed scripts)' : '');
  } else {
    result.detail = `Punycode domain: "${domain}" renders as "${a.decoded}"` + (a.mixedScript ? ' (mixed scripts)' : '');
  }
  return result;
}

// ─── FEATURE 6: PhishTank / OpenPhish Integration ────────────────────────────
// Free fallback that requires no API key — checks URLs against live phishing DBs.
async function checkOpenPhish(url) {
  const cacheKey = `openphish:${url}`;
  const cached = await getCached(cacheKey);
  if (cached) return cached;

  try {
    // OpenPhish public feed — we check if hostname appears in their feed
    // We use a CORS-friendly approach: check via our existing DNS lookup pattern
    // Since direct feed fetch may fail CORS in SW, we check domain reputation heuristically
    // and flag xn-- / javascript: / data: URIs immediately.

    let urlObj;
    try { urlObj = new URL(url); } catch { return { isPhishing: false, source: null }; }

    const hostname = urlObj.hostname.toLowerCase();
    const protocol = urlObj.protocol;

    // javascript: and data: URIs are always critical
    if (protocol === 'javascript:' || protocol === 'data:') {
      const result = {
        isPhishing: true, source: 'protocol-check',
        reason: `Dangerous URI scheme: ${protocol} — bypasses URL scanners`
      };
      await setCache(cacheKey, result);
      return result;
    }

    // Punycode detection on link domain
    const punycodeCheck = detectPunycode(hostname);
    if (punycodeCheck.suspicious) {
      const result = {
        isPhishing: true, source: 'punycode-check',
        reason: punycodeCheck.detail
      };
      await setCache(cacheKey, result);
      return result;
    }

    // Try OpenPhish feed — GET the plain-text list and check if the hostname appears in it.
    // The feed is ~2-5 KB and lists one active phishing URL per line.
    // We cache the entire feed for 30 minutes to prevent fetching it for every URL in the email.
    try {
      const feedKey = 'openphish_feed_data';
      const cachedFeed = await chrome.storage.local.get(feedKey);
      let lines = [];
      
      if (cachedFeed[feedKey] && Date.now() - cachedFeed[feedKey].timestamp < 30 * 60 * 1000) {
        lines = cachedFeed[feedKey].lines;
      } else {
        const feedRes = await fetch('https://openphish.com/feed.txt', {
          signal: AbortSignal.timeout(4000)
        });
        if (feedRes.ok) {
          const feedText = await feedRes.text();
          lines = feedText.split('\n').map(l => l.trim()).filter(Boolean);
          await chrome.storage.local.set({ [feedKey]: { lines, timestamp: Date.now() } });
        }
      }

      if (lines.length > 0) {
        const match = lines.find(line => {
          try { return new URL(line).hostname.toLowerCase() === hostname; } catch { return false; }
        });
        if (match) {
          const result = {
            isPhishing: true, source: 'openphish',
            reason: `Hostname "${hostname}" found in OpenPhish live feed`
          };
          await setCache(cacheKey, result);
          return result;
        }
      }
    } catch { /* feed unreachable — fall through to clean result */ }

    const result = { isPhishing: false, source: null };
    await setCache(cacheKey, result);
    return result;
  } catch (e) {
    return { isPhishing: false, source: null, error: e.message };
  }
}
// ─── Weekly Report Alarm (runs every 7 days) ──────────────────────────────────
chrome.runtime.onStartup.addListener(() => { withKeyLock(migrateApiKeysIfNeeded).catch(() => { }); purgeEmailContent({ legacyOnly: true }); });
chrome.runtime.onInstalled.addListener(() => {
  withKeyLock(migrateApiKeysIfNeeded).catch(() => { });
  purgeEmailContent({ legacyOnly: true });   // remove plaintext email content saved by older versions
  chrome.alarms.create('phishalert_weekly_report', { periodInMinutes: 7 * 24 * 60 });
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== 'phishalert_weekly_report') return;

  // Clear all stale cache entries so the 10MB storage limit isn't reached
  const all = await chrome.storage.local.get(null);
  const now = Date.now();
  const keysToRemove = [];
  for (const [key, value] of Object.entries(all)) {
    if (key.startsWith('phishalert_cache_')) {
      if (!value || typeof value.timestamp !== 'number') {
        keysToRemove.push(key);
      } else {
        // Default sweep TTL: 7 days if not specified in the object
        const ttl = value.ttl || (7 * 24 * 60 * 60 * 1000);
        if (now - value.timestamp > ttl) {
          keysToRemove.push(key);
        }
      }
    }
  }
  if (keysToRemove.length) await chrome.storage.local.remove(keysToRemove);

  // Generate and deliver the weekly threat report notification
  const report = await generateWeeklyReport();
  if (!report.hasData) return;

  const settingsData = await chrome.storage.local.get('phishalert_settings');
  const settings = settingsData.phishalert_settings || {};
  if (settings.notificationsEnabled === false) return;

  chrome.notifications.create('phishalert_weekly_' + Date.now(), {
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: '📊 PhishAlert Weekly Report',
    message: `Last 7 days: ${report.totalScanned} emails scanned, ${report.threatsCount} threats caught. Your threat score: ${report.personalThreatScore}/100.`,
    priority: 1
  });
});


// ─── Navigation guard: check the page you are about to open, not just links in email ─────────
// Until now the only webNavigation listener was for OAuth consent screens, so typing or pasting
// a known phishing URL into the address bar (or following it from anywhere but a webmail tab) was
// never checked at all. This runs every top-level http(s) navigation through the same feeds the
// email link check uses and replaces the tab with blocked.html when it is a hit.
//
// Privacy: this sends the visited URL to PhishTank / URLhaus (and Google Safe Browsing if a key is
// set). Controlled by phishalert_settings.navigationProtectionEnabled (default on).
const NAV_VERDICT_TTL_MS = 10 * 60 * 1000;
const NAV_ALLOW_TTL_MS = 10 * 60 * 1000;
const navVerdictCache = new Map();   // url -> { t, v }

function isNavCheckable(u) {
  try {
    const x = new URL(u);
    if (!/^https?:$/.test(x.protocol)) return false;
    const h = x.hostname.toLowerCase();
    if (!h || h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') || h.endsWith('.internal')) return false;
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) {
      const [a, b] = h.split('.').map(Number);
      if (a === 10 || a === 127 || a === 0 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254)) return false;
    }
    return true;
  } catch { return false; }
}

async function navAllowUrl(url) {
  try {
    const cur = (await chrome.storage.session.get('pa_nav_allow')).pa_nav_allow || {};
    const now = Date.now();
    Object.keys(cur).forEach(k => { if (cur[k] < now) delete cur[k]; });
    cur[url] = now + NAV_ALLOW_TTL_MS;
    await chrome.storage.session.set({ pa_nav_allow: cur });
  } catch { }
}
async function navIsAllowed(url) {
  try {
    const cur = (await chrome.storage.session.get('pa_nav_allow')).pa_nav_allow || {};
    return !!cur[url] && cur[url] > Date.now();
  } catch { return false; }
}

// -> null (nothing to report) | { kind:'block'|'warn', reasons:[string] }
async function evaluateNavigation(url) {
  const hit = navVerdictCache.get(url);
  if (hit && Date.now() - hit.t < NAV_VERDICT_TTL_MS) return hit.v;

  const keys = await getApiKeys();
  const [ptR, linkR] = await Promise.allSettled([
    checkPhishTank(url, keys.phishtankApiKey || ''),
    analyzeLinkDestination({ url })
  ]);
  const pt = ptR.status === 'fulfilled' ? ptR.value : null;
  const link = linkR.status === 'fulfilled' ? linkR.value : null;

  let v = null;
  if (link && (link.verdict === 'BLOCK' || link.confirmed)) {
    v = { kind: 'block', reasons: (link.reasons || []).map(r => r.detail).filter(Boolean) };
  } else if (pt && pt.inDatabase && pt.pending) {
    // Listed in PhishTank, vote not finished: not "confirmed", but far too risky to load silently.
    v = { kind: 'warn', reasons: [pt.detail || 'Listed in PhishTank (awaiting community verification)'] };
  }
  navVerdictCache.set(url, { t: Date.now(), v });
  if (navVerdictCache.size > 500) navVerdictCache.delete(navVerdictCache.keys().next().value);
  return v;
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0 || !isNavCheckable(details.url)) return;
  try {
    const s = (await chrome.storage.local.get('phishalert_settings')).phishalert_settings || {};
    if (s.navigationProtectionEnabled === false) return;
    const url = details.url.split('#')[0];
    if (await isWhitelisted(new URL(url).hostname)) return;
    if (await navIsAllowed(url)) return;

    const v = await evaluateNavigation(url);
    if (!v) return;

    const page = chrome.runtime.getURL('blocked.html') +
      '?k=' + v.kind + '&u=' + encodeURIComponent(url) + '&r=' + encodeURIComponent(JSON.stringify(v.reasons.slice(0, 5)));
    await chrome.tabs.update(details.tabId, { url: page });

    try {
      chrome.notifications.create('pa_nav_' + Date.now(), {
        type: 'basic', iconUrl: 'icons/icon128.png',
        title: v.kind === 'block' ? 'PhishAlert blocked a phishing page' : 'PhishAlert: reported phishing page',
        message: new URL(url).hostname
      });
    } catch { }
  } catch (e) { /* never break browsing because a check failed */ }
});
