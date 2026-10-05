// PhishAlert — idn.js
// Real punycode (RFC 3492) decoding plus look-alike ("skeleton") brand matching.
//
// Why this exists: `new URL("https://xn--80ak6aa92e.com").hostname` does NOT give the
// Unicode form — the WHATWG URL API always serialises hostnames as ASCII/punycode, so
// "decoding" through it returns the xn-- string unchanged and nothing downstream can see
// which brand is being mimicked. This file decodes the labels itself.
//
// Loaded as a content script (after psl.js) and via importScripts() in the background
// service worker, so both sides share identical logic.
(function (g) {
  'use strict';

  // ── RFC 3492 decoder ──────────────────────────────────────────────────────
  var BASE = 36, T_MIN = 1, T_MAX = 26, SKEW = 38, DAMP = 700, INITIAL_BIAS = 72, INITIAL_N = 128;

  function adapt(delta, numPoints, first) {
    delta = first ? Math.floor(delta / DAMP) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    var k = 0;
    while (delta > (((BASE - T_MIN) * T_MAX) >> 1)) {
      delta = Math.floor(delta / (BASE - T_MIN));
      k += BASE;
    }
    return k + Math.floor(((BASE - T_MIN + 1) * delta) / (delta + SKEW));
  }

  function digitValue(cp) {
    if (cp >= 48 && cp <= 57) return cp - 22;   // 0-9 -> 26-35
    if (cp >= 65 && cp <= 90) return cp - 65;   // A-Z -> 0-25
    if (cp >= 97 && cp <= 122) return cp - 97;  // a-z -> 0-25
    return BASE;
  }

  // Decodes the part after "xn--". Returns a string, or null if malformed.
  function punyDecode(input) {
    var output = [];
    var n = INITIAL_N, i = 0, bias = INITIAL_BIAS;
    var basic = input.lastIndexOf('-');
    if (basic < 0) basic = 0;
    for (var j = 0; j < basic; j++) {
      var c = input.charCodeAt(j);
      if (c >= 0x80) return null;
      output.push(c);
    }
    for (var index = basic > 0 ? basic + 1 : 0; index < input.length;) {
      var oldi = i;
      for (var w = 1, k = BASE; ; k += BASE) {
        if (index >= input.length) return null;
        var d = digitValue(input.charCodeAt(index++));
        if (d >= BASE) return null;
        i += d * w;
        if (i > 0x7fffffff) return null;
        var t = k <= bias ? T_MIN : (k >= bias + T_MAX ? T_MAX : k - bias);
        if (d < t) break;
        w *= BASE - t;
        if (w > 0x7fffffff) return null;
      }
      var out = output.length + 1;
      bias = adapt(i - oldi, out, oldi === 0);
      n += Math.floor(i / out);
      if (n > 0x10ffff) return null;
      i %= out;
      output.splice(i++, 0, n);
    }
    try { return String.fromCodePoint.apply(null, output); } catch (e) { return null; }
  }

  // "xn--80ak6aa92e.com" -> "аррӏе.com". A label that fails to decode is kept as-is
  // and reported via `failed` so callers can treat malformed punycode as suspicious.
  function toUnicodeHost(host) {
    var failed = false;
    var labels = String(host || '').toLowerCase().replace(/\.+$/, '').split('.').map(function (l) {
      if (l.indexOf('xn--') !== 0) return l;
      var d = punyDecode(l.slice(4));
      if (d === null) { failed = true; return l; }
      return d;
    });
    return { unicode: labels.join('.'), labels: labels, failed: failed };
  }

  // ── Look-alike skeleton ───────────────────────────────────────────────────
  // Maps characters that render like a Latin letter to that letter. Accents are
  // handled separately (NFKD + strip combining marks).
  var CONFUSABLE = {
    // Cyrillic
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y', 'і': 'i',
    'ї': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'һ': 'h', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w',
    'ɡ': 'g', 'ɑ': 'a', 'ɩ': 'i', 'ı': 'i', 'ⅼ': 'l', 'ǀ': 'l', 'ɫ': 'l',
    // Greek
    'ο': 'o', 'ρ': 'p', 'α': 'a', 'ν': 'v', 'ι': 'i', 'κ': 'k', 'υ': 'u', 'χ': 'x',
    // Latin small caps
    'ᴀ': 'a', 'ʙ': 'b', 'ᴄ': 'c', 'ᴅ': 'd', 'ᴇ': 'e', 'ɢ': 'g', 'ʜ': 'h', 'ɪ': 'i',
    'ᴊ': 'j', 'ᴋ': 'k', 'ʟ': 'l', 'ᴍ': 'm', 'ɴ': 'n', 'ᴏ': 'o', 'ᴘ': 'p', 'ʀ': 'r',
    'ᴛ': 't', 'ᴜ': 'u', 'ᴠ': 'v', 'ᴡ': 'w', 'ʏ': 'y', 'ᴢ': 'z',
    // Latin letters with no decomposition
    'ł': 'l', 'ø': 'o', 'đ': 'd', 'ħ': 'h', 'ŧ': 't', 'ƅ': 'b', 'ß': 'ss'
  };

  function skeleton(str) {
    var s = String(str || '').toLowerCase();
    try { s = s.normalize('NFKD'); } catch (e) { /* very old engines: skip */ }
    s = s.replace(/[\u0300-\u036f]/g, '');
    var out = '';
    for (var ch of s) out += (CONFUSABLE[ch] !== undefined ? CONFUSABLE[ch] : ch);
    return out;
  }

  // Which of the scripts commonly used in spoofs does this label use?
  function scriptsOf(label) {
    var found = [];
    try {
      var tests = { Latin: /\p{Script=Latin}/u, Cyrillic: /\p{Script=Cyrillic}/u, Greek: /\p{Script=Greek}/u,
                    Armenian: /\p{Script=Armenian}/u };
      for (var name in tests) if (tests[name].test(label)) found.push(name);
    } catch (e) { /* no \p support */ }
    return found;
  }

  function lev(a, b) {
    var prev = [], cur = [], i, j;
    for (j = 0; j <= b.length; j++) prev[j] = j;
    for (i = 1; i <= a.length; i++) {
      cur = [i];
      for (j = 1; j <= b.length; j++) {
        cur[j] = a[i - 1] === b[j - 1] ? prev[j - 1] : 1 + Math.min(prev[j], cur[j - 1], prev[j - 1]);
      }
      prev = cur;
    }
    return prev[b.length];
  }

  function matchBrand(label, brands) {
    var sk = skeleton(label);
    if (sk.length < 4) return null;
    for (var b = 0; b < brands.length; b++) {
      var brand = brands[b];
      if (sk === brand) return { brand: brand, match: 'lookalike', skeleton: sk };
    }
    // Embedded: long brands match as a substring ("paypal-secure"); short ones (meta, zoom,
    // uber ...) only as a whole hyphen-delimited token, so "métal" doesn't read as "meta".
    var tokens = sk.split('-');
    for (b = 0; b < brands.length; b++) {
      brand = brands[b];
      if ((brand.length >= 5 && sk.indexOf(brand) !== -1) || tokens.indexOf(brand) !== -1) {
        return { brand: brand, match: 'embedded', skeleton: sk };
      }
    }
    for (b = 0; b < brands.length; b++) {
      brand = brands[b];
      if (brand.length >= 5 && Math.abs(sk.length - brand.length) <= 2 &&
          lev(sk, brand) <= (brand.length <= 6 ? 1 : 2)) {
        return { brand: brand, match: 'near', skeleton: sk };
      }
    }
    return null;
  }

  // Full analysis of a hostname. `brands` is the caller's brand list (lower-case names).
  // Looks at the registrable name first, then every label in front of it.
  function analyze(host, brands) {
    var h = String(host || '').toLowerCase().replace(/\.+$/, '');
    var res = { hasPunycode: false, decoded: null, failed: false, mixedScript: false,
                targetBrand: null, match: null, skeleton: null, label: null };
    var labels = h.split('.');
    if (!labels.some(function (l) { return l.indexOf('xn--') === 0; })) return res;
    res.hasPunycode = true;

    var uni = toUnicodeHost(h);
    res.decoded = uni.unicode;
    res.failed = uni.failed;

    // Registrable name = label just before the public suffix; check it first.
    var reg = (typeof g.paRootDomain === 'function') ? g.paRootDomain(h) : h;
    var regLabelCount = reg.split('.').length;
    var sldIdx = Math.max(0, uni.labels.length - regLabelCount);
    var order = [sldIdx];
    for (var i = sldIdx - 1; i >= 0; i--) order.push(i);

    for (var k = 0; k < uni.labels.length; k++) {
      if (scriptsOf(uni.labels[k]).length > 1) res.mixedScript = true;
    }
    for (var o = 0; o < order.length; o++) {
      var m = matchBrand(uni.labels[order[o]], brands || []);
      if (m) {
        res.targetBrand = m.brand; res.match = m.match; res.skeleton = m.skeleton;
        res.label = uni.labels[order[o]];
        break;
      }
    }
    return res;
  }

  g.paIdn = { punyDecode: punyDecode, toUnicodeHost: toUnicodeHost, skeleton: skeleton,
              scriptsOf: scriptsOf, analyze: analyze };
})(typeof self !== 'undefined' ? self : globalThis);
