// PhishAlert — content-shared.js
// Shared utilities injected before every client content script.
// All clients call window.showHijackAlert() and window.paCreateBanner()
// instead of duplicating these functions themselves.

// ── Shared icon set (replaces raw pictographic emoji) ──────────────────────
// FIX: link badges, the QR-danger alert, the HIBP breach modal, and the
// outgoing-scan warning dialog in content.js were still using raw emoji
// (🔗/⚠️/🚨/🚫/✅/🔍) instead of the inline-SVG icon system already used for
// the trust-tier badge and the shared banner helpers above. Centralizing
// them here so every consumer draws from the same set instead of each
// re-inventing (or missing) the fix.
window.paIcon = function(name, color, size) {
  color = color || 'currentColor';
  size = size || 14;
  var body = {
    warning: '<path d="M12 4l9 16H3L12 4z"/><path d="M12 10v4"/><path d="M12 17h.01"/>',
    critical: '<path d="M8.5 3h7L21 8.5v7L15.5 21h-7L3 15.5v-7L8.5 3z"/><path d="M12 8v4"/><path d="M12 16h.01"/>',
    link: '<path d="M9 15l6-6"/><path d="M10 6l.7-.7a4 4 0 015.7 5.7l-1 1"/><path d="M14 18l-.7.7a4 4 0 01-5.7-5.7l1-1"/>',
    check: '<circle cx="12" cy="12" r="9"/><path d="M8 12.5l2.5 2.5L16 9.5"/>',
    block: '<circle cx="12" cy="12" r="9"/><path d="M6.5 6.5l11 11"/>',
    search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="M20 20l-4.35-4.35"/>'
  }[name] || '';
  return '<svg width="' + size + '" height="' + size + '" viewBox="0 0 24 24" fill="none" stroke="' + color +
    '" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;vertical-align:middle">' +
    body + '</svg>';
};

// ── Thread Hijack Alert modal ─────────────────────────────────────────────────
window.showHijackAlert = function(domain, knownDomains) {
  document.querySelectorAll('.pa-hijack-alert').forEach(e => e.remove());

  if (!document.getElementById('pa-hijack-anim')) {
    const s = document.createElement('style');
    s.id = 'pa-hijack-anim';
    // FIX: was raw unquoted CSS — must be a template literal string
    s.textContent = `
      @keyframes pa-slide-in{from{opacity:0;transform:translateY(-12px)}to{opacity:1;transform:translateY(0)}}
      .pa-hijack-alert{animation:pa-slide-in .3s ease-out}
      .pa-hijack-alert{transition:opacity .2s,transform .2s}
    `;
    document.head.appendChild(s);
  }

  const el = document.createElement('div');
  el.className = 'pa-hijack-alert';
  el.style.cssText = [
    'position:fixed;top:20px;right:20px;width:340px',
    'background:#fff;border:1px solid #fecaca;border-left:4px solid #ef4444',
    'border-radius:12px;box-shadow:0 8px 28px rgba(0,0,0,.12)',
    'z-index:2147483647;font-family:-apple-system,"Segoe UI",Roboto,sans-serif;overflow:hidden'
  ].join(';');

  // FIX: was a broken backslash-escaped string — must be a template literal.
  // FIX: domain was never interpolated into the <strong> — now it is.
  // FIX: ⚠️ emoji was corrupted to ?? — restored.
  el.innerHTML = `
    <div style="padding:16px 16px 14px;display:flex;align-items:flex-start;gap:12px">
      <div style="
        width:36px;height:36px;border-radius:10px;
        background:#fee2e2;display:flex;align-items:center;
        justify-content:center;font-size:18px;flex-shrink:0
      ">⚠️</div>
      <div style="flex:1;min-width:0">
        <div style="font-weight:700;font-size:14px;color:#b91c1c;margin-bottom:4px">
          Unfamiliar sender in this conversation
        </div>
        <div style="font-size:12px;color:#4b5563;line-height:1.55">
          This email is from <strong style="color:#1f2937">${domain}</strong>,
          which hasn't appeared in this thread before.
          Be cautious with any links or requests.
        </div>
      </div>
      <button class="pa-hj-x" style="
        background:none;border:none;cursor:pointer;font-size:16px;
        color:#9ca3af;padding:2px;line-height:1;flex-shrink:0
      " title="Dismiss">✕</button>
    </div>
    <div style="padding:0 16px 14px">
      <button class="pa-hj-x" style="
        width:100%;padding:9px;background:#fee2e2;color:#b91c1c;
        border:1px solid #fecaca;border-radius:8px;font-size:12px;
        font-weight:600;cursor:pointer;letter-spacing:.2px;
        transition:background .15s
      " onmouseover="this.style.background='#fecaca'"
        onmouseout="this.style.background='#fee2e2'">Got it</button>
    </div>
  `;

  document.body.appendChild(el);

  el.querySelectorAll('.pa-hj-x').forEach(b => {
    b.addEventListener('click', () => {
      el.style.opacity = '0';
      el.style.transform = 'translateY(-8px)';
      setTimeout(() => el.remove(), 220);
    });
  });

  // Auto-dismiss after 14 seconds
  setTimeout(() => { if (el.isConnected) el.remove(); }, 14000);
};

// ── Shared banner config helper ───────────────────────────────────────────────
// Returns the color/label config for a given trust level.
// Clients use this so they don't each hardcode the same color table.
window.paBannerConfig = function(score) {
  const level = score >= 80 ? 'trusted' : score >= 50 ? 'suspicious' : 'critical';
  const cfg = {
    trusted:    { color:'#15803d', bg:'#f0fdf4', border:'#bbf7d0', accent:'#16a34a', label:'Trusted Sender',   icon:'✓', level },
    suspicious: { color:'#92400e', bg:'#fffbeb', border:'#fde68a', accent:'#d97706', label:'Suspicious Sender', icon:'!', level },
    critical:   { color:'#991b1b', bg:'#fef2f2', border:'#fecaca', accent:'#dc2626', label:'Critical Risk',     icon:'✕', level }
  };
  return cfg[level];
};

// ── Active Link Protection ─────────────────────────────────────────────────────
// "Don't wait until the user gets hacked." Every client's own scanLinksInEmail
// (or equivalent) already annotates suspicious links with a badge — but that's
// passive: the user has to notice it and click it themselves. This intercepts
// the *real* click on the link, before the browser is allowed to navigate,
// and routes it through the background's full destination pipeline
// (SCAN_LINK_CLICK → redirect-chain follow, URLhaus, Google Safe Browsing,
// IDN/brand-impersonation, domain age). ALLOW opens immediately; WARN/BLOCK
// show an interstitial with the reasons and a deliberate Continue-Anyway step.
//
// Deliberately scoped to cross-origin links only (see onClick below) — same-
// host links are the mail app's own navigation (inbox, folders, settings),
// not email content, and checking those would add pointless latency to
// everyday use of Gmail/Outlook/Yahoo/Proton itself.

function paEnsureLinkGuardStyles() {
  if (document.getElementById('pa-alg-anim')) return;
  const s = document.createElement('style');
  s.id = 'pa-alg-anim';
  s.textContent = `
    @keyframes pa-alg-fade{from{opacity:0}to{opacity:1}}
    @keyframes pa-alg-pop{from{opacity:0;transform:scale(.96) translateY(6px)}to{opacity:1;transform:scale(1) translateY(0)}}
    @keyframes pa-alg-spin{to{transform:rotate(360deg)}}
    .pa-alg-overlay{animation:pa-alg-fade .15s ease-out}
    .pa-alg-card{animation:pa-alg-pop .18s ease-out}
  `;
  document.head.appendChild(s);
}

// Tracks the sender domain of whichever email is currently open, so a link
// click can be judged against it ("also doesn't match the sender's own
// domain…"). Each client's scan() calls this after it resolves the domain.
window.__paLinkGuardSenderDomain = '';
window.paSetLinkGuardSender = function (domain) {
  window.__paLinkGuardSenderDomain = domain || '';
};

window.paShowCheckingToast = function () {
  paEnsureLinkGuardStyles();
  const el = document.createElement('div');
  el.className = 'pa-alg-toast';
  el.style.cssText = [
    'position:fixed;bottom:22px;right:22px;z-index:2147483647',
    'background:#111827;color:#fff;font-family:-apple-system,"Segoe UI",Roboto,sans-serif',
    'font-size:12.5px;padding:10px 16px;border-radius:10px',
    'display:flex;align-items:center;gap:9px;box-shadow:0 6px 20px rgba(0,0,0,.25)',
    'animation:pa-alg-fade .15s ease-out'
  ].join(';');
  el.innerHTML = '<span style="width:13px;height:13px;border:2px solid rgba(255,255,255,.35);' +
    'border-top-color:#fff;border-radius:50%;display:inline-block;animation:pa-alg-spin .7s linear infinite">' +
    '</span>PhishAlert is checking this link…';
  document.body.appendChild(el);
  return el;
};

// Maps the current webmail host to a display name so the "return" button
// reads naturally regardless of which of the four clients is running.
function paCurrentClientName() {
  const h = location.hostname;
  if (h.includes('mail.google.com')) return 'Gmail';
  if (h.includes('outlook.')) return 'Outlook';
  if (h.includes('mail.yahoo.com')) return 'Yahoo Mail';
  if (h.includes('proton.')) return 'Proton Mail';
  return 'Inbox';
}

window.paShowLinkGuardModal = function (result, originalHref) {
  paEnsureLinkGuardStyles();
  document.querySelectorAll('.pa-alg-overlay').forEach(e => e.remove());

  // BLOCK = confirmed/high-risk phishing — no bypass, just a way out.
  // WARN  = suspicious but unconfirmed — user can still choose to proceed.
  const isBlock = result.verdict === 'BLOCK';
  const accent = isBlock ? '#dc2626' : '#d97706';
  const bg = isBlock ? '#fef2f2' : '#fffbeb';
  const border = isBlock ? '#fecaca' : '#fde68a';
  const title = isBlock ? 'PhishAlert blocked this link' : 'Suspicious link';
  const riskTag = isBlock ? (result.confirmed ? 'CONFIRMED PHISHING' : 'HIGH RISK') : 'SUSPICIOUS';
  const subtitle = isBlock
    ? (result.confirmed
        ? 'Threat intelligence identified this URL as a known phishing destination.'
        : 'Multiple independent risk indicators point to a phishing destination.')
    : (result.redirect?.hops
        ? `This link redirected through ${result.redirect.hops} domain${result.redirect.hops > 1 ? 's' : ''} and ended at <strong>${result.finalDomain}</strong>.`
        : `This link leads to <strong>${result.finalDomain || result.domain}</strong>.`);

  const reasonsHtml = (result.reasons || []).map(r => `
    <div style="display:flex;gap:8px;align-items:flex-start;padding:6px 0;border-bottom:1px solid ${border};font-size:12.5px;color:#374151">
      <span style="flex-shrink:0;margin-top:1px">${window.paIcon(r.severity === 'critical' || r.severity === 'high' ? 'critical' : 'warning', accent, 14)}</span>
      <span style="line-height:1.5">${r.detail}</span>
    </div>`).join('') || '<div style="font-size:12.5px;color:#6b7280;padding:6px 0">No specific reason recorded — treat with caution.</div>';

  const overlay = document.createElement('div');
  overlay.className = 'pa-alg-overlay';
  overlay.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:rgba(15,23,42,.55);' +
    'display:flex;align-items:center;justify-content:center;padding:20px;font-family:-apple-system,"Segoe UI",Roboto,sans-serif';

  const footerHtml = isBlock
    ? `<div style="padding:16px 20px 18px">
        <button class="pa-alg-return" style="width:100%;padding:11px;border-radius:8px;border:none;background:${accent};color:#fff;font-weight:600;font-size:12.5px;cursor:pointer">Return to ${paCurrentClientName()}</button>
      </div>`
    : `<div style="display:flex;gap:10px;padding:16px 20px 18px">
        <button class="pa-alg-back" style="flex:1;padding:10px;border-radius:8px;border:1px solid #d1d5db;background:#fff;color:#374151;font-weight:600;font-size:12.5px;cursor:pointer">← Go Back</button>
        <button class="pa-alg-proceed" style="flex:1;padding:10px;border-radius:8px;border:none;background:${accent};color:#fff;font-weight:600;font-size:12.5px;cursor:pointer">Continue Anyway →</button>
      </div>`;

  overlay.innerHTML = `
    <div class="pa-alg-card" style="width:420px;max-width:100%;background:#fff;border-radius:14px;border:1px solid ${border};box-shadow:0 20px 50px rgba(0,0,0,.3);overflow:hidden">
      <div style="background:${bg};padding:18px 20px;display:flex;gap:12px;align-items:flex-start;border-bottom:1px solid ${border}">
        <div style="width:38px;height:38px;border-radius:10px;background:${accent};display:flex;align-items:center;justify-content:center;flex-shrink:0">${window.paIcon(isBlock ? 'block' : 'warning', '#fff', 20)}</div>
        <div>
          <div style="display:inline-block;font-size:9.5px;font-weight:800;letter-spacing:.6px;color:#fff;background:${accent};padding:2px 7px;border-radius:4px;margin-bottom:5px">${riskTag}</div>
          <div style="font-weight:700;font-size:14.5px;color:${isBlock ? '#991b1b' : '#92400e'}">${isBlock ? '🚨' : '⚠️'} ${title}</div>
          <div style="font-size:12px;color:#4b5563;margin-top:4px;line-height:1.5">${subtitle}</div>
        </div>
      </div>
      <div style="padding:12px 20px 4px;max-height:200px;overflow-y:auto">
        <div style="font-size:10.5px;font-weight:700;letter-spacing:.4px;color:#9ca3af;text-transform:uppercase;margin-bottom:2px">Why?</div>
        ${reasonsHtml}
      </div>
      <div style="padding:8px 20px 6px;font-size:11px;color:#9ca3af;word-break:break-all">${result.finalUrl || originalHref}</div>
      ${footerHtml}
    </div>
  `;

  document.body.appendChild(overlay);

  if (isBlock) {
    // Confirmed/high-risk — the only way out is back to the inbox. No
    // "continue anyway" bypass, no dismiss-by-clicking-outside either.
    overlay.querySelector('.pa-alg-return').addEventListener('click', () => overlay.remove());
    return;
  }

  overlay.querySelector('.pa-alg-back').addEventListener('click', () => overlay.remove());
  overlay.querySelector('.pa-alg-proceed').addEventListener('click', () => {
    overlay.remove();
    window.open(result.finalUrl || originalHref, '_blank', 'noopener');
  });
  overlay.addEventListener('click', (e) => { if (e.target === overlay) overlay.remove(); });
};

// Call once per content script, at init: window.paActiveLinkGuard({ bg }).
// `bg` is that client's own message-to-background helper. Attaches a single
// document-level, capture-phase listener — safe against the SPA replacing
// the email's own DOM container on every navigation, since it delegates
// rather than binding to a node reference that can go stale.
window.paActiveLinkGuard = function (opts) {
  opts = opts || {};
  const bg = opts.bg;
  if (!bg || window.__paLinkGuardAttached) return;
  window.__paLinkGuardAttached = true;

  async function proceed(href) {
    let settings = null;
    try { settings = await bg('GET_SETTINGS', {}); } catch { }
    if (settings && settings.activeLinkProtectionEnabled === false) {
      window.open(href, '_blank', 'noopener');
      return;
    }

    const toast = window.paShowCheckingToast();
    let result = null;
    try {
      result = await bg('SCAN_LINK_CLICK', { url: href, senderDomain: window.__paLinkGuardSenderDomain || '' });
    } catch { }
    toast.remove();

    if (!result || result.skipped || result.verdict === 'ALLOW') {
      window.open((result && result.finalUrl) || href, '_blank', 'noopener');
      return;
    }
    window.paShowLinkGuardModal(result, href);
  }

  function onClick(e) {
    if (e.button === 2) return; // right-click / "open in new tab" from context menu isn't hookable
    const a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
    if (!a) return;
    if (a.dataset.paBypass === 'true' || a.closest('.pa-link-preview, .pa-alg-overlay')) return; // our own UI

    let href;
    try { href = a.href; } catch { return; } // resolved absolute URL
    if (!/^https?:\/\//i.test(href)) return;

    let hostname = '';
    try { hostname = new URL(href).hostname; } catch { }
    if (!hostname || hostname === location.hostname) return; // the app's own navigation, not email content

    e.preventDefault();
    e.stopImmediatePropagation();
    proceed(href);
  }

  document.addEventListener('click', onClick, true);
  document.addEventListener('auxclick', onClick, true); // middle-click / open-in-new-tab
};

// ── Shared flag row renderer ──────────────────────────────────────────────────
// Builds the HTML rows shown inside a banner for each flag.
window.paFlagRows = function(flagList, c) {
  return (flagList || []).map(f => {
    const good = f.startsWith('✅');
    const clean = f.replace(/^[\u2705\u26a0\ufe0f\u26d4\u{1f6ab}\u{1f3ad}\u274c\u23f0\u21a9\ufe0f\u{1f6a8}]+\s*/u, '');
    return `<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid ${c.border};font-size:12px;color:${good ? '#15803d' : c.color}">
      <span style="flex-shrink:0;font-size:13px">${good ? '✅' : c.level === 'critical' ? '⛔' : '⚠️'}</span>
      <span style="line-height:1.4">${clean}</span>
    </div>`;
  }).join('');
};

// ── FEATURE NEW 5: Investigation Mode — shared IOC extraction helper ─────────
// Every client (Gmail, Outlook, Proton, Yahoo) calls this once per scanned
// email, passing whatever raw evidence it collected. It proactively resolves
// a handful of shortened links to a real destination (reusing the existing
// UNSHORT_URL redirect-chain follower in background.js) so the Investigation
// tab and incident reports don't depend on the user having clicked a link
// first, then hands everything to the background IOC-extraction engine.
const PA_SHORTENER_DOMAINS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
  'dlvr.it', 'ift.tt', 'tiny.cc', 'is.gd', 'su.pr', 'snip.ly'];

window.paResolveRedirectsForIOCs = async function(bg, links, max) {
  const cap = max || 5;
  const targets = [...new Set((links || []).filter(u => typeof u === 'string' && u.startsWith('http')))]
    .filter(u => PA_SHORTENER_DOMAINS.some(d => u.includes(d)))
    .slice(0, cap);
  if (!targets.length) return [];
  const results = await Promise.all(targets.map(async url => {
    try {
      const r = await bg('UNSHORT_URL', { url });
      return r ? { originalUrl: url, ...r } : null;
    } catch { return null; }
  }));
  return results.filter(Boolean);
};

window.paExtractIOCs = async function(bg, data) {
  try {
    const redirects = await window.paResolveRedirectsForIOCs(bg, data.links);
    const scanKey = data.scanKey || `${data.domain || 'unknown'}::${data.from || ''}`;
    return await bg('EXTRACT_IOCS', { scanKey, data: { ...data, redirects } });
  } catch {
    return null;
  }
};

// ═══════════════════════════════════════════════════════════════════════════
// FEATURE 4 (shared) — Outgoing scan guard
// Used by content-yahoo.js and content-proton.js (Outlook/Gmail can adopt it).
//
// Why this exists: the old per-client handlers were `async` and awaited the
// background scan BEFORE calling preventDefault(). By then the click event had
// already finished dispatching, so the mail was sent regardless of the warning.
// This guard stops the click synchronously, scans, and only re-fires the real
// click if the mail is clean or the user confirms "Send anyway".
//
// Behaviour:
//   • Click and Ctrl/Cmd+Enter are both held until the scan finishes.
//   • Recipients come from To/Cc/Bcc chips, typed-but-unchipped input text and
//     title/aria-label attributes. If none can be read the scan still runs on
//     the subject/body (sensitive-content checks) instead of being skipped.
//   • Fails open: scan error or 10s timeout never traps the user's email.
//   • Respects the Settings toggle (phishalert_settings.outgoingScanEnabled).
// ═══════════════════════════════════════════════════════════════════════════
window.paOutgoingGuard = function (cfg) {
  if (!cfg || typeof cfg.bg !== 'function' || !cfg.sendSelector) return;
  if (window.__paOutgoingGuardInstalled) return;
  window.__paOutgoingGuardInstalled = true;

  var bg = cfg.bg;
  var enabled = true;
  var bypass = false;
  var busy = false;
  var EMAIL_RE = /[A-Z0-9._%+'-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
  var ATTRS = ['title', 'aria-label', 'data-email', 'email', 'data-address'];

  function applySetting(s) {
    if (s && typeof s.outgoingScanEnabled === 'boolean') enabled = s.outgoingScanEnabled;
  }
  try {
    chrome.storage.local.get('phishalert_settings', function (r) { applySetting(r && r.phishalert_settings); });
    chrome.storage.onChanged.addListener(function (ch) {
      if (ch && ch.phishalert_settings) applySetting(ch.phishalert_settings.newValue);
    });
  } catch (e) {}

  function emailsFrom(str) {
    return (String(str || '').match(EMAIL_RE) || []).map(function (s) { return s.toLowerCase(); });
  }

  // ── Find the compose container that owns the clicked Send button ──
  function findRoot(btn) {
    var roots = cfg.composeRootSelectors || [];
    for (var i = 0; i < roots.length; i++) {
      var r = btn.closest(roots[i]);
      if (r) return r;
    }
    var recips = cfg.recipientSelectors || [];
    var node = btn.parentElement, hops = 0;
    while (node && node !== document.body && hops < 14) {
      for (var j = 0; j < recips.length; j++) { if (node.querySelector(recips[j])) return node; }
      node = node.parentElement; hops++;
    }
    return document;
  }

  function insideEditor(root, el) {
    var sels = cfg.bodySelectors || [];
    for (var i = 0; i < sels.length; i++) {
      var ed = root.querySelector(sels[i]);
      if (ed && ed.contains(el)) return true;
    }
    return false;
  }

  function collectRecipients(root) {
    var found = {};
    function add(v) { emailsFrom(v).forEach(function (e) { found[e] = true; }); }
    function addFrom(el) {
      if (el.value) add(el.value);                       // typed but not yet a chip
      ATTRS.forEach(function (a) { add(el.getAttribute && el.getAttribute(a)); });
    }
    // Read text node by node: adjacent chips ("Alice" + "bob@corp.org") must not
    // be glued together into one bogus address like "alicebob@corp.org".
    function addText(el) {
      var tw = document.createTreeWalker(el, NodeFilter.SHOW_TEXT, null);
      var n;
      while ((n = tw.nextNode())) add(n.nodeValue);
    }
    (cfg.recipientSelectors || []).forEach(function (sel) {
      root.querySelectorAll(sel).forEach(function (el) {
        addFrom(el);
        addText(el);
        el.querySelectorAll('input,[title],[aria-label],[data-email],[email],[data-address]').forEach(addFrom);
      });
    });
    // Last resort: scan short leaf nodes of the compose window outside the body editor.
    if (!Object.keys(found).length && root !== document) {
      root.querySelectorAll('span,a,button,li,input,[title],[aria-label]').forEach(function (el) {
        if (insideEditor(root, el)) return;
        addFrom(el);
        if (!el.children.length && (el.textContent || '').length < 120) add(el.textContent);
      });
    }
    return Object.keys(found);
  }

  function readSubject(root) {
    var sels = cfg.subjectSelectors || [];
    for (var i = 0; i < sels.length; i++) {
      var el = root.querySelector(sels[i]);
      if (el) { var v = el.value || el.textContent; if (v) return String(v).trim(); }
    }
    return '';
  }

  function readBody(root) {
    if (typeof cfg.getBody === 'function') {
      try { var b = cfg.getBody(root); if (b) return String(b).substring(0, 20000); } catch (e) {}
    }
    var sels = cfg.bodySelectors || [];
    for (var i = 0; i < sels.length; i++) {
      var el = root.querySelector(sels[i]);
      var txt = el && (el.innerText || el.textContent);
      if (txt) return txt.substring(0, 20000);
    }
    return '';
  }

  // ── UI ──
  function showToast() {
    hideToast();
    var t = document.createElement('div');
    t.id = 'pa-out-toast';
    t.textContent = 'PhishAlert: checking recipients before sending…';
    t.style.cssText = 'position:fixed;bottom:24px;left:50%;transform:translateX(-50%);z-index:2147483646;' +
      'background:#1a1a2e;color:#e5e7eb;border:1px solid #3b3b5c;border-radius:8px;padding:9px 16px;' +
      'font:13px -apple-system,Segoe UI,Roboto,sans-serif;box-shadow:0 8px 24px rgba(0,0,0,.35)';
    document.body.appendChild(t);
  }
  function hideToast() { var t = document.getElementById('pa-out-toast'); if (t) t.remove(); }

  function confirmModal(issues) {
    return new Promise(function (resolve) {
      var old = document.getElementById('pa-outgoing-overlay'); if (old) old.remove();
      var overlay = document.createElement('div');
      overlay.id = 'pa-outgoing-overlay';
      overlay.style.cssText = 'position:fixed;inset:0;z-index:2147483647;background:rgba(0,0,0,.6);display:flex;align-items:center;justify-content:center';

      var card = document.createElement('div');
      card.style.cssText = 'background:#1a1a2e;border:1px solid #ef4444;border-radius:14px;padding:26px;max-width:440px;width:90%;' +
        'box-shadow:0 20px 60px rgba(0,0,0,.7);font-family:-apple-system,Segoe UI,Roboto,sans-serif';

      var title = document.createElement('div');
      title.style.cssText = 'display:flex;align-items:center;gap:8px;font-size:19px;font-weight:800;color:#ef4444;margin-bottom:8px';
      title.innerHTML = (window.paIcon ? window.paIcon('critical', '#ef4444', 22) : '') + ' ';
      title.appendChild(document.createTextNode('PhishAlert — Outgoing Email Warning'));

      var sub = document.createElement('div');
      sub.textContent = 'Your email triggered the following security checks:';
      sub.style.cssText = 'font-size:13px;color:#aaa;margin-bottom:14px';

      var list = document.createElement('div');
      list.style.cssText = 'margin-bottom:18px;max-height:240px;overflow:auto';
      issues.forEach(function (i) {
        var row = document.createElement('div');
        row.textContent = i.detail || String(i);
        row.style.cssText = 'padding:8px 11px;background:rgba(239,68,68,.08);border-left:3px solid #ef4444;border-radius:5px;font-size:13px;color:#e5e7eb;margin-bottom:5px';
        list.appendChild(row);
      });

      var btns = document.createElement('div');
      btns.style.cssText = 'display:flex;gap:10px';
      var cancel = document.createElement('button');
      cancel.textContent = '← Cancel & Review';
      cancel.style.cssText = 'flex:1;padding:11px;background:#111;border:1px solid #555;color:#ccc;border-radius:9px;cursor:pointer;font-size:13px;font-weight:700';
      var ok = document.createElement('button');
      ok.textContent = 'Send Anyway →';
      ok.style.cssText = 'flex:1;padding:11px;background:#7f1d1d;border:1px solid #ef4444;color:#fca5a5;border-radius:9px;cursor:pointer;font-size:13px;font-weight:700';
      cancel.id = 'pa-out-cancel'; ok.id = 'pa-out-confirm';
      btns.appendChild(cancel); btns.appendChild(ok);

      card.appendChild(title); card.appendChild(sub); card.appendChild(list); card.appendChild(btns);
      overlay.appendChild(card);
      document.body.appendChild(overlay);

      function done(v) { overlay.remove(); resolve(v); }
      cancel.onclick = function () { done(false); };
      ok.onclick = function () { done(true); };
    });
  }

  // ── Core flow ──
  function release(btn) {
    var target = btn && btn.isConnected ? btn : document.querySelector(cfg.sendSelector);
    if (!target) return;
    bypass = true;
    try { target.click(); } finally { bypass = false; }
  }

  async function handle(btn, payload) {
    var result = null;
    showToast();
    try {
      result = await Promise.race([
        bg('SCAN_OUTGOING', payload),
        new Promise(function (res) { setTimeout(function () { res(null); }, 10000); })
      ]);
    } catch (e) { result = null; }
    hideToast();
    var proceed = true;
    if (result && result.safe === false && result.issues && result.issues.length) {
      proceed = await confirmModal(result.issues);
    }
    if (proceed) release(btn);
  }

  function intercept(e, btn) {
    // Must happen synchronously: once we await, the click has already gone through.
    e.preventDefault();
    e.stopImmediatePropagation();
    if (busy) return;
    busy = true;
    var root = findRoot(btn);
    var payload = { to: collectRecipients(root), subject: readSubject(root), body: readBody(root) };
    try { console.debug('[PhishAlert] outgoing scan — recipients detected:', payload.to.length, payload.to); } catch (x) {}
    handle(btn, payload).then(function () { busy = false; }, function () { busy = false; });
  }

  document.addEventListener('click', function (e) {
    if (bypass || !enabled) return;
    var btn = e.target && e.target.closest ? e.target.closest(cfg.sendSelector) : null;
    if (!btn) return;
    intercept(e, btn);
  }, true);

  // Ctrl/Cmd+Enter sends without a click, so hold that too.
  document.addEventListener('keydown', function (e) {
    if (bypass || !enabled) return;
    if (!((e.ctrlKey || e.metaKey) && e.key === 'Enter')) return;
    var node = document.activeElement, btn = null, hops = 0;
    while (node && node !== document.documentElement && hops < 16 && !btn) {
      btn = node.querySelector ? node.querySelector(cfg.sendSelector) : null;
      node = node.parentElement; hops++;
    }
    if (!btn) return;            // can't find a Send button → don't interfere
    intercept(e, btn);
  }, true);
};