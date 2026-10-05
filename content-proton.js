// PhishAlert — content-proton.js
// FEATURE NEW 1: ProtonMail support
(function() {
  'use strict';

  function bg(type, data) {
    return new Promise(resolve => {
      try { chrome.runtime.sendMessage({ type, ...data }, res => { resolve(chrome.runtime.lastError ? null : res); }); }
      catch { resolve(null); }
    });
  }

  let lastHash = '';

  // ── Thread Hijack Alert (separate floating modal) ─────────────────
  // FIX: showHijackAlert removed — provided by content-shared.js as window.showHijackAlert

  function injectBanner(result) {
    document.querySelectorAll('.pa-proton-banner').forEach(e => e.remove());

    const score = result.score ?? 50;
    // FIX: use shared helpers from content-shared.js
    const c = window.paBannerConfig(score);
    const flagRows = window.paFlagRows(result.flagList, c);

    const el = document.createElement('div');
    el.className = 'pa-proton-banner';
    el.style.cssText = [
      `font-family:-apple-system,Inter,Roboto,sans-serif`,
      `background:${c.bg}`,
      `border:1px solid ${c.border}`,
      `border-left:4px solid ${c.accent}`,
      `border-radius:8px`,
      `margin:6px 0`,
      `overflow:hidden`,
      `z-index:99999`,
      `box-shadow:0 2px 8px rgba(0,0,0,.06)`
    ].join(';');

    el.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;padding:11px 14px;border-bottom:1px solid ${c.border}">
        <div style="display:flex;align-items:center;gap:11px">
          <div style="width:30px;height:30px;border-radius:50%;background:${c.accent};display:flex;align-items:center;justify-content:center;color:#fff;font-weight:700;font-size:15px;flex-shrink:0">${c.icon}</div>
          <div>
            <div style="font-weight:700;font-size:13px;color:${c.color};letter-spacing:.1px">PhishAlert — ${c.label}</div>
            <div style="font-size:11px;color:#6b7280;margin-top:2px">${result.domain || 'Unknown domain'}</div>
          </div>
        </div>
        <div style="display:flex;align-items:center;gap:12px">
          <div style="text-align:center">
            <div style="font-size:22px;font-weight:800;color:${c.color};line-height:1">${score}</div>
            <div style="font-size:10px;color:#9ca3af;letter-spacing:.4px;text-transform:uppercase">Score</div>
          </div>
          <button class="pa-proton-close" style="background:none;border:none;cursor:pointer;font-size:17px;color:#9ca3af;padding:4px;line-height:1;flex-shrink:0">✕</button>
        </div>
      </div>
      ${result.flagList?.length
        ? `<div style="padding:4px 14px 8px">${flagRows}</div>`
        : `<div style="padding:10px 14px;font-size:12px;color:${c.color};opacity:.8">No specific issues detected.</div>`
      }
    `;

    const sub = document.querySelector('h2.message-conversation-summary-title, [data-testid="message-header-subject"]');
    if (sub) sub.after(el); else document.body.prepend(el);
    el.querySelector('.pa-proton-close').addEventListener('click', () => el.remove());
  }

  function extractEmail() {
    const fromEl    = document.querySelector('[data-testid="message-header:from"] .proton-link');
    const subjectEl = document.querySelector('h2.message-conversation-summary-title, [data-testid="message-header-subject"]');
    const from      = fromEl ? fromEl.textContent.trim() : '';
    const subject   = subjectEl ? subjectEl.textContent.trim() : '';
    const links     = [...document.querySelectorAll('a[rel="noopener noreferrer"]')]
      .map(a => a.href).filter(h => h && h.startsWith('http'));

    // FEATURE 10: Proton sometimes shows Reply-To in a separate header row
    let replyTo = '';
    const replyToEl = document.querySelector(
      '[data-testid="message-header:replyTo"] .proton-link, [aria-label*="Reply-To"]'
    );
    if (replyToEl) {
      replyTo = replyToEl.textContent.trim();
    } else {
      // Fallback: all proton-links in header; second one may be reply-to
      const links2 = [...document.querySelectorAll('[data-testid^="message-header"] .proton-link')];
      if (links2.length > 1 && links2[1].textContent.includes('@') && links2[1].textContent !== from) {
        replyTo = links2[1].textContent.trim();
      }
    }

    // FEATURE 14: Thread ID from Proton URL
    const tidM = window.location.pathname.match(/\/([a-zA-Z0-9_-]{20,})/) ||
                 window.location.hash.match(/thread-([a-zA-Z0-9_-]+)/);
    const threadId = tidM ? tidM[1].substring(0, 80) : null;

    // FEATURE 11: Body text for urgency scoring
    const bodyEl = document.querySelector('.proton-mail-message-body, [data-testid="message-content"]');
    const body   = bodyEl ? bodyEl.innerText.substring(0, 1200) : '';

    return { from, subject, links, client: 'proton', replyTo, threadId, body };
  }

  async function scan() {
    const data   = extractEmail();
    const hash   = data.from + '|' + data.subject.slice(0, 50);
    if (hash === lastHash || (!data.from && !data.subject)) return;
    lastHash = hash;
    const domain = data.from.match(/@([\w.-]+)/)?.[1] || '';
    if (!domain) return;
    window.paSetLinkGuardSender && window.paSetLinkGuardSender(domain); // FEATURE NEW 3: Active Link Protection
    try {
      const res = await bg('VERIFY_EMAIL_AUTH', { domain });
      if (!res) return;

      let score = Math.min(100, Math.max(0,
        (res.spf?.pass?25:0)+(res.dkim?.pass?25:(res.dkim?.inconclusive?12:0))+(res.dmarc?.pass?20:0)+(res.mx?.hasMX?15:0)+15
      ));
      const flagList = [];
      if (!res.spf?.pass)   flagList.push('SPF fail');
      if (!res.dkim?.pass && !res.dkim?.inconclusive) flagList.push('DKIM fail');
      if (!res.dmarc?.pass) flagList.push('DMARC fail');
      if (!res.mx?.hasMX)   flagList.push('No MX');
      if (res.urlhaus?.malicious) flagList.push('⚠️ Malware domain (URLhaus)');
      if (res.bimi?.isImpersonatingBrand) flagList.push(`⚠️ No BIMI — impersonates ${res.bimi.claimedBrand}`);
      if (res.bimi?.hasBIMI && res.bimi?.hasVMC) flagList.push('✅ BIMI verified');

      // ── FEATURE 10: Reply-To mismatch ─────────────────────────────────
      if (data.replyTo) {
        const rt = await bg('CHECK_REPLY_TO', { from: data.from, replyTo: data.replyTo }).catch(() => null);
        if (rt?.mismatch) { flagList.push(`↩️ Reply-To mismatch → ${rt.replyToDomain}`); score = Math.max(0, score - 25); }
      }

      // ── FEATURE 11: Urgency keyword scoring ───────────────────────────
      const urg = await bg('URGENCY_SCORE', { subject: data.subject, body: data.body }).catch(() => null);
      if (urg?.isHighRisk)        { flagList.push(`⏰ High-pressure: ${urg.matched.slice(0,2).join(', ')}`); score = Math.max(0, score - 20); }
      else if (urg?.isMediumRisk) { flagList.push(`⏰ Urgency: ${urg.matched.slice(0,2).join(', ')}`); score = Math.max(0, score - 10); }

      // ── FEATURE 12: Contact lookalike ──────────────────────────────────
      const cl = await bg('CHECK_CONTACT_LOOKALIKE', { domain }).catch(() => null);
      if (cl?.lookalike) { flagList.push(`🎭 Lookalike of "${cl.targetDomain}"`); score = Math.max(0, score - (cl.severity === 'high' ? 30 : 18)); }

      // ── FEATURE 13: DNSBL check ────────────────────────────────────────
      const dbl = await bg('DNSBL_CHECK', { domain }).catch(() => null);
      if (dbl?.listed) { flagList.push(`🚫 IP blacklisted: ${dbl.listings?.map(l=>l.source).join(', ')}`); score = Math.max(0, score - (dbl.listings?.length >= 2 ? 35 : 20)); }

      // ── FEATURE 14: Thread hijacking ──────────────────────────────────
      // FIX: check must run BEFORE record. RECORD_THREAD_SENDER was firing
      // first (and unawaited), adding this sender's domain to thread history
      // before CHECK_THREAD_HIJACKING looked at it — so the current sender
      // always matched and hijacking never fired. Now: check against prior
      // history first, then record this sender after.
      if (data.threadId) {
        const hj = await bg('CHECK_THREAD_HIJACKING', { threadId: data.threadId, senderDomain: domain }).catch(() => null);
        if (hj?.hijacking) {
          score = Math.max(0, score - 30);
          // FIX: call shared version from content-shared.js
          window.showHijackAlert(domain, hj.threadDomains || []);
        }
        await bg('RECORD_THREAD_SENDER', { threadId: data.threadId, senderEmail: data.from, senderDomain: domain });
      }

      // FEATURE NEW 4: Phishing DNA — contribute this scan's fingerprint to
      // the cross-client campaign correlation graph.
      bg('RECORD_CAMPAIGN_FINGERPRINT', {
        from: data.from, domain, replyTo: data.replyTo,
        links: data.links, subject: data.subject, client: 'proton'
      }).catch(() => {});

      // FEATURE NEW 5: Investigation Mode — extract IOCs from this scan.
      window.paExtractIOCs && window.paExtractIOCs(bg, {
        scanKey: data.threadId || domain,
        domain, from: data.from, replyTo: data.replyTo, subject: data.subject,
        links: data.links, threadId: data.threadId,
        dnsblIp: dbl?.ip || null,
        client: 'proton'
      }).catch(() => {});

      injectBanner({ score: Math.round(score), domain, flagList });
    } catch {}
  }

  // Outgoing scan (FEATURE 4) — shared guard in content-shared.js.
  // Holds the Send click (or Ctrl/Cmd+Enter) until the scan finishes, then
  // re-fires it if clean or if the user confirms "Send anyway".
  window.paOutgoingGuard && window.paOutgoingGuard({
    bg,
    client: 'proton',
    sendSelector: 'button[data-testid="composer:send-button"]',
    composeRootSelectors: ['[data-testid="composer:container"]', '.composer', '[role="dialog"]', 'form'],
    recipientSelectors: [
      '[data-testid="composer:to"]',
      '[data-testid="composer:cc"]',
      '[data-testid="composer:bcc"]',
      '[data-testid^="composer-addresses"]'
    ],
    subjectSelectors: [
      '[data-testid="composer:subject"]',
      'input[placeholder*="ubject" i]'
    ],
    bodySelectors: [],
    // Proton's editor lives in a same-origin iframe
    getBody: function (root) {
      var f = root.querySelector('iframe[data-testid="rooster-iframe"]') || root.querySelector('iframe');
      var d = f && (f.contentDocument || (f.contentWindow && f.contentWindow.document));
      return d && d.body ? d.body.innerText : '';
    }
  });

  const obs = new MutationObserver(() => { clearTimeout(window._paProtonT); window._paProtonT = setTimeout(scan, 1000); });
  obs.observe(document.body, { childList: true, subtree: true });
  setTimeout(scan, 3000);

  // FEATURE NEW 3: Active Link Protection — intercept real link clicks
  window.paActiveLinkGuard && window.paActiveLinkGuard({ bg });
})();
