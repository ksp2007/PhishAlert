// PhishAlert — content-outlook.js
// FEATURE NEW 1: Outlook Web (live.com, office.com, office365.com) support
(function() {
  'use strict';

  function bg(type, data) {
    return new Promise(resolve => {
      try {
        chrome.runtime.sendMessage({ type, ...data }, res => {
          if (chrome.runtime.lastError) { resolve(null); return; }
          resolve(res);
        });
      } catch { resolve(null); }
    });
  }

  let lastHash = '';

  // FIX: showHijackAlert removed — now provided by content-shared.js as window.showHijackAlert

  // ── Banner injection ───────────────────────────────────────────────
  function injectBanner(result) {
    document.querySelectorAll('.pa-owa-banner').forEach(e => e.remove());

    const score = result.score ?? 50;
    // FIX: use shared helper from content-shared.js
    const c = window.paBannerConfig(score);
    const flagRows = window.paFlagRows(result.flagList, c);

    const el = document.createElement('div');
    el.className = 'pa-owa-banner';
    el.style.cssText = [
      `font-family:-apple-system,"Segoe UI",Roboto,sans-serif`,
      `background:${c.bg}`,
      `border:1px solid ${c.border}`,
      `border-left:4px solid ${c.accent}`,
      `border-radius:8px`,
      `margin:8px 12px`,
      `overflow:hidden`,
      `z-index:9999`,
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
          <button class="pa-owa-close" style="background:none;border:none;cursor:pointer;font-size:17px;color:#9ca3af;padding:4px;line-height:1;flex-shrink:0">✕</button>
        </div>
      </div>
      ${result.flagList?.length
        ? `<div style="padding:4px 14px 8px">${flagRows}</div>`
        : `<div style="padding:10px 14px;font-size:12px;color:${c.color};opacity:.8">No specific issues detected.</div>`
      }
    `;

    const target = document.querySelector('[role="main"]') || document.body;
    target.insertBefore(el, target.firstChild);
    el.querySelector('.pa-owa-close').addEventListener('click', () => el.remove());
  }

  // ── Extract email data ─────────────────────────────────────────────
  function extractEmail() {
    const fromEl    = document.querySelector('[data-testid="recipientWell"] .ms-Persona-primaryText, .allowTextSelection .PF6_z, [title*="@"]');
    const subjectEl = document.querySelector('[role="heading"][tabindex="-1"], h1[tabindex="-1"]');
    const from      = fromEl ? (fromEl.getAttribute('title') || fromEl.textContent).trim() : '';
    const subject   = subjectEl ? subjectEl.textContent.trim() : '';
    const links     = [...document.querySelectorAll('.XbIp4 a[href], .ck1Bs a[href], [role="document"] a[href]')]
      .map(a => a.href).filter(h => h && h.startsWith('http'));

    // FEATURE 10: Reply-To extraction from Outlook DOM
    let replyTo = '';
    const replyToRow = document.querySelector('[aria-label*="Reply-to"], [aria-label*="reply-to"]');
    if (replyToRow) {
      const m = replyToRow.textContent.match(/[\w.+%-]+@[\w.-]+\.[a-z]{2,}/i);
      if (m) replyTo = m[0];
    }
    if (!replyTo) {
      const allPersonas = [...document.querySelectorAll('.ms-Persona-primaryText, [class*="personaText"]')];
      if (allPersonas.length > 1) {
        const second = (allPersonas[1].getAttribute('title') || allPersonas[1].textContent).trim();
        if (second.includes('@') && second !== from) replyTo = second;
      }
    }

    // FEATURE 14: Thread ID from Outlook URL
    const tidM = window.location.hash.match(/[/#]([a-zA-Z0-9_%-]{20,})/) ||
                 window.location.search.match(/[?&](?:id|threadid)=([^&]+)/i);
    const threadId = tidM ? decodeURIComponent(tidM[1]).substring(0, 80) : null;

    // FEATURE 11: Body text snippet for urgency scoring
    const bodyEl = document.querySelector('[role="document"], [aria-label="Message body"]');
    const body   = bodyEl ? bodyEl.innerText.substring(0, 1200) : '';

    return { from, subject, links, headers: {}, client: 'outlook', replyTo, threadId, body };
  }

  async function scan() {
    const data   = extractEmail();
    const hash   = data.from + '|' + data.subject.slice(0, 50);
    if (hash === lastHash || (!data.from && !data.subject)) return;
    lastHash = hash;
    try {
      const domain = data.from.match(/@([\w.-]+)/)?.[1] || '';
      if (!domain) return;
      window.paSetLinkGuardSender && window.paSetLinkGuardSender(domain); // FEATURE NEW 3: Active Link Protection

      const res = await bg('VERIFY_EMAIL_AUTH', { domain });
      if (!res) return;

      let score = Math.min(100, Math.max(0,
        (res.spf?.pass ? 25 : 0) + (res.dkim?.pass ? 25 : (res.dkim?.inconclusive ? 12 : 0)) +
        (res.dmarc?.pass ? 20 : 0) + (res.mx?.hasMX ? 15 : 0) + 15
      ));
      const flagList = [];
      if (!res.spf?.pass)   flagList.push('SPF fail');
      if (!res.dkim?.pass && !res.dkim?.inconclusive) flagList.push('DKIM fail');
      if (!res.dmarc?.pass) flagList.push('DMARC fail');
      if (!res.mx?.hasMX)   flagList.push('No MX');
      if (res.urlhaus?.malicious) flagList.push('URLhaus: ' + res.urlhaus.threat);
      if (res.bimi?.isImpersonatingBrand) flagList.push(`No BIMI — impersonates ${res.bimi.claimedBrand}`);
      if (res.bimi?.hasBIMI && res.bimi?.hasVMC) flagList.push('✅ BIMI verified');

      // ── FEATURE 10: Reply-To mismatch ─────────────────────────────────
      if (data.replyTo) {
        const rt = await bg('CHECK_REPLY_TO', { from: data.from, replyTo: data.replyTo }).catch(() => null);
        if (rt?.mismatch) {
          flagList.push(`↩️ Reply-To mismatch → ${rt.replyToDomain}`);
          score = Math.max(0, score - 25);
        }
      }

      // ── FEATURE 11: Urgency keyword scoring ───────────────────────────
      const urg = await bg('URGENCY_SCORE', { subject: data.subject, body: data.body }).catch(() => null);
      if (urg?.isHighRisk)        { flagList.push(`⏰ High-pressure: ${urg.matched.slice(0,2).join(', ')}`); score = Math.max(0, score - 20); }
      else if (urg?.isMediumRisk) { flagList.push(`⏰ Urgency signals: ${urg.matched.slice(0,2).join(', ')}`); score = Math.max(0, score - 10); }

      // ── FEATURE 12: Contact lookalike ──────────────────────────────────
      const cl = await bg('CHECK_CONTACT_LOOKALIKE', { domain }).catch(() => null);
      if (cl?.lookalike) {
        flagList.push(`🎭 Lookalike of your contact "${cl.targetDomain}"`);
        score = Math.max(0, score - (cl.severity === 'high' ? 30 : 18));
      }

      // ── FEATURE 13: DNSBL check ────────────────────────────────────────
      const dbl = await bg('DNSBL_CHECK', { domain }).catch(() => null);
      if (dbl?.listed) {
        flagList.push(`🚫 IP blacklisted: ${dbl.listings?.map(l => l.source).join(', ')}`);
        score = Math.max(0, score - (dbl.listings?.length >= 2 ? 35 : 20));
      }

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
      // the cross-client campaign correlation graph. Fire-and-forget: never
      // blocks or affects the banner shown above.
      bg('RECORD_CAMPAIGN_FINGERPRINT', {
        from: data.from, domain, replyTo: data.replyTo,
        links: data.links, subject: data.subject, client: 'outlook'
      }).catch(() => {});

      // FEATURE NEW 5: Investigation Mode — extract IOCs from this scan.
      window.paExtractIOCs && window.paExtractIOCs(bg, {
        scanKey: data.threadId || domain,
        domain, from: data.from, replyTo: data.replyTo, subject: data.subject,
        links: data.links, threadId: data.threadId,
        dnsblIp: dbl?.ip || null,
        client: 'outlook'
      }).catch(() => {});

      injectBanner({ score: Math.round(score), domain, flagList });
    } catch {}
  }

  // ── Outgoing scan (Feature 4) ──────────────────────────────────────
  // Shared guard in content-shared.js: holds the Send click (or Ctrl/Cmd+Enter)
  // until the scan finishes, then re-fires it if clean or user confirms.
  window.paOutgoingGuard && window.paOutgoingGuard({
    bg,
    client: 'outlook',
    sendSelector: 'button[aria-label="Send"], button[data-testid="compose-send-button"]',
    composeRootSelectors: ['[role="dialog"]', '.ms-Dialog', '[data-app-section="ConversationContainer"] form', 'form'],
    recipientSelectors: [
      '.ms-PickerItem-text', '.GHb5K',
      '[data-testid="recipientWell"]',
      '[aria-label="To"]', '[aria-label="Cc"]', '[aria-label="Bcc"]'
    ],
    subjectSelectors: [
      'input[aria-label="Add a subject"]',
      'input[placeholder*="subject" i]',
      'input[aria-label*="ubject" i]'
    ],
    bodySelectors: ['[aria-label="Message body"]', '[role="textbox"][aria-label*="Message body" i]', '[contenteditable="true"][role="textbox"]']
  });

  // ── Observer ───────────────────────────────────────────────────────
  const obs = new MutationObserver(() => {
    clearTimeout(window._paOWATimer);
    window._paOWATimer = setTimeout(scan, 900);
  });
  obs.observe(document.body, { childList: true, subtree: true });
  setTimeout(scan, 2000);

  // FEATURE NEW 3: Active Link Protection — intercept real link clicks
  window.paActiveLinkGuard && window.paActiveLinkGuard({ bg });
})();
