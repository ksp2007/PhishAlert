// PhishAlert — Content Script (Gmail)
// Phase 1: Domain scoring + Display name spoofing + WHOIS age
// Phase 2: Link scanning + URL unshortener + IDN homograph detection
// Phase 3: VirusTotal integration + Community threat reporting

(function () {
  'use strict';

  // Registrable-domain helper (psl.js is loaded before this file). If it is ever
  // missing, fall back to the full hostname so different hosts never compare equal.
  function paRoot(host) {
    var h = String(host || '').toLowerCase();
    return (typeof window.paRootDomain === 'function') ? window.paRootDomain(h) : h;
  }

  // HTML-escape for anything that did not originate in this extension (AI output,
  // email-derived text). AI responses are steerable by the email being analysed, so
  // they are treated as untrusted: always escaped, never concatenated into markup raw.
  function paEsc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  // Escaped text with newlines preserved as <br> (escape FIRST, then add the tag).
  function paEscBr(s) { return paEsc(s).replace(/\r?\n/g, '<br>'); }

  // ─── Message helper to background ────────────────────────────────────────
  // Retries up to 4 times with exponential backoff (200→400→800→1600 ms).
  // This covers the SW cold-start window: when Chrome loads the extension the
  // service worker may not be alive yet when the first inbox scan fires.
  function bg(type, data = {}, _attempt = 0) {
    return new Promise((resolve) => {
      // If the extension context was invalidated (extension reloaded mid-session)
      // chrome.runtime.id is undefined — bail immediately rather than throw.
      if (!chrome.runtime?.id) { resolve(null); return; }

      try {
        chrome.runtime.sendMessage({ type, ...data }, (res) => {
          const err = chrome.runtime.lastError;
          if (err) {
            const msg = err.message || '';
            const retryable =
              msg.includes('Could not establish connection') ||
              msg.includes('Receiving end does not exist') ||
              msg.includes('message channel closed');
            if (retryable && _attempt < 4) {
              setTimeout(() => bg(type, data, _attempt + 1).then(resolve),
                200 * Math.pow(2, _attempt));
            } else {
              resolve(null);
            }
          } else {
            resolve(res);
          }
        });
      } catch (e) {
        // sendMessage itself threw — SW context not ready yet, retry
        if (_attempt < 4) {
          setTimeout(() => bg(type, data, _attempt + 1).then(resolve),
            200 * Math.pow(2, _attempt));
        } else {
          console.warn('[PhishAlert] sendMessage failed after retries:', e.message);
          resolve(null);
        }
      }
    });
  }

  // ─── Cache ────────────────────────────────────────────────────────────────
  const domainCache = new Map();

  // ─── PHASE 1: Scoring Constants ───────────────────────────────────────────
  const WEIGHTS = { spf: 25, dkim: 25, dmarc: 20, domainAge: 15, reputation: 15 };
  const THRESHOLD_GREEN = 90;

  // Free-mail providers: anyone can open an account, so the PROVIDER's domain age and reputation
  // say nothing about the individual sender. A scammer on gmail.com used to inherit gmail.com's
  // 30/30 age+reputation points. For these domains those points are withheld and the score
  // rests on the message itself (auth results, content, links, sender history).
  const PA_FREEMAIL = new Set([
    'gmail.com', 'googlemail.com', 'yahoo.com', 'yahoo.in', 'yahoo.co.in', 'yahoo.co.uk', 'ymail.com',
    'rocketmail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'outlook.in', 'hotmail.co.uk',
    'icloud.com', 'me.com', 'mac.com', 'aol.com', 'proton.me', 'protonmail.com', 'pm.me',
    'rediffmail.com', 'zoho.com', 'zohomail.in', 'gmx.com', 'gmx.net', 'mail.com', 'yandex.com',
    'yandex.ru', 'tutanota.com', 'tuta.io', 'fastmail.com'
  ]);
  function paIsFreemail(domain) { return PA_FREEMAIL.has((domain || '').toLowerCase()); }
  function paAddrOf(senderStr) {
    const m = String(senderStr || '').toLowerCase().match(/[a-z0-9._%+\-]+@[a-z0-9.\-]+/);
    return m ? m[0] : '';
  }

  const TRUSTED_DOMAINS = new Set([
    'gmail.com', 'google.com', 'microsoft.com', 'outlook.com', 'yahoo.com',
    'apple.com', 'amazon.com', 'facebook.com', 'twitter.com', 'linkedin.com',
    'github.com', 'dropbox.com', 'slack.com', 'zoom.us', 'paypal.com',
    'bankofamerica.com', 'chase.com', 'wellsfargo.com', 'netflix.com',
    'spotify.com', 'adobe.com', 'salesforce.com', 'shopify.com', 'instagram.com',
    'whatsapp.com', 'telegram.org', 'reddit.com', 'wikipedia.org', 'notion.so'
  ]);

  // Top brands for lookalike detection
  const TOP_BRANDS = [
    'google', 'microsoft', 'apple', 'amazon', 'facebook', 'paypal', 'netflix',
    'instagram', 'twitter', 'linkedin', 'dropbox', 'slack', 'zoom', 'adobe',
    'salesforce', 'shopify', 'github', 'spotify', 'walmart', 'ebay', 'chase',
    'wellsfargo', 'citibank', 'barclays', 'hsbc', 'airbnb', 'uber', 'lyft'
  ];

  // ─── PHASE 2: IDN Homograph Confusable Map ───────────────────────────────
  const CONFUSABLES = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'і': 'i', 'ї': 'i',
    'ɑ': 'a', 'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g', 'ʟ': 'l', 'ᴍ': 'm', 'ɴ': 'n',
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '6': 'g', '7': 't', '8': 'b',
    'ⅼ': 'l', 'ı': 'i', 'ĺ': 'l', 'ḷ': 'l', 'ļ': 'l', 'ľ': 'l',
    'á': 'a', 'à': 'a', 'â': 'a', 'ä': 'a', 'ã': 'a', 'å': 'a',
    'é': 'e', 'è': 'e', 'ê': 'e', 'ë': 'e',
    'í': 'i', 'ì': 'i', 'î': 'i', 'ï': 'i',
    'ó': 'o', 'ò': 'o', 'ô': 'o', 'ö': 'o', 'õ': 'o',
    'ú': 'u', 'ù': 'u', 'û': 'u', 'ü': 'u',
    'ñ': 'n', 'ç': 'c', 'ß': 'ss'
  };

  function normalizeForHomograph(str) {
    let result = str.toLowerCase();
    for (const [confusable, ascii] of Object.entries(CONFUSABLES)) {
      result = result.split(confusable).join(ascii);
    }
    return result;
  }

  // Levenshtein distance for fuzzy brand matching
  function levenshtein(a, b) {
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

  // ─── PHASE 1: Display Name Spoofing Detection ────────────────────────────
  function detectDisplayNameSpoofing(displayName, senderEmail) {
    if (!displayName || !senderEmail) return { spoofing: false };

    const domain = extractDomain(senderEmail);
    if (!domain) return { spoofing: false };

    const domainBase = domain.split('.')[0].toLowerCase();
    const displayLower = displayName.toLowerCase();

    // Check if display name impersonates a well-known brand
    // but the actual domain doesn't match
    for (const brand of TOP_BRANDS) {
      const displayMentionsBrand = displayLower.includes(brand);
      const domainMatchesBrand = domain.includes(brand) || TRUSTED_DOMAINS.has(domain);

      if (displayMentionsBrand && !domainMatchesBrand) {
        return {
          spoofing: true,
          claimedBrand: brand,
          actualDomain: domain,
          detail: `Display name claims to be "${brand}" but email is from "${domain}"`
        };
      }
    }

    // Check if display name contains an email address different from actual sender
    const emailInDisplayName = displayLower.match(/[\w.-]+@[\w.-]+\.[a-z]{2,}/);
    if (emailInDisplayName && !senderEmail.toLowerCase().includes(emailInDisplayName[0])) {
      return {
        spoofing: true,
        claimedBrand: emailInDisplayName[0],
        actualDomain: domain,
        detail: `Display name shows different email than actual sender`
      };
    }

    return { spoofing: false };
  }

  // ─── PHASE 1: IDN Homograph Check ────────────────────────────────────────
  function checkHomograph(domain) {
    const normalized = normalizeForHomograph(domain);
    const domainBase = normalized.split('.')[0];

    for (const brand of TOP_BRANDS) {
      if (domainBase === brand) continue; // exact match is fine

      const distance = levenshtein(domainBase, brand);
      const isHomograph = normalized !== domain; // contains confusable chars
      const isTyposquat = distance <= 2 && distance > 0;

      if (isHomograph && isTyposquat) {
        return {
          detected: true,
          type: 'homograph',
          targetBrand: brand,
          detail: `Possible IDN homograph attack mimicking "${brand}"`
        };
      }

      if (isTyposquat && domainBase.length >= brand.length - 1) {
        return {
          detected: true,
          type: 'typosquat',
          targetBrand: brand,
          detail: `Possible typosquatting of "${brand}" (distance: ${distance})`
        };
      }
    }

    return { detected: false };
  }

  // ─── FEATURE 3: Punycode / xn-- Detection (via background) ──────────────
  async function checkPunycode(domain) {
    if (!domain.includes('xn--')) return { hasPunycode: false, suspicious: false };
    return await bg('CHECK_PUNYCODE', { domain }) || { hasPunycode: false, suspicious: false };
  }

  // ─── FEATURE 4: Link Text vs URL Mismatch Detection ─────────────────────
  function checkLinkTextMismatch(anchorText, href) {
    if (!anchorText || !href) return { mismatch: false };
    const text = anchorText.trim().toLowerCase();

    // If anchor text looks like a URL
    const looksLikeUrl = /^https?:\/\/|^www\.|[\w-]+\.[a-z]{2,}(\/|$)/.test(text);
    if (!looksLikeUrl) return { mismatch: false };

    let hrefDomain = '';
    let textDomain = '';
    try {
      hrefDomain = new URL(href).hostname.toLowerCase().replace(/^www\./, '');
    } catch { return { mismatch: false }; }

    try {
      const textUrl = text.startsWith('http') ? text : 'https://' + text;
      textDomain = new URL(textUrl).hostname.toLowerCase().replace(/^www\./, '');
    } catch { return { mismatch: false }; }

    if (!textDomain || !hrefDomain) return { mismatch: false };
    if (textDomain === hrefDomain) return { mismatch: false };

    // Check if they share a registrable domain (e.g. login.paypal.com vs paypal.com).
    // Uses the Public Suffix List so sbi.co.in and evil.co.in are NOT the same domain.
    if (paRoot(textDomain) === paRoot(hrefDomain)) return { mismatch: false };

    return {
      mismatch: true,
      displayedDomain: textDomain,
      actualDomain: hrefDomain,
      detail: `Link shows "${textDomain}" but goes to "${hrefDomain}" — classic phishing trick`
    };
  }

  // ─── FEATURE 5: javascript: and data: URI Detection ─────────────────────
  function checkDangerousURI(href) {
    if (!href) return { dangerous: false };
    const lower = href.trim().toLowerCase();
    if (lower.startsWith('javascript:')) {
      return { dangerous: true, scheme: 'javascript:', detail: 'javascript: URI — executes code, bypasses URL scanners' };
    }
    if (lower.startsWith('data:text/html') || lower.startsWith('data:application')) {
      return { dangerous: true, scheme: 'data:', detail: 'data: URI — embeds executable HTML/JS, bypasses URL scanners' };
    }
    if (lower.startsWith('vbscript:')) {
      return { dangerous: true, scheme: 'vbscript:', detail: 'vbscript: URI — executes VBScript code' };
    }
    return { dangerous: false };
  }

  // ─── Utilities ────────────────────────────────────────────────────────────
  function extractDomain(emailStr) {
    if (!emailStr) return null;
    const match = emailStr.match(/<([^>]+)>/) || emailStr.match(/([^\s]+@[^\s]+)/);
    const email = match ? match[1] : emailStr.trim();
    const parts = email.split('@');
    if (parts.length < 2) return null;
    return parts[1].toLowerCase().trim();
  }

  function extractDisplayName(emailStr) {
    if (!emailStr) return null;
    const match = emailStr.match(/^([^<]+)<[^>]+>/);
    if (match) return match[1].trim().replace(/^["']|["']$/g, '');
    // If no angle brackets, check if there's a name before the email
    return null;
  }

  // FIX: detect the signed-in account's own address so injectBadge() can
  // skip the user's own sent/reply messages. Gmail's conversation view
  // auto-expands the newest message in a thread — which, right after you
  // reply to a phishing email, IS your own reply — so without this check
  // injectBadge() was scoring your own outgoing message and overwriting the
  // single "current scan" record with it, breaking Threats & Forensics /
  // canary lookups for the phishing email you actually meant to investigate.
  let _ownEmailCache = undefined;
  function getOwnAccountEmail() {
    if (_ownEmailCache !== undefined) return _ownEmailCache;
    let email = null;
    const acctEl = document.querySelector(
      'a[aria-label*="Google Account"], a[href*="SignOutOptions"][aria-label*="@"], .gb_A[aria-label*="@"]'
    );
    const label = acctEl?.getAttribute('aria-label') || '';
    const m = label.match(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/i);
    if (m) email = m[0].toLowerCase();
    _ownEmailCache = email;
    return email;
  }

  // Name part of the registrable domain: "sbi" for sbi.co.in (was "co"), "paypal" for paypal.com.
  function getDomainBase(domain) {
    const root = paRoot(domain || '');
    return root.split('.')[0] || '';
  }

  // ─── PHASE 4: Sender History Trust ───────────────────────────────────────
  async function getSenderTrustBonus(email) {
    return await bg('GET_SENDER_TRUST', { email }) || { trustBonus: 0, label: 'First contact', replyCount: 0, seenCount: 0 };
  }

  // ─── PHASE 4: Pixel Tracker Detection ────────────────────────────────────
  async function detectTrackers(emailContainer) {
    const html = emailContainer.innerHTML || '';
    return await bg('DETECT_TRACKERS', { htmlContent: html });
  }

  // ─── PHASE 4: Email Header Analysis ──────────────────────────────────────
  function extractEmailHeaders(emailContainer) {
    const headers = {};

    // From (sender)
    const senderEl = emailContainer.querySelector('[data-hovercard-id], span[email], .gD');
    if (senderEl) {
      const email = senderEl.getAttribute('email') || senderEl.getAttribute('data-hovercard-id') || '';
      if (email.includes('@')) headers.from = email;
    }

    // ── FEATURE 10: Reply-To — improved multi-strategy extraction ──────────
    // Strategy 1: Gmail exposes reply-to via the "reply-to" tooltip/title on
    // the sender info row when it differs from From.
    const replyToTip = emailContainer.querySelector('[data-tooltip*="reply-to"], [title*="reply-to"], [aria-label*="reply-to"]');
    if (replyToTip) {
      const tip = replyToTip.getAttribute('data-tooltip') || replyToTip.getAttribute('title') || '';
      const m = tip.match(/[\w.+%-]+@[\w.-]+\.[a-z]{2,}/i);
      if (m) headers.replyTo = m[0];
    }

    // Strategy 2: Gmail's expanded "Show details" panel prints labeled plain-text
    // rows (from:, reply-to:, to:, date:, mailed-by:, signed-by:...). When a
    // reply-to row is present, it's the only reliable DOM signal that the
    // message actually carries a Reply-To header different from From — unlike
    // guessing from element position, which false-positives on any multi-recipient
    // email (recipient chips also carry email/data-hovercard-id attributes and
    // were previously being mistaken for a Reply-To chip).
    if (!headers.replyTo) {
      const detailsText = emailContainer.innerText || '';
      const rtLineMatch = detailsText.match(/reply-to:\s*[^\n<]*?([\w.+%-]+@[\w.-]+\.[a-z]{2,})/i);
      if (rtLineMatch) headers.replyTo = rtLineMatch[1];
    }

    // NOTE: There is deliberately NO "any mailto: link in the body" fallback.
    // A mailto: anchor in the body (invoice contact, signature, "questions?
    // email billing@...") is just a link — it says nothing about the Reply-To
    // header and previously caused false "BEC redirect" warnings on benign mail.
    // Reply-To is only set from the header-level signals above.

    // Message-ID from Gmail URL hash
    const urlHash = window.location.hash;
    const msgIdMatch = urlHash.match(/#[^/]+\/([a-f0-9]+)/);
    if (msgIdMatch) headers.messageId = msgIdMatch[1];

    // FEATURE 2: Extract additional headers for deep analysis
    // Gmail renders some header data in hidden elements — scrape what we can

    // X-Spam-Score: look in any hidden/aria-hidden meta elements
    const allText = emailContainer.innerText || '';

    // Try to detect Received: chain indicators from metadata attributes
    // Gmail collapses headers but sometimes exposes hop data in data attributes
    const metaEls = emailContainer.querySelectorAll('[data-tooltip], [title]');
    const receivedHints = [];
    metaEls.forEach(el => {
      const t = (el.getAttribute('data-tooltip') || el.getAttribute('title') || '').toLowerCase();
      if (t.includes('via') || t.includes('sent from') || t.includes('mailed-by')) {
        receivedHints.push(t);
      }
    });
    if (receivedHints.length > 0) headers.receivedChain = receivedHints;

    // Extract authentication result from Gmail's "mailed-by" / "signed-by" UI hints
    const mailedByEl = emailContainer.querySelector('[data-tooltip*="Mailed by"], [title*="mailed-by"]');
    // Gmail's "Mailed by" only names the sending domain; it does NOT expose the
    // SPF/DKIM/DMARC verdict, so we must not synthesize an auth result from it.
    // headers.authResults is only ever set from a real Authentication-Results
    // value (none is available from the Gmail DOM), so SPF stays unreported.
    if (mailedByEl) {
      headers.mailedBy = mailedByEl.textContent?.trim() || '';
    }

    // X-Spam heuristic: if Gmail shows "This message seems dangerous" banner
    const dangerBanner = emailContainer.querySelector('.a3s [data-danger], .ph, [data-phish]');
    if (dangerBanner || emailContainer.querySelector('[data-spam]')) {
      headers.xSpamStatus = 'Yes (Gmail flagged)';
      headers.xSpamScore = '10';
    }

    return headers;
  }

  // ─── FEATURE 9: Real QR Code Decoding via jsQR ──────────────────────────
  // jsQR.js is loaded as a regular content script (see manifest.json), so it
  // runs in the SAME isolated world as this file and window.jsQR is directly
  // visible here — no cross-world script injection needed.

  function isJsQRReady() {
    return typeof window.jsQR === 'function';
  }

  async function decodeQRFromImage(imgEl) {
    return new Promise((resolve) => {
      const src = imgEl.src || imgEl.getAttribute('src') || '';
      if (!src || src.startsWith('data:image/gif')) { resolve(null); return; }

      const img = new Image();
      img.crossOrigin = 'anonymous';

      img.onload = () => {
        try {
          const canvas = document.createElement('canvas');
          canvas.width = img.naturalWidth || img.width || 200;
          canvas.height = img.naturalHeight || img.height || 200;
          if (canvas.width < 10 || canvas.height < 10) { resolve(null); return; }

          const ctx = canvas.getContext('2d');
          ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

          // jsQR is loaded as a content script into this same isolated world
          const code = window.jsQR && window.jsQR(imageData.data, imageData.width, imageData.height, {
            inversionAttempts: 'dontInvert'
          });
          resolve(code ? code.data : null);
        } catch { resolve(null); }
      };

      img.onerror = () => resolve(null);

      // Re-trigger load for already-cached images
      if (src.startsWith('data:')) { img.src = src; }
      else { img.src = src + (src.includes('?') ? '&' : '?') + '_pa=' + Date.now(); }
    });
  }

  async function detectQRCodes(emailContainer) {
    // Step 1: Heuristic detection (works without jsQR — catches obvious cases)
    const html = emailContainer.innerHTML || '';
    const heuristicResult = await bg('DETECT_QR', { htmlContent: html });

    // Step 2: Attempt pixel-level decode via jsQR
    const qrScannedUrls = [];
    const qrThreats = [];

    // Only run jsQR decode if we have suspicious images or QR hints
    const hasQRHint = /qr|scan.*me|scan.*code/i.test(html);
    const images = [...emailContainer.querySelectorAll('img[src]')];

    // Only decode images that are plausibly QR codes (square-ish, ≥80px)
    const candidates = images.filter(img => {
      const w = img.naturalWidth || img.width || 0;
      const h = img.naturalHeight || img.height || 0;
      if (w === 0 && h === 0) return hasQRHint; // unknown size — try if hint present
      const ratio = w > 0 && h > 0 ? Math.max(w, h) / Math.min(w, h) : 99;
      return ratio < 1.4 && w >= 60 && h >= 60; // roughly square ≥ 60px
    });

    if (candidates.length > 0) {
      const loaded = isJsQRReady();
      if (!loaded) console.warn('[PhishAlert] jsQR not available — QR pixel decoding skipped for this scan.');
      if (loaded) {
        for (const img of candidates.slice(0, 6)) { // cap at 6 images
          const decoded = await decodeQRFromImage(img);
          if (!decoded) continue;

          // Mark the image visually
          img.style.outline = '3px solid #f59e0b';
          img.title = `PhishAlert: QR code decoded — scanning URL…`;

          let scanResult = null;
          if (decoded.startsWith('http')) {
            qrScannedUrls.push(decoded);
            scanResult = await bg('SCAN_QR_URL', { url: decoded });
          }

          const isMalicious = !!(scanResult?.isMalicious);
          const threats = scanResult?.threats || [];

          // Add decoded finding to heuristic results
          heuristicResult.qrFindings = heuristicResult.qrFindings || [];
          heuristicResult.qrFindings.push({
            type: 'qr_decoded',
            url: decoded,
            isMalicious,
            threats,
            detail: isMalicious
              ? `QR decoded: ${decoded.substring(0, 60)} — THREAT: ${threats[0] || 'malicious'}`
              : `QR decoded URL: ${decoded.substring(0, 60)}`
          });

          if (isMalicious) qrThreats.push({ decoded, scanResult });

          // Update image visual to reflect threat status
          img.style.outline = isMalicious ? '3px solid #dc2626' : '3px solid #22c55e';
          img.title = isMalicious
            ? `PhishAlert: DANGEROUS QR CODE — ${decoded.substring(0, 80)}`
            : `PhishAlert: QR code scanned — ${decoded.substring(0, 80)}`;

          // Inject in-email QR alert badge for critical threats
          if (isMalicious) {
            const alertEl = document.createElement('div');
            alertEl.style.cssText = 'display:flex;align-items:flex-start;gap:8px;background:#fef2f2;border:2px solid #dc2626;border-radius:6px;padding:8px 12px;margin:4px 0;font-size:12px;font-family:-apple-system,sans-serif;color:#7f1d1d';
            alertEl.innerHTML = `${window.paIcon('critical', '#dc2626')}
              <span><strong>PhishAlert: Dangerous QR code!</strong><br>
              Decoded URL: <code style="word-break:break-all">${paEsc(decoded.substring(0, 120))}</code><br>
              ${threats.map(t => `<span style="display:inline-flex;align-items:center;gap:4px;color:#dc2626">${window.paIcon('warning', '#dc2626')} ${paEsc(t)}</span>`).join('<br>')}</span>`;
            img.parentNode?.insertBefore(alertEl, img.nextSibling);
          }
        }
        heuristicResult.qrCount = (heuristicResult.qrFindings || []).length;
      }
    }

    return { ...heuristicResult, qrScannedUrls, qrThreats };
  }

  // ─── PHASE 4: Attachment Scanning ────────────────────────────────────────
  function extractAttachments(emailContainer) {
    const attachments = [];
    // Combine all selectors: .aZo is the main attachment chip container in Gmail.
    // We only select the main containers to avoid double-counting child elements.
    const attachElements = emailContainer.querySelectorAll('.aZo, .aQH, .aQI');
    
    attachElements.forEach(el => {
      // Prioritize explicit download attribute, fallback to inner text
      let name = el.getAttribute('download');
      if (!name) {
        const nameEl = el.querySelector('.aV3, .aQA, span') || el;
        name = nameEl.textContent?.trim() || '';
      }
      
      // Enforce a strict file extension check (e.g. .zip, .docx)
      // This automatically filters out truncated Gmail labels like "Network Traffic F..."
      const extMatch = name.match(/\.([a-z0-9]{2,5})$/i);
      if (extMatch) {
        const ext = extMatch[1].toLowerCase();
        const skip = ['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'txt'];
        if (!skip.includes(ext)) {
          attachments.push({ fileName: name, mimeType: '', base64Data: null });
        }
      }
    });

    // Deduplicate by normalized filename
    // (Gmail sometimes has 'File Name.zip' in text but 'File_Name.zip' in download attribute)
    const unique = [];
    const seen = new Set();
    for (const att of attachments) {
      const normalized = att.fileName.toLowerCase().replace(/[^a-z0-9.]/g, '');
      if (!seen.has(normalized)) {
        seen.add(normalized);
        unique.push(att);
      }
    }
    return unique;
  }

  async function scanAttachments(emailContainer) {
    const attachments = extractAttachments(emailContainer);
    if (attachments.length === 0) return [];
    const results = await Promise.all(
      attachments.map(a => bg('SCAN_ATTACHMENT', { fileName: a.fileName, mimeType: a.mimeType, base64Data: a.base64Data }))
    );
    return results.filter(Boolean);
  }

  // ─── Gmail: fetch this message's real headers ("Show original") ──────────
  // DNS alone can never confirm DKIM (the selector is chosen by the sender, e.g. Google's
  // dated "20251104"). Gmail's own Authentication-Results header has the real verdict, so
  // we fetch the raw message same-origin (uses the user's session; nothing leaves Gmail
  // except the header block we hand to our own background worker). Best-effort: any failure
  // returns null and the caller falls back to the DNS-only check.
  let _gmailIk = null;
  function findGmailIk() {
    if (_gmailIk) return _gmailIk;
    try {
      const a = document.querySelector('a[href*="ik="]');
      let m = a && a.getAttribute('href').match(/[?&;]ik=([0-9a-f]{6,})/i);
      if (m) return (_gmailIk = m[1]);
      for (const sc of document.scripts) {
        const t = sc.textContent || '';
        if (!t) continue;
        m = t.match(/[?&;\\u0026]ik=([0-9a-f]{6,})/i) || t.match(/["']ik["']\s*[:,]\s*["']([0-9a-f]{6,})["']/i);
        if (m) return (_gmailIk = m[1]);
        const g = t.match(/GLOBALS\s*=\s*\[([\s\S]{0,4000}?)\]/);
        if (g) {
          const parts = g[1].split(',');
          const v = (parts[9] || '').replace(/["'\s]/g, '');
          if (/^[0-9a-f]{6,}$/i.test(v)) return (_gmailIk = v);
        }
      }
    } catch (e) { /* ignore */ }
    return null;
  }

  const _rawHeaderCache = new Map();   // legacy message id -> header block | null
  // Inbox lists can have 50 rows; keep Gmail requests to 3 at a time.
  let _hdrActive = 0;
  const _hdrWaiters = [];
  async function _hdrAcquire() {
    if (_hdrActive < 3) { _hdrActive++; return; }
    await new Promise(r => _hdrWaiters.push(r));
  }
  function _hdrRelease() {
    const next = _hdrWaiters.shift();
    if (next) next(); else _hdrActive--;
  }

  async function getGmailRawHeaders(legacyId) {
    if (!legacyId || !/^[0-9a-f]+$/i.test(legacyId)) return null;
    if (_rawHeaderCache.has(legacyId)) return _rawHeaderCache.get(legacyId);
    const p = (async () => {
      await _hdrAcquire();
      try {
        const ik = findGmailIk();
        if (!ik) return null;
        const um = (location.pathname.match(/\/mail\/u\/(\d+)/) || [])[1] || '0';
        const url = `https://mail.google.com/mail/u/${um}/?ik=${ik}&view=om&th=${legacyId}`;
        const ctl = new AbortController();
        const timer = setTimeout(() => ctl.abort(), 8000);
        try {
          const resp = await fetch(url, { credentials: 'include', signal: ctl.signal });
          if (!resp.ok || !resp.body) return null;
          // Stream only until the blank line ending the header block, then stop: the full
          // raw message can be megabytes when it carries attachments.
          const reader = resp.body.getReader();
          const dec = new TextDecoder();
          let text = '';
          while (text.length < 100000) {
            const { done, value } = await reader.read();
            if (done) break;
            text += dec.decode(value, { stream: true });
            if (/\r?\n\r?\n/.test(text)) break;
          }
          try { reader.cancel(); } catch (e) { /* ignore */ }
          const end = text.search(/\r?\n\r?\n/);
          const block = (end > 0 ? text.slice(0, end) : text).slice(0, 100000);
          return /^authentication-results:/im.test(block) ? block : null;
        } finally { clearTimeout(timer); }
      } catch (e) { return null; }
      finally { _hdrRelease(); }
    })();
    _rawHeaderCache.set(legacyId, p);   // cache the promise so concurrent callers share one fetch
    p.then(function (v) { if (!v) _rawHeaderCache.delete(legacyId); });   // a failed fetch must be retried, not remembered
    return p;
  }

  // Header block belongs to this sender? (From: must contain the displayed address.)
  function paHeadersFromSender(block, senderEmail) {
    if (!block || !senderEmail) return false;
    const m = block.match(/^from:[^\n]*(?:\n[ \t][^\n]*)*/im);
    return !!m && m[0].toLowerCase().includes(senderEmail.toLowerCase());
  }

  // Headers for the message being viewed. In a conversation the pane can carry the id of a
  // different message (your own reply, a deleted one) — those have no Authentication-Results, the
  // fetch returns null and the score silently degraded to DNS-only (68 instead of 81 for the same
  // sender). Try the primary id, then the other messages in the thread, and accept only a header
  // block whose From: is this sender so another participant's verdict is never borrowed.
  async function getHeadersForSender(primaryId, senderEmail) {
    const tried = new Set();
    const candidates = [primaryId];
    document.querySelectorAll('[data-legacy-message-id]').forEach(el => {
      const id = el.getAttribute('data-legacy-message-id');
      if (id && !candidates.includes(id)) candidates.push(id);
    });
    for (const id of candidates.slice(0, 6)) {
      if (!id || tried.has(id)) continue;
      tried.add(id);
      const block = await getGmailRawHeaders(id);
      if (block && (id === primaryId ? true : paHeadersFromSender(block, senderEmail))) {
        // For the primary id keep the old behaviour only if the From matches too.
        if (paHeadersFromSender(block, senderEmail)) return { block, id };
      }
    }
    return { block: null, id: primaryId };
  }

  // ─── SPF / DKIM / DMARC Checks (UPGRADE 1: real DNS via background) ─────────
  // Single batched call — background caches results in chrome.storage.local.
  // rawHeaders (optional) layers the receiving server's real per-message verdict on top.
  async function checkEmailAuth(domain, rawHeaders) {
    const result = await bg('VERIFY_EMAIL_AUTH', rawHeaders ? { domain, rawHeaders } : { domain });
    if (!result) {
      return {
        spf: { pass: false, detail: 'Auth check failed' },
        dkim: { pass: false, detail: 'Auth check failed' },
        dmarc: { pass: false, policy: null, detail: 'Auth check failed' }
      };
    }
    return result;
  }

  // Legacy wrappers kept for internal use (now backed by batched real DNS)
  async function checkSPF(domain) {
    const auth = await checkEmailAuth(domain);
    return auth.spf;
  }

  async function checkDKIM(domain) {
    const auth = await checkEmailAuth(domain);
    return auth.dkim;
  }

  async function checkDMARC(domain) {
    const auth = await checkEmailAuth(domain);
    return auth.dmarc;
  }

  // ─── PHASE 1: WHOIS / RDAP Domain Age ────────────────────────────────────
  async function checkDomainAge(domain) {
    if (TRUSTED_DOMAINS.has(domain)) {
      return { ageInDays: 9999, isNew: false, detail: 'Known trusted domain', score: 15 };
    }

    const rdap = await bg('RDAP_AGE', { domain });

    if (rdap.error || rdap.ageInDays === null) {
      // Fallback: check MX and A records as proxy for legitimacy
      const mx = await bg('DNS_LOOKUP', { name: domain, recordType: 'MX' });
      const hasMX = mx?.Answer?.length > 0;
      return {
        ageInDays: null,
        isNew: false,
        detail: hasMX ? 'Age unknown, MX exists' : 'Age unknown',
        score: hasMX ? 8 : 4
      };
    }

    const isNew = rdap.ageInDays < 180; // Less than 6 months old = suspicious
    const isVeryNew = rdap.ageInDays < 30;

    let score = 15;
    if (isVeryNew) score = 0;
    else if (isNew) score = 5;
    else if (rdap.ageInDays < 365) score = 10;

    const years = Math.floor(rdap.ageInDays / 365);
    const months = Math.floor((rdap.ageInDays % 365) / 30);
    const ageStr = years > 0
      ? `${years}y ${months}m old`
      : `${months} month${months !== 1 ? 's' : ''} old`;

    return {
      ageInDays: rdap.ageInDays,
      registrationDate: rdap.registrationDate,
      isNew,
      isVeryNew,
      detail: ageStr,
      score
    };
  }

  // ─── Domain Reputation Heuristics ────────────────────────────────────────
  async function checkReputation(domain) {
    if (TRUSTED_DOMAINS.has(domain)) return { score: 15, detail: 'Known trusted domain' };

    let score = 0;
    const details = [];

    const mx = await bg('DNS_LOOKUP', { name: domain, recordType: 'MX' });
    if (mx?.Answer?.length > 0) { score += 7; details.push('MX records exist'); }

    const a = await bg('DNS_LOOKUP', { name: domain, recordType: 'A' });
    if (a?.Answer?.length > 0) { score += 5; details.push('A record exists'); }

    const base = getDomainBase(domain);
    if (base.length <= 20) { score += 3; }

    // Suspicious patterns
    const badPatterns = [
      /\d{4,}/, /[-]{2,}/, /paypa[^l]/, /arnazon/, /micros0ft/,
      /g00gle/, /secure.*login/, /account.*verify/, /update.*info/,
      /confirm.*password/, /bank.*security/
    ];
    if (badPatterns.some(p => p.test(domain))) {
      score = Math.max(0, score - 8);
      details.push('Suspicious pattern');
    }

    return { score: Math.min(score, 15), detail: details.join(', ') || 'Unknown' };
  }

  // ─── PHASE 3: VirusTotal Check ────────────────────────────────────────────
  async function checkVirusTotal(domain) {
    return await bg('VIRUSTOTAL_CHECK', { domain });
  }

  // ─── PHASE 3: Community Reports ───────────────────────────────────────────
  async function checkCommunityReports(domain) {
    return await bg('COMMUNITY_CHECK', { domain });
  }

  // ─── Master Scoring Function ──────────────────────────────────────────────
  // extra = { replyTo, subject, body, threadId } — all optional
  async function scoreDomain(domain, senderStr, extra = {}) {
    // ── WHITELIST GATE: check FIRST, before cache or any scoring ────────────
    // Whitelisted domains always score 100 and show a green "Verified" badge.
    // We also overwrite any stale cache entry so the change is instant.
    const wlCheck = await bg('WHITELIST_CHECK', { domain }).catch(() => ({ whitelisted: false }));
    if (wlCheck?.whitelisted) {
      const whitelistedResult = {
        domain,
        score: 100,
        isTrusted: true,
        whitelisted: true,
        checks: {
          spf:        { pass: true, strict: true,  detail: 'Whitelisted by you — skipped' },
          dkim:       { pass: true,                detail: 'Whitelisted by you — skipped' },
          dmarc:      { pass: true, policy: 'reject', detail: 'Whitelisted by you — skipped' },
          mx:         { hasMX: true, suspicious: false, detail: 'Whitelisted domain' },
          age:        { ageInDays: 9999, isNew: false, isVeryNew: false, detail: 'Whitelisted domain', score: 15 },
          reputation: { score: 15, detail: 'Whitelisted by you' },
          vt:         { available: false, skipped: true, reason: 'Whitelisted domain' },
          community:  null,
          dnsbl:      null
        },
        threats: {
          displayNameSpoof:  { spoofing: false },
          homograph:         { detected: false },
          punycode:          { suspicious: false },
          bimi:              null,
          replyToMismatch:   null,
          urgency:           null,
          contactLookalike:  null
        },
        threatList: [],
        senderStr, displayName: extractDisplayName(senderStr),
        senderHistory: null
      };
      // Overwrite any stale cached entry so whitelisting takes effect immediately
      const cacheKey2 = extra.replyTo ? `${domain}::rt` : domain;
      domainCache.set(cacheKey2, whitelistedResult);
      // FIX: SAVE_CURRENT_SCAN removed from here — scoreDomain() is shared by
      // inbox-list badge scanning (processInboxSenderSpan/processInboxYPSpan),
      // and every list-row scan was clobbering the single global
      // phishalert_current_scan record, which the popup's Threats &
      // Forensics tab (and the canary deployment lookup) reads via
      // GET_LAST_SCAN. "Current scan" is now only ever set from
      // injectBadge(), for the message actually open in the reading pane.
      return whitelistedResult;
    }

    // Cache key now includes replyTo so different reply-to headers are re-evaluated
    // Per-message headers make the auth verdict message-specific, so cache by message then.
    // Free-mail: one domain hosts millions of unrelated people, so cache per ADDRESS, never per
    // domain (otherwise the first gmail sender's score and history are served for every other one).
    const isFreemail = paIsFreemail(domain);
    const addrKey = isFreemail ? (paAddrOf(senderStr) || domain) : domain;
    const baseKey = extra.replyTo ? `${addrKey}::rt` : addrKey;
    const hasLinks = Array.isArray(extra.linkHrefs) && extra.linkHrefs.length > 0;
    const messageSpecific = !!(extra.msgKey && (extra.rawHeaders || hasLinks));
    const cacheKey = messageSpecific ? `${baseKey}::m${extra.msgKey}` : baseKey;
    if (domainCache.has(cacheKey)) return domainCache.get(cacheKey);

    const displayName = extractDisplayName(senderStr);

    // Run auth + remaining checks in parallel (including MX and punycode)
    // FEATURES 10-13: new checks run in same parallel batch so no extra latency
    let [
      authResult, ageResult, reputation, vtResult, communityReport,
      homograph, senderHistory, punycodeResult,
      replyToResult, urgencyResult, contactLookalikeResult, dnsblResult
    ] = await Promise.all([
      checkEmailAuth(domain, extra.rawHeaders),
      checkDomainAge(domain),
      checkReputation(domain),
      checkVirusTotal(domain),
      checkCommunityReports(domain),
      Promise.resolve(checkHomograph(domain)),
      getSenderTrustBonus(senderStr),
      checkPunycode(domain),                          // FEATURE 3
      // FEATURE 10: Reply-To mismatch (only if replyTo is available)
      extra.replyTo
        ? bg('CHECK_REPLY_TO', { from: senderStr, replyTo: extra.replyTo })
          .catch(() => ({ mismatch: false }))
        : Promise.resolve({ mismatch: false }),
      // FEATURE 11: Urgency keyword scoring (local, no API — always fast)
      (extra.subject || extra.body)
        ? bg('URGENCY_SCORE', { subject: extra.subject || '', body: extra.body || '' })
          .catch(() => ({ score: 0, matched: [] }))
        : Promise.resolve({ score: 0, matched: [] }),
      // FEATURE 12: Contact lookalike domain check
      bg('CHECK_CONTACT_LOOKALIKE', { domain })
        .catch(() => ({ lookalike: false })),
      // FEATURE 13: DNS Blacklist check
      bg('DNSBL_CHECK', { domain })
        .catch(() => ({ checked: false, listed: false }))
    ]);

    if (isFreemail) {
      ageResult = Object.assign({}, ageResult, { score: 0, isNew: false, isVeryNew: false,
        detail: 'Free-mail provider — the provider\'s age says nothing about this sender' });
      reputation = Object.assign({}, reputation, { score: 0,
        detail: 'Free-mail provider — provider reputation does not apply to individual senders' });
    }
    const spf = authResult.spf;
    const dkim = authResult.dkim;
    const dmarc = authResult.dmarc;
    let mx = authResult.mx;  // FEATURE 1
    // If the receiving server verified this exact message as DMARC-aligned with the From domain,
    // a missing MX proves nothing (a spoofer cannot pass DMARC) — never treat it as critical.
    if (mx?.suspicious && authResult.authSource === 'message' && authResult.dmarc?.pass &&
        authResult.messageAuth?.dmarc?.aligned !== false) {
      mx = Object.assign({}, mx, { suspicious: false, detail: 'No MX on this host, but the receiving server verified DMARC for this message' });
    }

    // Display name spoofing (sync)
    const displayNameSpoof = detectDisplayNameSpoofing(displayName, senderStr);

    let score = 0;
    if (spf.pass) score += spf.strict ? WEIGHTS.spf : WEIGHTS.spf * 0.7;
    else if (spf.status === 'unaligned') score += WEIGHTS.spf * 0.3;      // passed, but for a third-party domain
    if (dkim.pass) score += WEIGHTS.dkim;
    else if (dkim.inconclusive) score += WEIGHTS.dkim * 0.5;   // unknown ≠ fail: DKIM selectors can't be guessed from DNS
    else if (dkim.status === 'google-default') score += WEIGHTS.dkim * 0.8;
    else if (dkim.status === 'unaligned') score += WEIGHTS.dkim * 0.4;    // valid signature, signed by a bulk-mail/ESP domain
    if (dmarc.pass) {
      if (dmarc.policy === 'reject') score += WEIGHTS.dmarc;
      else if (dmarc.policy === 'quarantine') score += WEIGHTS.dmarc * 0.8;
      else score += WEIGHTS.dmarc * 0.4;
    }
    score += ageResult.score;
    score += reputation.score;

    // ── Track all applied score adjustments (penalties + bonuses) for UI transparency ───────────────────
    const scoreDeductions = [];

    // Sender history trust bonus (max +20 for frequent contacts)
    if (senderHistory?.trustBonus) {
      const bonus = Math.min(senderHistory.trustBonus, 20);
      score += bonus;
      scoreDeductions.push({ label: 'Frequent sender trust bonus', points: bonus, icon: '🌟' });
    }

    // Penalties
    if (ageResult.isVeryNew) { score = Math.max(0, score - 25); scoreDeductions.push({ label: 'Very new domain (< 30 days)', points: -25, icon: '🆕' }); }
    else if (ageResult.isNew) { score = Math.max(0, score - 10); scoreDeductions.push({ label: 'New domain (< 6 months)', points: -10, icon: '📅' }); }

    if (displayNameSpoof.spoofing) { score = Math.max(0, score - 30); scoreDeductions.push({ label: 'Display name spoofing', points: -30, icon: '🎭' }); }
    if (homograph.detected) { score = Math.max(0, score - 35); scoreDeductions.push({ label: 'Homograph / lookalike characters', points: -35, icon: '🔤' }); }

    // FEATURE 1: No MX records = strong phishing signal
    if (mx && mx.suspicious) { score = Math.max(0, score - 20); scoreDeductions.push({ label: 'No MX records (send-only domain)', points: -20, icon: '📭' }); }

    // FEATURE 3: Punycode domain = very suspicious
    if (punycodeResult?.suspicious) { score = Math.max(0, score - 30); scoreDeductions.push({ label: 'Punycode / IDN domain', points: -30, icon: '🔡' }); }

    // FEATURE 7: BIMI — missing BIMI on a major brand = phishing signal
    // Skip when the receiving server confirmed this exact message passed DMARC aligned with
    // the From domain: a spoofer cannot pass that, so a missing BIMI record proves nothing.
    const msgAuthClean = authResult.authSource === 'message' && authResult.dmarc?.pass &&
      authResult.messageAuth?.dmarc?.aligned !== false;
    let bimiResult = authResult.bimi || null;
    if (bimiResult?.isImpersonatingBrand && msgAuthClean) {
      bimiResult = Object.assign({}, bimiResult, { isImpersonatingBrand: false, claimedBrand: null });
    }
    if (bimiResult?.isImpersonatingBrand) {
      score = Math.max(0, score - 20);
      scoreDeductions.push({ label: `No BIMI record — impersonating ${bimiResult.claimedBrand}`, points: -20, icon: '🏷️' });
    }

    // VirusTotal penalty
    if (vtResult?.available && vtResult.isMalicious) {
      score = Math.max(0, score - 40);
      scoreDeductions.push({ label: `VirusTotal: flagged by ${vtResult.maliciousCount} engines`, points: -40, icon: '🦠' });
    }

    // Community report penalty
    if (communityReport && communityReport.count >= 3) {
      score = Math.max(0, score - 20);
      scoreDeductions.push({ label: `Community-reported phishing (${communityReport.count}×)`, points: -20, icon: '🚩' });
    }

    // ── FEATURE 10: Reply-To mismatch penalty ──────────────────────────────
    if (replyToResult?.mismatch) {
      score = Math.max(0, score - 25);
      scoreDeductions.push({ label: `Reply-To routes to different domain (${replyToResult.replyToDomain})`, points: -25, icon: '↩️' });
    }

    // ── FEATURE 11: Urgency keyword penalty ────────────────────────────────
    if (urgencyResult?.isHighRisk) {
      score = Math.max(0, score - 20);
      scoreDeductions.push({ label: `High-pressure urgency language: "${urgencyResult.matched?.slice(0, 2).join('", "')}"`, points: -20, icon: '⏰' });
    } else if (urgencyResult?.isMediumRisk) {
      score = Math.max(0, score - 10);
      scoreDeductions.push({ label: `Urgency keywords detected: "${urgencyResult.matched?.slice(0, 2).join('", "')}"`, points: -10, icon: '⏰' });
    }

    // ── FEATURE 12: Contact lookalike penalty ──────────────────────────────
    if (contactLookalikeResult?.lookalike) {
      const penalty = contactLookalikeResult.severity === 'high' ? 30 : 18;
      score = Math.max(0, score - penalty);
      scoreDeductions.push({ label: `Lookalike of a domain you email (${contactLookalikeResult.targetDomain})`, points: -penalty, icon: '🎭' });
    }

    // ── Link content penalty ────────────────────────────────────────────────
    // The links inside THIS message. Previously link findings were drawn next to each link but
    // never reached the score, so a scam link could sit under an 81 "Likely safe" badge.
    // Plain "link goes to another domain" is only penalised for free-mail senders (no brand
    // domain to compare against); for company senders it stays a per-link warning because
    // legitimate mail routinely links to tracking/CDN hosts.
    let linkFinding = null;
    if (hasLinks) {
      const seen = new Set();
      for (const href of extra.linkHrefs.slice(0, 40)) {
        if (!href || seen.has(href)) continue;
        seen.add(href);
        let r;
        try { r = isSuspiciousLink(href, domain); } catch (e) { continue; }
        if (!r || !r.suspicious) continue;
        const crossDomainOnly = /^Link goes to/.test(r.reason || '');
        if (r.critical || !crossDomainOnly || isFreemail) {
          if (!linkFinding || r.critical) linkFinding = { reason: r.reason, linkDomain: r.linkDomain, critical: !!r.critical };
          if (r.critical) break;
        }
      }
      if (linkFinding) {
        const pen = linkFinding.critical ? 40 : 25;
        score = Math.max(0, score - pen);
        scoreDeductions.push({ label: `Suspicious link: ${linkFinding.reason}`, points: -pen, icon: '🔗' });
      }
    }

    // ── FEATURE 13: DNSBL blacklist penalty ────────────────────────────────
    if (dnsblResult?.listed) {
      const penalty = dnsblResult.listings?.length >= 2 ? 35 : 20;
      score = Math.max(0, score - penalty);
      scoreDeductions.push({ label: `IP blacklisted: ${dnsblResult.listings?.map(l => l.source).join(', ')}`, points: -penalty, icon: '🚫' });
    }

    const finalScore = Math.min(Math.round(score), 100);
    const isTrusted = finalScore >= THRESHOLD_GREEN &&
      !displayNameSpoof.spoofing && !homograph.detected && !punycodeResult?.suspicious &&
      !replyToResult?.mismatch && !contactLookalikeResult?.lookalike; // FEAT 10 & 12

    const result = {
      domain, score: finalScore, isTrusted,
      authSource: authResult.authSource || 'dns',
      scoreDeductions, // ← penalty list for UI transparency
      checks: {
        spf, dkim, dmarc, mx,
        age: ageResult, reputation, vt: vtResult, community: communityReport,
        dnsbl: dnsblResult || null
      },
      threats: {
        displayNameSpoof, homograph, punycode: punycodeResult, bimi: bimiResult,
        replyToMismatch: replyToResult?.mismatch ? replyToResult : null,
        urgency: urgencyResult?.score > 0 ? urgencyResult : null,
        contactLookalike: contactLookalikeResult?.lookalike ? contactLookalikeResult : null
      },
      senderStr, displayName, senderHistory,
      freemail: isFreemail,
      linkFinding,
      messageSpecific: messageSpecific || !!linkFinding
    };

    // Also cache under plain domain key so inbox badge & open-email badge stay in sync
    // A result built from one message's headers must not become the domain-wide answer:
    // a forged mail from the same domain would otherwise inherit this message's DKIM pass.
    // Never for free-mail (per-address) or when a link finding made the result message-specific.
    if (!extra.rawHeaders && !isFreemail && !linkFinding) domainCache.set(domain, result);
    domainCache.set(cacheKey, result);

    // Build the full log/scan entry
    const logEntry = {
      domain, score: finalScore, isTrusted,
      sender: senderStr,
      senderHistory,
      checks: {
        spf: { pass: spf.pass, detail: spf.detail },
        dkim: { pass: dkim.pass, inconclusive: !!dkim.inconclusive, detail: dkim.detail },
        dmarc: { pass: dmarc.pass, detail: dmarc.detail, policy: dmarc.policy },
        mx: mx || null,
        age: { ageInDays: ageResult.ageInDays, isNew: ageResult.isNew, detail: ageResult.detail, score: ageResult.score },
        reputation: { score: reputation.score, detail: reputation.detail },
        vt: vtResult || null,
        urlhaus: authResult?.urlhaus || null,
        bimi: bimiResult || null,
        community: communityReport || null,
        dnsbl: dnsblResult || null
      },
      threats: {
        displayNameSpoof, homograph, punycode: punycodeResult, bimi: bimiResult,
        replyToMismatch: replyToResult?.mismatch ? replyToResult : null,
        urgency: urgencyResult?.score > 0 ? urgencyResult : null,
        contactLookalike: contactLookalikeResult?.lookalike ? contactLookalikeResult : null
      },
      threatList: [
        displayNameSpoof.spoofing ? 'Display name spoofing' : null,
        homograph.detected ? `${homograph.type}: ${homograph.targetBrand}` : null,
        punycodeResult?.suspicious ? `Punycode IDN: ${punycodeResult.detail}` : null,
        mx?.suspicious ? 'No MX records — send-only domain' : null,
        vtResult?.isMalicious ? 'VirusTotal: Malicious' : null,
        bimiResult?.isImpersonatingBrand ? `BIMI: No record — likely impersonating ${bimiResult.claimedBrand}` : null,
        communityReport?.count >= 3 ? `Reported ${communityReport.count}x` : null,
        // FEATURES 10-13
        replyToResult?.mismatch ? `Reply-To mismatch: ${replyToResult.detail}` : null,
        urgencyResult?.isHighRisk ? `High urgency: ${urgencyResult.matched.slice(0, 2).join(', ')}` : null,
        urgencyResult?.isMediumRisk ? `Urgency signals: ${urgencyResult.matched.slice(0, 2).join(', ')}` : null,
        contactLookalikeResult?.lookalike ? `Lookalike domain: ${contactLookalikeResult.detail}` : null,
        dnsblResult?.listed ? `DNSBL: ${dnsblResult.detail}` : null
      ].filter(Boolean)
    };

    // FIX: SAVE_CURRENT_SCAN removed from here — see note above the
    // whitelisted-domain branch of scoreDomain() for why. SAVE_SCAN_LOG stays;
    // it's an append-only history and isn't what the Investigation tab reads.
    bg('SAVE_SCAN_LOG', { entry: { ...logEntry, threats: logEntry.threatList } });

    return result;
  }

  // ─── PHASE 2: Link Scanner ────────────────────────────────────────────────
  function isSuspiciousLink(href, senderDomain) {
    // FEATURE 5: javascript: and data: URI detection — always critical
    const dangerousURI = checkDangerousURI(href);
    if (dangerousURI.dangerous) {
      return { suspicious: true, critical: true, reason: dangerousURI.detail, linkDomain: '' };
    }

    if (!href || !href.startsWith('http')) return { suspicious: false };

    try {
      const url = new URL(href);
      const linkDomain = url.hostname.toLowerCase();

      // FEATURE 3: Punycode check on link domain (sync part — full check done async in scanLinksInEmail)
      if (linkDomain.includes('xn--')) {
        return { suspicious: true, reason: `Punycode domain detected: "${linkDomain}" — may be IDN spoofing`, linkDomain };
      }

      // Homograph check on link domain
      const homograph = checkHomograph(linkDomain);
      if (homograph.detected) {
        return { suspicious: true, reason: `Homograph: mimics "${homograph.targetBrand}"`, linkDomain };
      }

      // Domain mismatch: link domain differs from sender domain
      const senderBase = getDomainBase(senderDomain || '');
      const linkBase = getDomainBase(linkDomain);
      if (senderDomain && senderBase && linkBase !== senderBase && !TRUSTED_DOMAINS.has(linkDomain)) {
        const allowedCDNs = ['googleapis.com', 'gstatic.com', 'cloudfront.net', 'akamai.com',
          'fastly.net', 'cdn.com', 'amazonaws.com', 'azure.com', 'cloudflare.com'];
        if (!allowedCDNs.some(cdn => linkDomain.includes(cdn))) {
          return {
            suspicious: true,
            reason: `Link goes to "${linkDomain}", not sender's domain "${senderDomain}"`,
            linkDomain
          };
        }
      }

      // Suspicious URL patterns
      const suspiciousPatterns = [
        /login.*verify/i, /account.*suspend/i, /update.*payment/i,
        /confirm.*identity/i, /secure.*signin/i, /verify.*account/i
      ];
      const fullUrl = href.toLowerCase();
      for (const pat of suspiciousPatterns) {
        if (pat.test(fullUrl)) {
          return { suspicious: true, reason: 'Suspicious URL pattern detected', linkDomain };
        }
      }

      return { suspicious: false, linkDomain };
    } catch (e) {
      return { suspicious: false };
    }
  }

  // Inject link scanning badges on all links in an email
  async function scanLinksInEmail(container, senderDomain, senderEmail) {
    window.paSetLinkGuardSender && window.paSetLinkGuardSender(senderDomain); // FEATURE NEW 3: Active Link Protection
    const links = container.querySelectorAll('a[href]');

    // ── FEATURE 6: Google Safe Browsing — batch scan ALL links upfront ──────
    const allHrefs = [...links]
      .map(l => l.getAttribute('href'))
      .filter(h => h && h.startsWith('http'));

    let gsbMatches = new Set(); // set of malicious URLs
    if (allHrefs.length > 0) {
      bg('GSB_CHECK', { urls: allHrefs }).then(gsbResult => {
        if (gsbResult?.isMalicious) {
          gsbResult.matches.forEach(m => m.url && gsbMatches.add(m.url));
          // Retroactively upgrade badges for any already-rendered links
          for (const link of links) {
            const href = link.getAttribute('href');
            if (href && gsbMatches.has(href)) {
              const existingBadge = link.nextSibling;
              if (existingBadge?.classList?.contains('pa-link-badge')) {
                existingBadge.className = 'pa-link-badge pa-link-critical';
                existingBadge.innerHTML = window.paIcon('critical', '#dc2626');
                existingBadge.title = `PhishAlert CRITICAL (Google Safe Browsing): This URL is flagged as malicious`;
              }
            }
          }
        }
      });
    }

    for (const link of links) {
      if (link.dataset.phishalertScanned) continue;
      link.dataset.phishalertScanned = 'true';

      const href = link.getAttribute('href');
      if (!href || href.startsWith('mailto:') || href.startsWith('#')) continue;

      // FEATURE 5: javascript:/data: URI — always flag immediately, no further checks
      const dangerousURI = checkDangerousURI(href);
      if (dangerousURI.dangerous) {
        const linkBadge = document.createElement('span');
        linkBadge.className = 'pa-link-badge pa-link-critical';
        linkBadge.innerHTML = window.paIcon('critical', '#dc2626');
        linkBadge.title = `PhishAlert CRITICAL: ${dangerousURI.detail}`;
        linkBadge.addEventListener('click', (e) => {
          e.preventDefault(); e.stopPropagation();
          showLinkPreview(link, { originalUrl: href, finalUrl: href, wasShortened: false },
            { suspicious: true, critical: true, reason: dangerousURI.detail }, senderEmail);
        });
        link.parentNode?.insertBefore(linkBadge, link.nextSibling);
        continue;
      }

      // Check if shortened URL
      const shortenerDomains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
        'dlvr.it', 'ift.tt', 'tiny.cc', 'is.gd', 'su.pr', 'snip.ly'];
      const isShortened = shortenerDomains.some(d => href.includes(d));

      const suspicion = isSuspiciousLink(href, senderDomain);

      // FEATURE 4: Link text vs URL mismatch
      const anchorText = link.textContent || link.innerText || '';
      const textMismatch = checkLinkTextMismatch(anchorText, href);
      if (textMismatch.mismatch && !suspicion.suspicious) {
        suspicion.suspicious = true;
        suspicion.reason = textMismatch.detail;
        suspicion.textMismatch = true;
      }

      // FEATURE 6: OpenPhish / protocol check (async, don't block rendering)
      if (suspicion.suspicious || isShortened) {
        // Fire OpenPhish check in background, update badge if result comes back positive
        bg('URLHAUS_CHECK', { url: href }).then(phishResult => { // v5 upgraded to URLhaus
          if (phishResult?.malicious) {
            const existingBadge = link.nextSibling;
            if (existingBadge?.classList?.contains('pa-link-badge')) {
              existingBadge.className = 'pa-link-badge pa-link-critical';
              existingBadge.innerHTML = window.paIcon('critical', '#dc2626');
              existingBadge.title = `PhishAlert CRITICAL (URLhaus): ${phishResult.threat}`;
            }
          }
        });
      }

      if (suspicion.suspicious || isShortened) {
        const isCritical = suspicion.critical;
        const linkBadge = document.createElement('span');
        linkBadge.className = isCritical ? 'pa-link-badge pa-link-critical'
          : isShortened ? 'pa-link-badge pa-link-shortened' : 'pa-link-badge pa-link-warn';
        linkBadge.innerHTML = isCritical ? window.paIcon('critical', '#dc2626')
          : isShortened ? window.paIcon('link', '#3b82f6') : window.paIcon('warning', '#d97706');
        linkBadge.title = isCritical ? `PhishAlert CRITICAL: ${suspicion.reason}`
          : isShortened ? 'PhishAlert: Shortened URL — click to preview destination'
            : `PhishAlert: ${suspicion.reason}`;

        if (isShortened) {
          linkBadge.addEventListener('click', async (e) => {
            e.preventDefault(); e.stopPropagation();
            linkBadge.innerHTML = '···';
            const result = await bg('UNSHORT_URL', { url: href });
            linkBadge.innerHTML = window.paIcon('link', '#3b82f6');
            showLinkPreview(link, result, suspicion, senderEmail);
          });
        } else {
          linkBadge.addEventListener('click', (e) => {
            e.preventDefault(); e.stopPropagation();
            showLinkPreview(link, { originalUrl: href, finalUrl: href, wasShortened: false }, suspicion, senderEmail);
          });
        }

        link.parentNode?.insertBefore(linkBadge, link.nextSibling);
      }
    }
  }

  function showLinkPreview(anchorEl, urlResult, suspicion, senderEmail) {
    document.querySelectorAll('.pa-link-preview').forEach(p => p.remove());

    const panel = document.createElement('div');
    panel.className = 'pa-link-preview';

    const isSuspicious = suspicion.suspicious || (urlResult.wasShortened && urlResult.finalUrl !== urlResult.originalUrl);
    // Destination comes from the email (or a redirect chain): escape for display and
    // only ever allow http(s) in the clickable href.
    const _dest = urlResult.finalUrl || urlResult.originalUrl || '';
    const _safeHref = /^https?:\/\//i.test(_dest) ? _dest : '#';

    panel.innerHTML = `
      <div class="pa-lp-header ${isSuspicious ? 'warn' : 'info'}">
        <span>${isSuspicious ? window.paIcon('warning', '#fff') + ' Suspicious Link' : window.paIcon('link', '#fff') + ' Link Preview'}</span>
        <button class="pa-close">✕</button>
      </div>
      <div class="pa-lp-body">
        ${urlResult.wasShortened ? `<div class="pa-lp-row"><span>Original:</span><code>${paEsc(urlResult.originalUrl)}</code></div>` : ''}
        <div class="pa-lp-row"><span>Destination:</span><code>${paEsc(_dest)}</code></div>
        ${urlResult.limited ? `<div class="pa-lp-reason">${window.paIcon('link', '#6b7280')} Redirect-chain scanning is off — enable it in PhishAlert settings to see where shortened links actually lead.</div>` : ''}
        ${suspicion.suspicious ? `<div class="pa-lp-reason">${window.paIcon('warning', '#d97706')} ${paEsc(suspicion.reason)}</div>` : ''}
        <div class="pa-lp-actions">
          <button class="pa-btn-danger" onclick="void(0)">${window.paIcon('block', '#b91c1c')} Don't visit</button>
          <a href="${paEsc(_safeHref)}" target="_blank" rel="noopener noreferrer" class="pa-btn-proceed" data-pa-bypass="true">Continue anyway →</a>
        </div>
      </div>
    `;

    panel.querySelector('.pa-close').addEventListener('click', () => panel.remove());

    // Show blocked banner if this sender is already blocked
    bg('IS_BLOCKED', { email: senderEmail }).then(isBlocked => {
      if (isBlocked) {
        const banner = panel.querySelector('.pa-blocked-banner');
        if (banner) banner.style.display = 'block';
        const blockBtn = panel.querySelector('.pa-block-btn');
        if (blockBtn) { blockBtn.innerHTML = window.paIcon('check', 'currentColor') + ' Already Blocked'; blockBtn.disabled = true; }
      }
    });
    panel.querySelector('.pa-btn-danger').addEventListener('click', () => panel.remove());

    document.body.appendChild(panel);
    const rect = anchorEl.getBoundingClientRect();
    panel.style.top = `${rect.bottom + window.scrollY + 4}px`;
    panel.style.left = `${Math.max(10, Math.min(rect.left + window.scrollX, window.innerWidth - 320))}px`;

    setTimeout(() => {
      document.addEventListener('click', function h() {
        panel.remove();
        document.removeEventListener('click', h);
      });
    }, 100);
  }

  // ─── Shared 5-tier trust badge (replaces flat 🟢/⚠️/🚨 icon set) ──────────
  // FEATURE NEW: graded trust tiers with real iconography instead of raw
  // emoji, so the badge reflects the actual 0-100 score resolution instead
  // of collapsing everything into three buckets.
  const PA_TIERS = [
    { min: 90, key: 'trusted',    label: 'Trusted sender',    color: '#16a34a',
      svg: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.5-3 8-7 9-4-1-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>' },
    { min: 70, key: 'likely-safe', label: 'Likely safe',      color: '#2563eb',
      svg: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.5-3 8-7 9-4-1-7-4.5-7-9V6l7-3z"/></svg>' },
    { min: 45, key: 'suspicious', label: 'Suspicious sender', color: '#d97706',
      svg: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#d97706" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4l9 16H3L12 4z"/><path d="M12 10v4"/><path d="M12 17h.01"/></svg>' },
    { min: 20, key: 'high-risk',  label: 'High-risk sender',  color: '#ea580c',
      svg: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#ea580c" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.5-3 8-7 9-4-1-7-4.5-7-9V6l7-3z"/><path d="M9.5 9.5l5 5M14.5 9.5l-5 5"/></svg>' },
    { min: -1, key: 'critical',   label: 'Critical threat',   color: '#dc2626',
      svg: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#dc2626" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M8.5 3h7L21 8.5v7L15.5 21h-7L3 15.5v-7L8.5 3z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>' }
  ];
  function paTrustTier(score, forceCritical) {
    if (forceCritical) return PA_TIERS[PA_TIERS.length - 1];
    const s = typeof score === 'number' ? score : 50;
    return PA_TIERS.find(t => s >= t.min) || PA_TIERS[PA_TIERS.length - 1];
  }

  // ─── Two more badge states, kept separate from the trust-tier badge ──────
  // Whitelisted always scores 100, so before this it silently reused the
  // same "Trusted" tier icon as an algorithmically-high-scoring sender —
  // now it gets its own distinct icon so "you verified this" reads
  // differently from "the checks scored well". First-time sender is an
  // orthogonal signal (a first email can score anywhere 0-100), so it's
  // shown as an ADDITIONAL small badge next to the tier badge, driven by
  // an actual check against stored sender history rather than a guess.
  const PA_WHITELIST_BADGE = {
    label: 'Verified sender (whitelisted by you)', color: '#7c3aed',
    svg: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#7c3aed" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="5"/><path d="M9.5 8l1.5 1.5 3.5-3.5"/><path d="M8.5 12.5l-2.5 7.5 6-3 6 3-2.5-7.5"/></svg>'
  };
  const PA_FIRSTTIME_BADGE = {
    label: 'First-time sender — no prior history with this address', color: '#0891b2',
    svg: '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#0891b2" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="8" r="3.5"/><path d="M3 20c0-3.6 2.7-6 6-6s6 2.4 6 6"/><path d="M18 8v4"/><path d="M18 15h.01"/></svg>'
  };
  // Verification check: true only when the stored history for this exact
  // address shows zero prior replies AND zero prior sightings — not an
  // assumption, a lookup against phishalert_sender_history (see
  // getSenderTrustFromHistory in background.js).
  function paIsFirstTimeSender(result) {
    const sh = result && result.senderHistory;
    return !!sh && (sh.replyCount || 0) === 0 && (sh.seenCount || 0) === 0;
  }

  // ─── UI: Create email indicator badge ────────────────────────────────────
  // ONE definition of "critical" shared by the open-email badge and the inbox-list badge.
  // They used to differ (the list ignored No-MX / punycode / malware), so the same sender was
  // orange in the list and red once opened.
  function paIsCritical(result) {
    return !!(result.threats?.displayNameSpoof?.spoofing ||
      result.threats?.homograph?.detected ||
      result.threats?.punycode?.suspicious ||
      (result.checks?.vt?.available && result.checks?.vt?.isMalicious) ||
      result.checks?.mx?.suspicious ||
      result.threats?.malware);
  }

  function createBadge(result) {
    const group = document.createElement('span');
    group.className = 'phishalert-badge-group';
    group.dataset.domain = result.domain;

    const badge = document.createElement('span');
    badge.className = 'phishalert-badge';
    badge.dataset.domain = result.domain;

    const hasCriticalThreat = paIsCritical(result);

    if (hasCriticalThreat) {
      const tier = paTrustTier(result.score, true);
      badge.innerHTML = tier.svg;
      badge.className += ' pa-badge-critical';
      badge.title = 'PhishAlert: CRITICAL THREAT DETECTED — Click for details';
    } else if (result.whitelisted) {
      badge.innerHTML = PA_WHITELIST_BADGE.svg;
      badge.className += ' pa-badge-whitelisted';
      badge.title = `PhishAlert: ${PA_WHITELIST_BADGE.label} — Click for details`;
    } else {
      const tier = paTrustTier(result.score, false);
      badge.innerHTML = tier.svg;
      badge.title = `PhishAlert: ${tier.label} (score ${result.score}) — Click for details`;
    }

    badge.addEventListener('click', (e) => {
      e.stopPropagation();
      showDetailPanel(result, badge);
    });
    group.appendChild(badge);

    // Separate first-time-sender badge, only when not already covered by
    // a critical or whitelisted state (whitelisted senders have no
    // senderHistory lookup — see the whitelist gate above).
    if (!hasCriticalThreat && !result.whitelisted && paIsFirstTimeSender(result)) {
      const ftBadge = document.createElement('span');
      ftBadge.className = 'phishalert-badge phishalert-badge-firsttime';
      ftBadge.innerHTML = PA_FIRSTTIME_BADGE.svg;
      ftBadge.title = `PhishAlert: ${PA_FIRSTTIME_BADGE.label} — Click for details`;
      ftBadge.addEventListener('click', (e) => {
        e.stopPropagation();
        showDetailPanel(result, ftBadge);
      });
      group.appendChild(ftBadge);
    }

    return group;
  }

  // ─── Gmail Native Block Sender Trigger ───────────────────────────────────
  // Simulates clicking Gmail's built-in "Block [sender]" menu item.
  // Gmail's flow: open email → click ⋮ (More) button → click "Block [Name]"
  function triggerGmailBlockSender() {
    // The More (⋮) kebab menu button inside an open email
    // Gmail uses aria-label "More" on this button
    const moreSelectors = [
      'button[aria-label="More"]',
      'div[aria-label="More"]',
      '[data-tooltip="More"]',
      '.T-I.J-J5-Ji.T-I-Js-Gs.aap.T-I-awG'  // Gmail's internal class for more btn
    ];

    let moreBtn = null;
    for (const sel of moreSelectors) {
      // Only look inside the open email view, not the toolbar top
      const candidates = document.querySelectorAll(sel);
      for (const el of candidates) {
        // Must be inside the message action bar (not compose or top nav)
        if (el.closest('.iH, .ade, [gh="tm"]') || el.closest('.G-atb')) continue;
        moreBtn = el;
        break;
      }
      if (moreBtn) break;
    }

    if (!moreBtn) return false;

    // Click the More button to open the dropdown
    moreBtn.click();

    // Wait for the dropdown to render, then find and click "Block"
    setTimeout(() => {
      const menuItems = document.querySelectorAll('[role="menuitem"], .J-N, .aaq');
      for (const item of menuItems) {
        const text = item.textContent || '';
        if (/block\s/i.test(text)) {
          item.click();
          return;
        }
      }
      // If not found, close the menu and show fallback
      document.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
    }, 350);

    return true;
  }

  // ─── UI Helper: Make Element Draggable ────────────────────────────────────
  function makeDraggable(el, handleSelector) {
    const handle = el.querySelector(handleSelector) || el;
    let isDragging = false, startX, startY, initialX, initialY;

    handle.style.cursor = 'move';
    
    handle.addEventListener('mousedown', (e) => {
      // Don't drag if clicking a button or link
      if (e.target.tagName === 'BUTTON' || e.target.closest('button') || e.target.closest('a')) return;
      isDragging = true;
      startX = e.clientX;
      startY = e.clientY;
      const rect = el.getBoundingClientRect();
      initialX = rect.left;
      initialY = rect.top;
      
      el.style.position = 'fixed';
      el.style.left = initialX + 'px';
      el.style.top = initialY + 'px';
      el.style.right = 'auto';
      el.style.bottom = 'auto';
      el.style.margin = '0';
      el.style.transform = 'none';

      document.addEventListener('mousemove', onMouseMove);
      document.addEventListener('mouseup', onMouseUp);
      e.preventDefault();
    });

    function onMouseMove(e) {
      if (!isDragging) return;
      const dx = e.clientX - startX;
      const dy = e.clientY - startY;
      el.style.left = (initialX + dx) + 'px';
      el.style.top = (initialY + dy) + 'px';
    }

    function onMouseUp() {
      isDragging = false;
      document.removeEventListener('mousemove', onMouseMove);
      document.removeEventListener('mouseup', onMouseUp);
    }
  }

  // ─── Auto-close Popups on Navigation ──────────────────────────────────────
  let paLastUrl = location.href;
  new MutationObserver(() => {
    const url = location.href;
    if (url !== paLastUrl) {
      paLastUrl = url;
      document.querySelectorAll('.phishalert-panel, .pa-hibp-modal').forEach(p => p.remove());
    }
  }).observe(document.body, { childList: true, subtree: true });


  // ─── UI: Detail Panel ─────────────────────────────────────────────────────

  // One authentication row. `status` comes from the receiving server's own verdict when we have
  // it (pass | unaligned | fail | none | error); otherwise it falls back to the DNS pass/fail.
  function authRow(label, chk) {
    chk = chk || {};
    const st = chk.status || (chk.pass ? 'pass' : (chk.inconclusive ? 'unknown' : 'fail'));
    const map = {
      pass:      ['pass',    '✅'],
      'google-default': ['pass', '✅'],
      unaligned: ['warn',    '⚠️'],
      none:      ['neutral', '➖'],
      error:     ['neutral', '❔'],
      unknown:   ['neutral', '❔'],
      fail:      ['fail',    '❌']
    };
    const m = map[st] || map.fail;
    const tip = [chk.detail, chk.fullDetail].filter(Boolean).join(' — ');
    return `<div class="pa-check ${m[0]}" title="${paEsc(tip)}">
            ${m[1]} ${label}
            <span class="pa-check-detail">${paEsc(chk.detail || '')}</span>
          </div>`;
  }

  function showDetailPanel(result, anchorEl) {
    document.querySelectorAll('.phishalert-panel').forEach(p => p.remove());

    const hasCriticalThreat = result.threats.displayNameSpoof.spoofing ||
      result.threats.homograph.detected ||
      (result.checks.vt?.available && result.checks.vt?.isMalicious);

    const detailTier = hasCriticalThreat
      ? paTrustTier(result.score, true)
      : result.whitelisted
        ? PA_WHITELIST_BADGE
        : paTrustTier(result.score, false);
    const headerColor = detailTier.color;

    const statusIcon = detailTier.svg;
    const statusText = hasCriticalThreat ? 'Critical Threat Detected' :
      result.whitelisted ? 'Verified Sender (Whitelisted)' :
      detailTier.label.replace(/^./, c => c.toUpperCase());
    const isFirstTime = !hasCriticalThreat && !result.whitelisted && paIsFirstTimeSender(result);

    const vtHtml = result.checks.vt?.available ? `
      <div class="pa-check ${result.checks.vt.isMalicious ? 'fail' : 'pass'}">
        ${result.checks.vt.isMalicious ? '❌' : '✅'} VirusTotal
        <span class="pa-check-detail">${result.checks.vt.maliciousCount}/${result.checks.vt.totalEngines} engines flagged</span>
      </div>` :
      `<div class="pa-check neutral">🔍 VirusTotal<span class="pa-check-detail">${paEsc(result.checks.vt?.error || 'API key not set')}</span></div>`;

    const communityHtml = result.checks.community ? `
      <div class="pa-check fail">
        🚩 Community Reports
        <span class="pa-check-detail">Reported ${result.checks.community.count} time${result.checks.community.count !== 1 ? 's' : ''}</span>
      </div>` : '';

    const threatsHtml = [
      result.threats.displayNameSpoof.spoofing ? `<div class="pa-threat">🎭 Display name spoofing: ${paEsc(result.threats.displayNameSpoof.detail)}</div>` : '',
      result.threats.homograph.detected ? `<div class="pa-threat">🔤 ${paEsc(result.threats.homograph.detail)}</div>` : '',
      (result.checks.age?.isVeryNew) ? `<div class="pa-threat">🆕 Domain is very new (< 30 days old) — high risk!</div>` : '',
      (result.checks.age?.isNew && !result.checks.age?.isVeryNew) ? `<div class="pa-threat">📅 Domain is less than 6 months old</div>` : '',
      result.threats.bimi?.isImpersonatingBrand ? `<div class="pa-threat">🏷️ BIMI missing — claims to be "${paEsc(result.threats.bimi.claimedBrand)}" but has no verified brand record</div>` : '',
      result.threats.bimi?.hasBIMI && result.threats.bimi?.hasVMC ? `<div class="pa-threat pa-threat-safe">✅ BIMI verified brand (VMC certificate)</div>` : ''
    ].filter(Boolean).join('');

    // Score ring SVG
    const score = result.score;
    const scoreColor = detailTier.color;
    const r = 26, circ = 2 * Math.PI * r;
    const dash = (score / 100) * circ;
    const scoreRingHtml = `
      <div class="pa-score-ring-wrap">
        <svg width="68" height="68" viewBox="0 0 68 68">
          <circle cx="34" cy="34" r="${r}" fill="none" stroke="#e5e7eb" stroke-width="6"/>
          <circle cx="34" cy="34" r="${r}" fill="none" stroke="${scoreColor}" stroke-width="6"
            stroke-dasharray="${dash} ${circ}" stroke-dashoffset="0"
            stroke-linecap="round"/>
        </svg>
        <div class="pa-score-ring-label" style="color:${scoreColor}">${score}</div>
        <div class="pa-score-ring-sub">/ 100</div>
      </div>`;

    // Score breakdown bars
    const spfScore = result.checks.spf.pass ? (result.checks.spf.strict ? 25 : 17) : (result.checks.spf.status === 'unaligned' ? 7.5 : 0);
    const dkimScore = result.checks.dkim.pass ? 25 : (result.checks.dkim.inconclusive ? 12.5 : (result.checks.dkim.status === 'google-default' ? 20 : (result.checks.dkim.status === 'unaligned' ? 10 : 0)));
    const dmarcScore = result.checks.dmarc.pass ? (result.checks.dmarc.policy === 'reject' ? 20 : result.checks.dmarc.policy === 'quarantine' ? 16 : 8) : 0;
    const ageScore = result.checks.age?.score ?? 0;
    const repScore = result.checks.reputation?.score ?? 0;

    function bar(label, val, max) {
      const pct = Math.round((val / max) * 100);
      const color = val === 0 ? '#ef4444' : val >= max * 0.8 ? '#22c55e' : '#f59e0b';
      return `<div class="pa-score-bar-row">
        <span class="pa-score-bar-label">${label}</span>
        <div class="pa-score-bar-track"><div class="pa-score-bar-fill" style="width:${pct}%;background:${color}"></div></div>
        <span class="pa-score-bar-val" style="color:${color}">${val}/${max}</span>
      </div>`;
    }

    const panel = document.createElement('div');
    panel.className = 'phishalert-panel';
    panel.innerHTML = `
      <div class="pa-panel-header" style="background:${headerColor}">
        <span class="pa-title">🛡️ PhishAlert</span>
        <button class="pa-close">✕</button>
      </div>
      <div class="pa-panel-body">
        <div class="pa-blocked-banner" id="pa-blocked-banner-${paEsc(result.domain)}" style="display:none">🚫 This sender is blocked</div>
        <div class="pa-hero-row">
          ${scoreRingHtml}
          <div class="pa-hero-text">
            <div class="pa-status">${statusIcon} ${statusText}</div>
            <div class="pa-domain">📧 ${paEsc(result.domain)}</div>
            ${isFirstTime ? `<div class="pa-status" style="margin-top:2px">${PA_FIRSTTIME_BADGE.svg} First-time sender — no prior history</div>` : ''}
          </div>
        </div>
        ${threatsHtml ? `<div class="pa-threats-section">${threatsHtml}</div>` : ''}
        <div class="pa-section-label">Score Breakdown</div>
        <div class="pa-score-bars">
          ${bar('SPF', spfScore, 25)}
          ${bar('DKIM', dkimScore, 25)}
          ${bar('DMARC', dmarcScore, 20)}
          ${bar('Age', ageScore, 15)}
          ${bar('Rep.', repScore, 15)}
        </div>
        ${(() => {
          const deductions = result.scoreDeductions || [];
          if (!deductions.length) return '';
          const rows = deductions.map(d => `
            <div class="pa-deduction-row ${d.points > 0 ? 'bonus' : 'penalty'}">
              <span class="pa-deduction-icon">${d.icon}</span>
              <span class="pa-deduction-label">${paEsc(d.label)}</span>
              <span class="pa-deduction-pts">${d.points > 0 ? '+' : ''}${d.points}</span>
            </div>`).join('');
          const hasPenalty = deductions.some(d => d.points < 0);
          const hasBonus = deductions.some(d => d.points > 0);
          const title = (hasPenalty && hasBonus) ? 'Score Adjustments' : hasBonus ? 'Score Bonuses' : 'Score Deductions';
          const icon = (hasPenalty && hasBonus) ? '↕' : hasBonus ? '⬆' : '⬇';
          const color = hasPenalty ? '#dc2626' : '#16a34a';
          return `
            <div class="pa-section-label" style="margin-top:8px;color:${color}">${icon} ${title}</div>
            <div class="pa-deductions-box" style="border-color:${hasPenalty ? '#fecaca' : '#bbf7d0'};background:${hasPenalty ? '#fff5f5' : '#f0fdf4'}">${rows}</div>`;
        })()}
        <div class="pa-section-label" style="margin-top:8px">Authentication Checks</div>
        <div class="pa-auth-source ${result.authSource === 'message' ? 'ok' : 'dns'}">${
          result.authSource === 'message'
            ? '✔ Verified from this message\'s headers'
            : '⚠ DNS records only — this message\'s headers could not be read, so results are not verified'}</div>
        <div class="pa-checks">
          ${authRow('SPF Record', result.checks.spf)}
          ${authRow('DKIM Signature', result.checks.dkim)}
          ${authRow('DMARC Policy', result.checks.dmarc)}
          <div class="pa-check ${result.checks.age?.isNew ? 'fail' : 'pass'}">
            ${result.checks.age?.isNew ? '⚠️' : '✅'} Domain Age
            <span class="pa-check-detail">${paEsc(result.checks.age?.detail || 'Unknown')}</span>
          </div>
          ${vtHtml}
          ${communityHtml}
        </div>
        <div class="pa-report-btn-row">
          <button class="pa-report-btn" data-domain="${paEsc(result.domain)}" title="Flag this domain for the PhishAlert community. Does not affect your Gmail inbox.">🚩 Report as Phishing</button>
          <button class="pa-block-btn" data-email="${paEsc(result.senderStr)}" data-domain="${paEsc(result.domain)}" title="Blocks this sender in Gmail AND reports to community.">🚫 Block in Gmail</button>
        </div>
        <div class="pa-hibp-row">
          <button class="pa-hibp-btn" data-domain="${paEsc(result.domain)}">${window.paIcon('search', 'currentColor')} Check Breach History</button>
        </div>
        ${!result.isTrusted || hasCriticalThreat ? `<div class="pa-warning">⚠️ Do NOT click links or share personal information from this email.</div>` : ''}
      </div>
    `;

    panel.querySelector('.pa-close').addEventListener('click', () => panel.remove());

    // 🚩 Report as Phishing — community report only, does NOT touch Gmail inbox
    panel.querySelector('.pa-report-btn').addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      const domain = result.domain;
      btn.textContent = '⏳ Reporting…';
      btn.disabled = true;
      await bg('COMMUNITY_REPORT', { domain, note: 'User reported from Gmail panel' });
      btn.textContent = '✅ Reported to Community';
    });

    // 1-click Block + Report button — triggers Gmail's native block flow
    panel.querySelector('.pa-block-btn').addEventListener('click', async (e) => {
      const btn = e.currentTarget;
      const email = btn.dataset.email;
      const domain = btn.dataset.domain;

      btn.textContent = '⏳ Opening Gmail block…';
      btn.disabled = true;

      // Step 1: Also save to PhishAlert block list + community report
      await bg('BLOCK_SENDER', { email, domain, reason: 'User blocked via Gmail native block' });

      // Step 2: Trigger Gmail's native "Block sender" via the More (⋮) menu
      // Gmail's More menu is the kebab button inside the open email toolbar
      const triggered = triggerGmailBlockSender();

      if (!triggered) {
        // Fallback: tell user to block manually
        btn.textContent = '✅ Reported — Block manually via ⋮ menu';
        btn.style.fontSize = '10.5px';
      } else {
        btn.textContent = '✅ Block dialog opened';
      }

      // Show blocked banner immediately
      const banner = panel.querySelector('.pa-blocked-banner');
      if (banner) banner.style.display = 'block';
    });

    // HIBP breach check button — shows results in a separate floating modal
    panel.querySelector('.pa-hibp-btn').addEventListener('click', async (e) => {
      e.stopPropagation(); // prevent panel close-on-click from firing
      const btn = e.currentTarget;
      const domain = btn.dataset.domain;
      btn.innerHTML = '···Checking breaches';
      btn.disabled = true;

      const hibp = await bg('HIBP_CHECK', { domain });
      btn.innerHTML = window.paIcon('search', 'currentColor') + ' Check Breach History';
      btn.disabled = false;

      // Remove any existing HIBP modal
      document.querySelectorAll('.pa-hibp-modal').forEach(m => m.remove());

      // Inject keyframe animation once
      if (!document.getElementById('pa-hibp-anim')) {
        const s = document.createElement('style');
        s.id = 'pa-hibp-anim';
        s.textContent = `
          @keyframes pa-hibp-in{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
          .pa-hibp-modal{animation:pa-hibp-in .25s cubic-bezier(.4,0,.2,1)}
        `;
        document.head.appendChild(s);
      }

      const modal = document.createElement('div');
      modal.className = 'pa-hibp-modal';

      if (!hibp || hibp.error) {
        // ── Error / service unavailable state ────────────────────────────
        const manualUrl = `https://xposedornot.com/domain/${encodeURIComponent(domain)}`;
        modal.innerHTML = `
          <div class="pa-hibp-modal-header pa-hibp-header-warn">
            <span class="pa-hibp-modal-icon">${window.paIcon('warning', '#d97706', 22)}</span>
            <div class="pa-hibp-modal-title-wrap">
              <div class="pa-hibp-modal-title">Breach Check Unavailable</div>
              <div class="pa-hibp-modal-sub">Breach Database · ${paEsc(domain)}</div>
            </div>
            <button class="pa-hibp-modal-close">✕</button>
          </div>
          <div class="pa-hibp-modal-body">
            <div class="pa-hibp-state-box pa-hibp-state-warn">
              <p class="pa-hibp-state-msg">The breach lookup service could not be reached right now. This is usually a temporary issue.</p>
              <p class="pa-hibp-state-note">Check this domain manually: <a href="${manualUrl}" target="_blank" rel="noopener" style="color:#92400e;font-weight:600">xposedornot.com ↗</a></p>
            </div>
          </div>
          <div class="pa-hibp-modal-footer">
            <a href="${manualUrl}" target="_blank" rel="noopener" class="pa-hibp-footer-link">Check on XposedOrNot →</a>
            <button class="pa-hibp-modal-close pa-hibp-footer-btn">Close</button>
          </div>`;

      } else if (!hibp.found) {
        // ── Clean state ──────────────────────────────────────────────────
        modal.innerHTML = `
          <div class="pa-hibp-modal-header pa-hibp-header-safe">
            <span class="pa-hibp-modal-icon">${window.paIcon('check', '#16a34a', 22)}</span>
            <div class="pa-hibp-modal-title-wrap">
              <div class="pa-hibp-modal-title">No Breaches Found</div>
              <div class="pa-hibp-modal-sub">Breach Database · ${paEsc(domain)}</div>
            </div>
            <button class="pa-hibp-modal-close">✕</button>
          </div>
          <div class="pa-hibp-modal-body">
            <div class="pa-hibp-state-box pa-hibp-state-safe">
              <p class="pa-hibp-state-msg"><strong>${paEsc(domain)}</strong> has no recorded data breaches in public breach databases.</p>
              <p class="pa-hibp-state-note">This means the domain has not appeared in any known public breach datasets. However, absence of a record does not guarantee the sender is legitimate.</p>
            </div>
          </div>
          <div class="pa-hibp-modal-footer">
            <button class="pa-hibp-modal-close pa-hibp-footer-btn">Close</button>
          </div>`;

      } else {
        // ── Breaches found state ─────────────────────────────────────────
        const breachCards = (hibp.breaches || []).map(b => {
          const classes = (b.dataClasses || []).slice(0, 6);
          const classHtml = classes.map(c =>
            `<span class="pa-hibp-tag">${paEsc(c)}</span>`
          ).join('');
          return `
            <div class="pa-hibp-breach-card">
              <div class="pa-hibp-breach-top">
                <span class="pa-hibp-breach-name">${paEsc(b.name)}</span>
                <span class="pa-hibp-breach-date">${paEsc(b.date)}</span>
              </div>
              ${classHtml
              ? `<div class="pa-hibp-tags-row">${classHtml}</div>`
              : `<div class="pa-hibp-no-classes">No data class details available</div>`}
            </div>`;
        }).join('');

        modal.innerHTML = `
          <div class="pa-hibp-modal-header pa-hibp-header-critical">
            <span class="pa-hibp-modal-icon">${window.paIcon('critical', '#dc2626', 22)}</span>
            <div class="pa-hibp-modal-title-wrap">
              <div class="pa-hibp-modal-title">${Number(hibp.breachCount) || 0} Data Breach${Number(hibp.breachCount) > 1 ? 'es' : ''} Found</div>
              <div class="pa-hibp-modal-sub">Breach Database · ${paEsc(domain)}</div>
            </div>
            <button class="pa-hibp-modal-close">✕</button>
          </div>
          <div class="pa-hibp-modal-body">
            <div class="pa-hibp-state-box pa-hibp-state-critical">
              <p class="pa-hibp-state-msg"><strong>${paEsc(domain)}</strong> has appeared in <strong>${Number(hibp.breachCount) || 0} known data breach${Number(hibp.breachCount) > 1 ? 'es' : ''}</strong>. Treat emails from this domain with extra caution.</p>
            </div>
            <div class="pa-hibp-breach-list">${breachCards}</div>
          </div>
          <div class="pa-hibp-modal-footer">
            <a href="https://xposedornot.com/domain/${encodeURIComponent(domain)}" target="_blank" class="pa-hibp-footer-link">View on XposedOrNot →</a>
            <button class="pa-hibp-modal-close pa-hibp-footer-btn">Close</button>
          </div>`;
      }

      document.body.appendChild(modal);

      // Make the modal draggable by its header
      makeDraggable(modal, '.pa-hibp-modal-header');

      modal.querySelectorAll('.pa-hibp-modal-close').forEach(b =>
        b.addEventListener('click', (ev) => { ev.stopPropagation(); modal.remove(); })
      );
    });

    document.body.appendChild(panel);
    
    // Make the panel draggable by its header
    makeDraggable(panel, '.pa-panel-header');

    const rect = anchorEl.getBoundingClientRect();
    const w = 300;
    let left = rect.left + window.scrollX;
    if (left + w > window.innerWidth) left = window.innerWidth - w - 10;
    panel.style.top = `${rect.bottom + window.scrollY + 5}px`;
    panel.style.left = `${Math.max(10, left)}px`;

    setTimeout(() => {
      document.addEventListener('click', function h(e) {
        if (!panel.contains(e.target)) {
          panel.remove();
          document.removeEventListener('click', h);
        }
      });
    }, 100);
  }

  // ─── Security Banner: Phase 4 findings ────────────────────────────────────
  function analyzeHeadersFromContainer(emailContainer) {
    const headers = extractEmailHeaders(emailContainer);
    if (!headers.from) return null;
    return bg('ANALYZE_HEADERS', { headers });
  }

  function injectSecurityBanner(emailContainer, { trackerResult, qrResult, attachmentResults, headerAnalysis, encryptionResult, result }) {
    if (emailContainer.querySelector('.pa-security-banner')) return;

    const items = [];

    // Pixel trackers
    if (trackerResult?.trackerCount > 0) {
      items.push({
        icon: '👁️',
        label: `${trackerResult.trackerCount} tracking pixel${trackerResult.trackerCount > 1 ? 's' : ''} blocked`,
        severity: 'info',
        detail: trackerResult.trackers.map(t => t.domain || t.src.substring(0, 40)).slice(0, 3).join(', ')
      });
    }

    // QR codes
    if (qrResult?.qrCount > 0) {
      const decoded = qrResult.qrFindings?.find(f => f.type === 'qr_decoded');
      const hasThreat = qrResult.qrThreats?.length > 0;
      items.push({
        icon: hasThreat ? '🚨' : '📷',
        label: decoded
          ? (hasThreat ? `Dangerous QR code decoded: ${decoded.url?.substring(0, 50)}` : `QR code decoded: ${decoded.url?.substring(0, 50)}`)
          : 'QR code detected — verify before scanning',
        severity: hasThreat ? 'danger' : 'warn',
        detail: qrResult.qrFindings[0]?.detail || ''
      });
    }

    // FEATURE 8: Email encryption / TLS status
    if (encryptionResult) {
      if (encryptionResult.issues?.length > 0) {
        const topIssue = encryptionResult.issues[0];
        items.push({
          icon: '🔐',
          label: topIssue.detail,
          severity: topIssue.severity === 'high' ? 'danger' : 'warn',
          detail: encryptionResult.encryptionType !== 'none'
            ? `Encryption: ${encryptionResult.encryptionType}`
            : 'No transport encryption detected'
        });
      } else if (encryptionResult.hasTLS) {
        items.push({
          icon: '🔒',
          label: `TLS encrypted transport${encryptionResult.tlsVersion ? ` (TLSv${encryptionResult.tlsVersion})` : ''}`,
          severity: 'safe',
          detail: encryptionResult.hasSMIME ? 'S/MIME signed' : encryptionResult.hasPGP ? 'PGP encrypted' : ''
        });
      }
    }

    // Attachment risks
    if (attachmentResults?.length > 0) {
      const dangerous = attachmentResults.filter(a => a.riskLevel === 'dangerous');
      const suspicious = attachmentResults.filter(a => a.riskLevel === 'suspicious');
      if (dangerous.length > 0) {
        items.push({
          icon: '📎',
          label: `Dangerous attachment: ${dangerous[0].fileName}`,
          severity: 'danger',
          detail: dangerous[0].detail
        });
      } else if (suspicious.length > 0) {
        items.push({
          icon: '📎',
          label: `Suspicious attachment: ${suspicious[0].fileName}`,
          severity: 'warn',
          detail: suspicious[0].detail
        });
      }
    }

    // Header issues (async — result may be a Promise)
    if (headerAnalysis && typeof headerAnalysis.then === 'function') {
      headerAnalysis.then(ha => {
        if (ha?.issues?.length > 0) {
          const banner = emailContainer.querySelector('.pa-security-banner');
          if (banner) addBannerItem(banner, {
            icon: '📨',
            label: `Header anomaly: ${ha.issues[0].detail}`,
            severity: ha.issues[0].severity === 'high' ? 'danger' : 'warn',
            detail: ''
          });
        }
      });
    }

    // Sender history note
    if (result?.senderHistory) {
      const sh = result.senderHistory;
      if (sh.replyCount === 0 && sh.seenCount === 0) {
        items.push({
          icon: '👤',
          label: 'First contact — sender not seen before',
          severity: 'info',
          detail: 'No prior replies or interactions'
        });
      } else if (sh.replyCount > 0) {
        items.push({
          icon: '✉️',
          label: `Known contact (${sh.replyCount} repl${sh.replyCount > 1 ? 'ies' : 'y'})`,
          severity: 'safe',
          detail: sh.label
        });
      }
    }

    // ── FEATURE 10: Reply-To mismatch alert ───────────────────────────────
    if (result?.threats?.replyToMismatch?.mismatch) {
      const rt = result.threats.replyToMismatch;
      items.push({
        icon: '↩️',
        label: `Reply-To mismatch: replies go to "${rt.replyToDomain}", not "${rt.fromDomain}"`,
        severity: 'danger',
        detail: 'Do not reply to this email — a different party will receive your response'
      });
    }

    // ── FEATURE 11: Urgency keyword alert ────────────────────────────────
    if (result?.threats?.urgency?.isHighRisk || result?.threats?.urgency?.isMediumRisk) {
      const urg = result.threats.urgency;
      items.push({
        icon: '⏰',
        label: urg.isHighRisk
          ? `High-pressure language detected: ${urg.matched.slice(0, 3).join(', ')}`
          : `Urgency signals detected: ${urg.matched.slice(0, 2).join(', ')}`,
        severity: urg.isHighRisk ? 'danger' : 'warn',
        detail: urg.detail
      });
    }

    // ── FEATURE 12: Contact lookalike domain alert ────────────────────────
    if (result?.threats?.contactLookalike?.lookalike) {
      const cl = result.threats.contactLookalike;
      items.push({
        icon: '🎭',
        label: `Lookalike domain: "${cl.targetDomain}" (a contact you email) is being impersonated`,
        severity: cl.severity === 'high' ? 'danger' : 'warn',
        detail: cl.detail
      });
    }

    // ── FEATURE 13: DNSBL blacklist alert ────────────────────────────────
    if (result?.checks?.dnsbl?.listed) {
      const bl = result.checks.dnsbl;
      items.push({
        icon: '🚫',
        label: `Sending IP blacklisted: ${bl.listings?.map(l => l.source).join(', ')}`,
        severity: bl.listings?.length >= 2 ? 'danger' : 'warn',
        detail: bl.detail
      });
    }

    if (items.length === 0) return;

    const banner = document.createElement('div');
    banner.className = 'pa-security-banner';

    const colorMap = { danger: '#dc2626', warn: '#d97706', info: '#2563eb', safe: '#16a34a' };
    banner.innerHTML = `
      <div class="pa-sec-banner-header">
        <span class="pa-sec-banner-title">🛡️ PhishAlert Security Findings</span>
        <button class="pa-sec-banner-close">✕</button>
      </div>
      <div class="pa-sec-banner-items"></div>
    `;

    const itemsContainer = banner.querySelector('.pa-sec-banner-items');

    function addBannerItem(bannerEl, item) {
      const div = document.createElement('div');
      div.className = `pa-sec-banner-item pa-sec-item-${item.severity}`;
      div.innerHTML = `
        <span class="pa-sec-item-icon">${item.icon}</span>
        <div class="pa-sec-item-text">
          <span class="pa-sec-item-label">${paEsc(item.label)}</span>
          ${item.detail ? `<span class="pa-sec-item-detail">${paEsc(item.detail)}</span>` : ''}
        </div>
      `;
      bannerEl.querySelector('.pa-sec-banner-items').appendChild(div);
    }

    // Make addBannerItem available in outer scope for async header results
    window._paAddBannerItem = addBannerItem;

    items.forEach(item => addBannerItem(banner, item));

    banner.querySelector('.pa-sec-banner-close').addEventListener('click', () => banner.remove());

    // Insert before the email body
    const bodyEl = emailContainer.querySelector('.a3s.aiL') ||
      emailContainer.querySelector('.a3s') ||
      emailContainer.querySelector('.ii.gt');
    if (bodyEl?.parentNode) {
      bodyEl.parentNode.insertBefore(banner, bodyEl);
    }
  }

  // ─── Gmail DOM Helpers ────────────────────────────────────────────────────
  function getSenderInfo(container) {
    // Try all known Gmail sender attribute locations
    const attrSelectors = [
      '[data-hovercard-id]', 'span[email]', '.gD', '.go span[email]',
      '[data-hovercard-owner-email]', '.zF', '.yP', '.bA4 span',
      // Promotional / marketing email sender formats
      'span[data-hovercard-id]', '[data-legacy-thread-id] span[email]',
      '.HOF span[email]', '.iw span[email]', 'span.g2'
    ];
    for (const sel of attrSelectors) {
      const el = container.querySelector(sel);
      if (el) {
        const email = el.getAttribute('email') ||
          el.getAttribute('data-hovercard-id') ||
          el.getAttribute('data-hovercard-owner-email');
        const name = el.getAttribute('name') || el.textContent.trim();
        if (email?.includes('@')) return { email, name };
      }
    }
    // Fallback: mailto links
    const mailto = container.querySelector('a[href^="mailto:"]');
    if (mailto) {
      const email = mailto.href.replace('mailto:', '').split('?')[0];
      if (email.includes('@')) return { email, name: mailto.textContent.trim() };
    }
    // Fallback: look for email in any title/data-tooltip attribute (used in promo emails)
    const withTitle = container.querySelector('[title*="@"], [data-tooltip*="@"]');
    if (withTitle) {
      const raw = withTitle.getAttribute('title') || withTitle.getAttribute('data-tooltip') || '';
      const m = raw.match(/[\w.+%-]+@[\w.-]+\.[a-z]{2,}/i);
      if (m) return { email: m[0], name: withTitle.textContent.trim() };
    }
    // Last resort: scan text for email pattern
    const spans = container.querySelectorAll('span,a,td');
    for (const span of spans) {
      const txt = span.textContent.trim();
      if (/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(txt)) return { email: txt, name: txt };
    }
    return null;
  }

  // ─── Track already-processed emails by unique message ID ─────────────────
  // Using a Set of message IDs prevents duplicate badges when multiple nested
  // Gmail containers (.adn, .h7, .gs, .ii.gt) match for the same email.
  const processedMessageIds = new Set();

  // ─── Inject badge into OPEN email view ────────────────────────────────────
  async function injectBadge(emailContainer) {
    // ── Dedup by data-message-id (unique per email thread message) ──────────
    // Walk up to find the nearest ancestor with data-message-id
    const msgEl = emailContainer.closest('[data-message-id]') || emailContainer;
    const msgId = msgEl.getAttribute('data-message-id') ||
      msgEl.getAttribute('data-legacy-message-id');

    if (msgId) {
      if (processedMessageIds.has(msgId)) return; // already done
      processedMessageIds.add(msgId);
    } else {
      // No message ID — fall back to element-level dedup
      if (emailContainer.dataset.phishalertProcessing) return;
    }
    emailContainer.dataset.phishalertProcessing = 'true';

    // Also guard against double badge inside container (extra safety)
    if (emailContainer.querySelector('.phishalert-badge')) return;

    const senderInfo = getSenderInfo(emailContainer);
    if (!senderInfo) {
      if (msgId) processedMessageIds.delete(msgId);
      delete emailContainer.dataset.phishalertProcessing;
      return;
    }

    const domain = extractDomain(senderInfo.email);
    if (!domain) {
      if (msgId) processedMessageIds.delete(msgId);
      delete emailContainer.dataset.phishalertProcessing;
      return;
    }

    // FIX: skip the user's own sent/reply messages entirely — see
    // getOwnAccountEmail() above. Nothing to phish-score in your own
    // outgoing mail, and scanning it was the thing clobbering "current scan".
    const ownEmail = getOwnAccountEmail();
    if (ownEmail && senderInfo.email.toLowerCase() === ownEmail) {
      if (msgId) processedMessageIds.delete(msgId);
      delete emailContainer.dataset.phishalertProcessing;
      return;
    }

    // Placeholder
    const placeholder = document.createElement('span');
    placeholder.className = 'phishalert-badge phishalert-loading';
    placeholder.innerHTML = '🔍';
    placeholder.title = 'PhishAlert: Scanning...';

    // Find the sender name element — try multiple Gmail selectors
    // We inject AFTER the sender name (not before) so the badge always appears
    // next to the name regardless of whether a profile picture is shown.
    // When a profile pic exists, Gmail restructures the DOM so injecting
    // before the name element hides the badge behind/under the avatar.
    const senderName = emailContainer.querySelector('.gD, [email].go, span[email]');
    const senderHovercard = emailContainer.querySelector('[data-hovercard-id]');
    const senderArea = senderName || senderHovercard;

    if (senderArea?.parentNode) {
      // Insert AFTER the sender element (nextSibling), not before it
      // This keeps the badge visible in the name line for both avatar and no-avatar cases
      const afterSender = senderArea.nextSibling;
      senderArea.parentNode.insertBefore(placeholder, afterSender);
    } else {
      // Fallback: try the subject/header row
      const header = emailContainer.querySelector('h3, .hP, .ha');
      if (header?.parentNode) {
        header.parentNode.insertBefore(placeholder, header);
      } else {
        emailContainer.prepend(placeholder);
      }
    }

    try {
      // ── FEATURE 14: Thread context — get thread ID from Gmail URL / DOM ──
      // Gmail thread URLs look like: #inbox/threadId or #thread-f:1234567890
      const threadIdMatch = window.location.hash.match(/#[^/]+\/([a-f0-9-]+)/i) ||
        window.location.hash.match(/thread-f[:%]([0-9]+)/i);
      const threadId = threadIdMatch ? threadIdMatch[1] : (msgId || null);

      // ── Build extra context for scoreDomain ─────────────────────────────
      // We need subject + body for Feature 11 (urgency) and replyTo for Feature 10.
      // Extract lightweight — don't block on a slow body scrape.
      const headers = extractEmailHeaders(emailContainer);
      const replyTo = headers.replyTo || null;
      const subjectEl = document.querySelector('h2.hP, .hP');
      const subject = subjectEl?.innerText?.trim() || '';
      const bodyEl = emailContainer.querySelector('.a3s.aiL, .a3s, .ii.gt .a3s, .ii.gt');
      const bodySnip = (bodyEl?.innerText || '').substring(0, 1200); // enough for keyword scan

      // Real per-message SPF/DKIM/DMARC verdict from Gmail's own headers (best-effort)
      const legacyId = msgEl.getAttribute('data-legacy-message-id') ||
        msgEl.querySelector('[data-legacy-message-id]')?.getAttribute('data-legacy-message-id') || null;
      let rawHeaders = null;
      let headerMsgId = legacyId;
      if (legacyId) {
        let got = await getHeadersForSender(legacyId, senderInfo.email);
        if (!got.block) {            // Gmail sometimes isn't ready right after the pane opens
          await new Promise(r => setTimeout(r, 800));
          got = await getHeadersForSender(legacyId, senderInfo.email);
        }
        rawHeaders = got.block;
        headerMsgId = got.id || legacyId;
      }

      const linkHrefs = [...(bodyEl?.querySelectorAll('a[href]') || [])]
        .map(a => a.getAttribute('href')).filter(h => h && /^(https?:|javascript:|data:)/i.test(h));
      const result = await scoreDomain(domain, senderInfo.email, {
        replyTo, subject, body: bodySnip, threadId,
        rawHeaders, linkHrefs, msgKey: headerMsgId || msgId || ''
      });
      const badge = createBadge(result);
      placeholder.replaceWith(badge);

      // FEATURE NEW 4: Phishing DNA — contribute this scan's fingerprint to
      // the cross-client campaign correlation graph. Fire-and-forget: never
      // blocks or affects the badge shown above.
      const emailLinks = [...(bodyEl?.querySelectorAll('a[href]') || [])]
        .map(a => a.href).filter(h => h && h.startsWith('http'));
      bg('RECORD_CAMPAIGN_FINGERPRINT', {
        from: senderInfo.email, domain, replyTo,
        links: emailLinks, subject, client: 'gmail'
      }).catch(() => {});

      // ── Sync inbox badge: overwrite plain-domain cache and replace any
      // inbox list badge already rendered for this domain so both views agree.
      if (!rawHeaders && !result.freemail && !result.messageSpecific) {
      domainCache.set(domain, result);
      document.querySelectorAll(`.phishalert-inbox-badge[data-domain="${domain}"]`).forEach(inboxBadge => {
        const freshInboxBadge = createInboxBadge(result);
        inboxBadge.replaceWith(freshInboxBadge);
      });
      }

      // ── FEATURE 14: Check for thread hijacking BEFORE recording this sender ──
      // FIX: order was reversed — RECORD used to run first, which added this
      // very sender to thread.domains, so CHECK always found a match and
      // hijacking never fired. Check first, against prior history only,
      // then record. checkThreadHijacking() already handles the "no history
      // yet" / brand-new-thread case internally, so no separate isNewThread
      // gate is needed here.
      if (threadId) {
        const hijackResult = await bg('CHECK_THREAD_HIJACKING', {
          threadId,
          senderDomain: domain
        }).catch(() => ({ hijacking: false }));

        if (hijackResult?.hijacking) {
          // FIX (Bug #4): use the shared floating modal from
          // content-shared.js instead of Gmail's own inline banner, so the
          // hijack alert looks and behaves the same (floating top-right,
          // auto-dismisses after 14s) across Gmail, Outlook, Proton, and
          // Yahoo instead of only Gmail getting a persistent inline banner.
          window.showHijackAlert(hijackResult.currentDomain || domain, hijackResult.threadDomains || []);
        }

        // Record this sender in the thread's participant list AFTER the check
        await bg('RECORD_THREAD_SENDER', {
          threadId,
          senderEmail: senderInfo.email,
          senderDomain: domain
        });
      }

      // Always update "current scan" here — even if scoreDomain() returned from
      // cache — so the AI tab always reflects the email the user is viewing now.
      // We include msgId in the entry so each unique email gets a unique key,
      // preventing the AI chat from reusing a stale cached scan for a different email.
      const currentScanEntry = {
        domain: result.domain,
        score: result.score,
        isTrusted: result.isTrusted,
        sender: senderInfo.email,
        msgId: msgId || null,   // unique per message — forces AI chat to reset
        checks: {
          spf: { pass: result.checks.spf.pass, detail: result.checks.spf.detail },
          dkim: { pass: result.checks.dkim.pass, inconclusive: !!result.checks.dkim.inconclusive, detail: result.checks.dkim.detail },
          dmarc: { pass: result.checks.dmarc.pass, detail: result.checks.dmarc.detail, policy: result.checks.dmarc.policy },
          age: { ageInDays: result.checks.age?.ageInDays, isNew: result.checks.age?.isNew, detail: result.checks.age?.detail, score: result.checks.age?.score },
          reputation: { score: result.checks.reputation?.score, detail: result.checks.reputation?.detail },
          vt: result.checks.vt || null,
          community: result.checks.community || null
        },
        threats: result.threats,
        threatList: [
          result.threats.displayNameSpoof?.spoofing ? 'Display name spoofing' : null,
          result.threats.homograph?.detected ? `${result.threats.homograph.type}: ${result.threats.homograph.targetBrand}` : null,
          result.checks.vt?.isMalicious ? 'VirusTotal: Malicious' : null,
          result.checks.community?.count >= 3 ? `Reported ${result.checks.community.count}x` : null
        ].filter(Boolean)
      };
      bg('SAVE_CURRENT_SCAN', { entry: currentScanEntry });

      // Phase 2: Scan links after badge injection
      await scanLinksInEmail(emailContainer, domain, senderInfo.email);

      // Phase 4a: Record sender as 'seen'
      bg('RECORD_SENDER', { email: senderInfo.email, domain: senderInfo.domain, interactionType: 'seen' });

      // Phase 4b: Parallel security scans — results saved to storage for popup
      // Re-use headers already extracted above (avoids redundant DOM walk)
      const [trackerResult, qrResult, attachmentResults, encryptionResult] = await Promise.all([
        detectTrackers(emailContainer),
        detectQRCodes(emailContainer),
        scanAttachments(emailContainer),
        // FEATURE 8: TLS / email encryption detection
        Promise.resolve(bg('DETECT_ENCRYPTION', { headers }))
      ]);

      const encResult = await encryptionResult;

      const headerAnalysis = analyzeHeadersFromContainer(emailContainer);
      const resolvedHeaders = headerAnalysis && typeof headerAnalysis.then === 'function'
        ? await headerAnalysis
        : headerAnalysis;

      // --- DYNAMIC MALWARE / ATTACHMENT PENALTY ---
      const dangerousAtt = attachmentResults.filter(a => a.riskLevel === 'dangerous');
      const suspiciousAtt = attachmentResults.filter(a => a.riskLevel === 'suspicious');
      // Look for Gmail's native warning banner for encrypted or suspicious attachments
      // We search the raw text since Gmail frequently changes warning banner CSS classes.
      const emailText = (emailContainer.innerText || '').toLowerCase();
      const hasGmailWarning = emailText.includes('encrypted attachment warning') ||
                              emailText.includes('suspicious attachment') ||
                              emailText.includes('be careful with this message');

      let dynamicPenalty = 0;
      let dynamicReasons = [];

      if (dangerousAtt.length > 0) {
        dynamicPenalty += 80;
        dynamicReasons.push(`Malicious attachment detected: ${dangerousAtt[0].fileName}`);
      } else if (suspiciousAtt.length > 0 || hasGmailWarning) {
        dynamicPenalty += 30;
        dynamicReasons.push('Suspicious or encrypted attachment detected');
      }

      if (qrResult?.qrThreats?.length > 0) {
        dynamicPenalty += 50;
        dynamicReasons.push('Malicious QR code detected');
      }

      if (dynamicPenalty > 0) {
        result.score = Math.max(0, result.score - dynamicPenalty);
        result.isTrusted = false;
        result.whitelisted = false;
        
        if (!result.scoreDeductions) result.scoreDeductions = [];
        if (!result.threats) result.threats = {};
        
        dynamicReasons.forEach(reason => {
          result.scoreDeductions.push({
            label: reason,
            points: -dynamicPenalty,
            icon: '🚨'
          });
          currentScanEntry.threatList.push(reason);
        });

        if (dangerousAtt.length > 0 || qrResult?.qrThreats?.length > 0 || hasGmailWarning) {
          result.threats.malware = true;
        }

        // Re-render badge dynamically with updated score
        const newBadge = createBadge(result);
        badge.replaceWith(newBadge);
        
        // Re-save scan to background
        const cacheKey = senderInfo.replyTo ? `${result.domain}::rt` : result.domain;
        domainCache.set(cacheKey, result);
        
        currentScanEntry.score = result.score;
        currentScanEntry.isTrusted = false;
        currentScanEntry.threats = result.threats;
        bg('SAVE_CURRENT_SCAN', { entry: currentScanEntry });
      }
      // --------------------------------------------

      // FEATURE NEW 5: Investigation Mode — extract IOCs from everything this
      // scan gathered (sender, reply-to, links, DNSBL-resolved mail IP,
      // attachments). Fire-and-forget: never blocks or affects the badge.
      window.paExtractIOCs && window.paExtractIOCs(bg, {
        scanKey: msgId || threadId || domain,
        domain, from: senderInfo.email, replyTo, subject,
        links: emailLinks, threadId,
        attachments: attachmentResults,
        dnsblIp: result.checks?.dnsbl?.ip || null,
        client: 'gmail'
      }).catch(() => {});

      // Save Phase 4 results to storage so popup Tools tab can display them
      bg('SAVE_PHASE4', {
        trackerResult,
        qrResult,
        attachmentResults,
        headerAnalysis: resolvedHeaders,
        encryptionResult: encResult,
        senderHistory: result.senderHistory,
        domain: result.domain,
        sender: senderInfo.email
      });

      // Inject security banner — now also includes encryption status
      injectSecurityBanner(emailContainer, {
        trackerResult, qrResult, attachmentResults,
        headerAnalysis: resolvedHeaders,
        encryptionResult: encResult,
        result
      });

      // Phase 4: OpenClaw AI Tools Panel
      injectAIToolsPanel(emailContainer, senderInfo, result);
    } catch (err) {
      placeholder.innerHTML = '❓';
      placeholder.title = 'PhishAlert: Could not verify.';
    } finally {
      // Release the guard now that this pass is done — it only exists to stop
      // multiple nested Gmail containers from double-scanning the SAME open,
      // not to remember this message forever. Without this, reopening an
      // email (e.g. after marking it unread again) would never re-scan it.
      if (msgId) processedMessageIds.delete(msgId);
      delete emailContainer.dataset.phishalertProcessing;
    }
  }

  // ─── INBOX LIST: Create compact badge ────────────────────────────────────
  function createInboxBadge(result) {
    const group = document.createElement('span');
    group.className = 'phishalert-inbox-badge-group';
    group.dataset.domain = result.domain;

    const badge = document.createElement('span');
    badge.className = 'phishalert-inbox-badge';
    badge.dataset.domain = result.domain;

    const hasCritical = paIsCritical(result);

    if (hasCritical) {
      const tier = paTrustTier(result.score, true);
      badge.innerHTML = tier.svg;
      badge.title = `PhishAlert: CRITICAL THREAT\nDomain: ${result.domain}`;
    } else if (result.whitelisted) {
      badge.innerHTML = PA_WHITELIST_BADGE.svg;
      badge.title = `PhishAlert: ${PA_WHITELIST_BADGE.label}\nDomain: ${result.domain}`;
    } else {
      const tier = paTrustTier(result.score, false);
      badge.innerHTML = tier.svg;
      badge.title = `PhishAlert: ${tier.label} (score ${result.score})\nDomain: ${result.domain}\nOpen email for full details.`;
    }
    group.appendChild(badge);

    if (!hasCritical && !result.whitelisted && paIsFirstTimeSender(result)) {
      const ftBadge = document.createElement('span');
      ftBadge.className = 'phishalert-inbox-badge phishalert-inbox-badge-firsttime';
      ftBadge.innerHTML = PA_FIRSTTIME_BADGE.svg;
      ftBadge.title = `PhishAlert: ${PA_FIRSTTIME_BADGE.label}\nDomain: ${result.domain}`;
      group.appendChild(ftBadge);
    }

    return group;
  }

  // FIX: `closest('tr.zA')` alone only proves the element is inside SOME
  // element Gmail tags as a message row — it doesn't prove that row is a
  // real, visible message. Gmail keeps at least one tr.zA-classed row
  // mounted off-screen behind the sticky list toolbar for layout/scroll
  // bookkeeping. That row passed this check, got scored like any other
  // message, and its badge (main trust badge + "first-time sender" badge)
  // ended up rendering on top of the refresh button instead of on a real
  // row. This checks the row actually has visible layout before proceeding.
  function isVisibleInboxRow(row) {
    if (!row || row.offsetParent === null) return false;
    const rect = row.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  }

  // ─── INBOX LIST: Core injection — targets .zF sender spans directly ───────
  // Gmail inbox rows: each sender name is a <span class="zF" data-hovercard-id="email@domain.com">
  // We inject the badge as a sibling BEFORE the .zF span inside its parent td

  // Legacy message id for a list row (last message of the thread, else thread id).
  function getRowLegacyId(row) {
    if (!row) return null;
    const el = row.querySelector('[data-legacy-last-message-id]') ||
               row.querySelector('[data-legacy-message-id]') ||
               row.querySelector('[data-legacy-thread-id]');
    if (!el) return null;
    return el.getAttribute('data-legacy-last-message-id') ||
           el.getAttribute('data-legacy-message-id') ||
           el.getAttribute('data-legacy-thread-id') || null;
  }

  async function scoreInboxRow(row, domain, email) {
    const legacyId = getRowLegacyId(row);
    const rawHeaders = legacyId ? await getGmailRawHeaders(legacyId) : null;
    return scoreDomain(domain, email, rawHeaders ? { rawHeaders, msgKey: legacyId } : {});
  }

  async function processInboxSenderSpan(zfSpan) {
    // Strictly allow only elements inside real, visible Gmail inbox rows
    const row = zfSpan.closest('tr.zA');
    if (!isVisibleInboxRow(row)) return;
    // Already processed?
    if (zfSpan.dataset.paScanned) return;
    zfSpan.dataset.paScanned = 'true';

    // Get email from data-hovercard-id (Gmail stores full email here)
    const email = zfSpan.getAttribute('data-hovercard-id') ||
      zfSpan.getAttribute('email') || '';

    if (!email.includes('@')) {
      // No email attribute — try parent row's data
      delete zfSpan.dataset.paScanned;
      return;
    }

    const domain = extractDomain(email);
    if (!domain) return;

    // Insert loading dot BEFORE the zF span
    const placeholder = document.createElement('span');
    placeholder.className = 'phishalert-inbox-badge phishalert-inbox-loading';
    placeholder.textContent = '⬤';
    placeholder.title = 'PhishAlert: Checking...';
    zfSpan.parentNode.insertBefore(placeholder, zfSpan);

    try {
      const result = await scoreInboxRow(row, domain, email);
      const badge = createInboxBadge(result);
      placeholder.replaceWith(badge);
    } catch (e) {
      placeholder.remove();
    }
  }

  // ─── INBOX LIST: Also handle .yP spans (another Gmail sender class) ────────
  async function processInboxYPSpan(ypSpan) {
    // Strictly allow only elements inside real, visible Gmail inbox rows
    const row = ypSpan.closest('tr.zA');
    if (!isVisibleInboxRow(row)) return;
    if (ypSpan.dataset.paScanned) return;

    // .yP spans sometimes have email attr
    const email = ypSpan.getAttribute('email') ||
      ypSpan.getAttribute('data-hovercard-id') || '';

    if (!email.includes('@')) {
      // Try the sibling .zF if available
      const row = ypSpan.closest('tr.zA');
      if (!row) return;
      const zf = row.querySelector('.zF[data-hovercard-id]');
      if (zf && !zf.dataset.paScanned) {
        processInboxSenderSpan(zf);
      }
      return;
    }

    ypSpan.dataset.paScanned = 'true';
    const domain = extractDomain(email);
    if (!domain) return;

    const placeholder = document.createElement('span');
    placeholder.className = 'phishalert-inbox-badge phishalert-inbox-loading';
    placeholder.textContent = '⬤';
    ypSpan.parentNode.insertBefore(placeholder, ypSpan);

    try {
      const result = await scoreInboxRow(row, domain, email);
      const badge = createInboxBadge(result);
      placeholder.replaceWith(badge);
    } catch (e) {
      placeholder.remove();
    }
  }

  // ─── INBOX LIST: Scan all rows on page ────────────────────────────────────
  function scanInboxRows() {
    // No dropdown guard needed — selectors below are scoped strictly to tr.zA rows

    // Primary: find all .zF spans with hovercard email in inbox rows only
    document.querySelectorAll('tr.zA .zF[data-hovercard-id]:not([data-pa-scanned])')
      .forEach(processInboxSenderSpan);

    // Fallback: tr rows — only mark as scanned if we actually found an email element
    document.querySelectorAll('tr.zA:not([data-pa-row-scanned])').forEach(row => {
      const emailEl = row.querySelector('[data-hovercard-id*="@"], [email*="@"]');
      if (emailEl) {
        row.dataset.paRowScanned = 'true';
        if (!emailEl.dataset.paScanned) {
          processInboxSenderSpan(emailEl);
        }
      }
      // If no email found yet, do NOT mark row as scanned — retry will catch it
    });
  }

  // ─── OpenClaw AI Tools Panel ───────────────────────────────────────────────

  function extractEmailBody(container) {
    const bodyEl = container.querySelector('.a3s.aiL') ||
      container.querySelector('.a3s') ||
      container.querySelector('.ii.gt .a3s') ||
      container.querySelector('.ii.gt');
    const subject = document.querySelector('h2.hP')?.innerText?.trim() ||
      document.querySelector('.hP')?.innerText?.trim() || '';
    const body = bodyEl?.innerText?.trim() || '';
    return { subject, body: body.substring(0, 3000) };
  }

  // ─── Extract all messages in the thread ───────────────────────────────────
  function extractThreadMessages() {
    const threadMessages = [];
    // Gmail thread: each message is a .adn or [data-message-id] block
    const msgContainers = document.querySelectorAll('[data-message-id]');
    msgContainers.forEach(container => {
      const bodyEl = container.querySelector('.a3s.aiL') ||
        container.querySelector('.a3s') ||
        container.querySelector('.ii.gt');
      if (!bodyEl) return;
      const senderEl = container.querySelector('[email], .gD, [data-hovercard-id]');
      const sender = senderEl?.getAttribute('email') || senderEl?.getAttribute('data-hovercard-id') || '';
      const body = bodyEl?.innerText?.trim() || '';
      if (body) {
        threadMessages.push({ sender, body: body.substring(0, 800) });
      }
    });
    // Fallback: if no thread containers found, just return the current email
    return threadMessages;
  }

  function injectAIToolsPanel(emailContainer, senderInfo, scanResult) {
    if (emailContainer.querySelector('.pa-ai-tools-wrap')) return;

    const bodyEl = emailContainer.querySelector('.a3s.aiL') ||
      emailContainer.querySelector('.a3s') ||
      emailContainer.querySelector('.ii.gt');
    if (!bodyEl) return;

    const { subject, body } = extractEmailBody(emailContainer);
    if (!body && !subject) return;

    // Privacy: subject/body/thread text is only handed to the extension (and only ever
    // sent to Groq) when the user has opted in to AI features in Settings. Default off.
    const aiSettingsP = bg('GET_AI_SETTINGS').then(r => ({
      consent: r?.consent === true, autoClassify: r?.autoClassify === true
    })).catch(() => ({ consent: false, autoClassify: false }));

    aiSettingsP.then(({ consent }) => {
      bg('SAVE_EMAIL_CONTENT', {
        subject: consent ? subject : '',
        body: consent ? body : '',
        sender: senderInfo.email,
        domain: scanResult.domain
      });
      if (consent) {
        const threadMessages = extractThreadMessages();
        if (threadMessages.length > 0) bg('SAVE_THREAD_MESSAGES', { messages: threadMessages });
      }
    });

    // ── Build panel markup ──────────────────────────────────────────────────
    const wrap = document.createElement('div');
    wrap.className = 'pa-ai-tools-wrap';
    wrap.innerHTML = `
      <div class="pa-ai-tools-bar">
        <div class="pa-ai-bar-left">
          <span class="pa-ai-bar-logo">🤖</span>
          <span class="pa-ai-bar-label">PhishAlert AI</span>
          <span class="pa-ai-cat-tag pa-ai-loading-tag">⏳ Classifying…</span>
        </div>
        <div class="pa-ai-bar-right">
          <button class="pa-ai-tool-btn" data-action="summarize">📝 Summarize</button>
          <button class="pa-ai-tool-btn" data-action="tone">🧠 Tone Check</button>
          <button class="pa-ai-tool-btn" data-action="explain">🔍 Why Dangerous?</button>
          <button class="pa-ai-tool-btn" data-action="draft">✍️ Draft Reply</button>
          <button class="pa-ai-collapse-btn" title="Toggle">▲</button>
        </div>
      </div>
      <div class="pa-ai-result-area" style="display:none"></div>
      <div class="pa-ai-draft-area" style="display:none">
        <div class="pa-ai-tone-row">
          <span class="pa-ai-tone-label">Tone:</span>
          <button class="pa-ai-tone-btn active" data-tone="formal">Formal</button>
          <button class="pa-ai-tone-btn" data-tone="friendly">Friendly</button>
          <button class="pa-ai-tone-btn" data-tone="brief">Brief</button>
        </div>
        <div class="pa-ai-thread-row">
          <label class="pa-ai-thread-label">
            <input type="checkbox" class="pa-ai-thread-check" checked> 🧵 Thread-aware (reads full conversation)
          </label>
        </div>
        <button class="pa-ai-generate-btn">⚡ Generate Draft</button>
        <div class="pa-ai-draft-output" style="display:none"></div>
        <button class="pa-ai-copy-btn" style="display:none">📋 Copy Draft</button>
      </div>
    `;

    bodyEl.parentNode.insertBefore(wrap, bodyEl);

    const catTag = wrap.querySelector('.pa-ai-cat-tag');
    const barLeft = wrap.querySelector('.pa-ai-bar-left');
    const resultArea = wrap.querySelector('.pa-ai-result-area');
    const draftArea = wrap.querySelector('.pa-ai-draft-area');

    // Helper: hide all panels, show one
    function showOnlyPanel(panelEl) {
      resultArea.style.display = 'none';
      draftArea.style.display = 'none';
      // Reset all btn text
      wrap.querySelector('[data-action="summarize"]').textContent = '📝 Summarize';
      wrap.querySelector('[data-action="tone"]').textContent = '🧠 Tone Check';
      wrap.querySelector('[data-action="explain"]').textContent = '🔍 Why Dangerous?';
      wrap.querySelector('[data-action="draft"]').textContent = '✍️ Draft Reply';
      if (panelEl) panelEl.style.display = 'block';
    }

    // ── Classify only when the user opted in to AI AND to automatic classification ──
    // Otherwise nothing leaves the browser; the Summarize button classifies on demand.
    aiSettingsP.then(({ consent, autoClassify }) => {
      if (!consent) {
        catTag.textContent = '🔒 AI off';
        catTag.className = 'pa-ai-cat-tag pa-ai-cat-error';
        catTag.title = 'AI features are off. Enable "Send email content to Groq" in PhishAlert Settings.';
        return;
      }
      if (!autoClassify) {
        catTag.textContent = '🤖 AI ready';
        catTag.className = 'pa-ai-cat-tag';
        catTag.title = 'Nothing is sent until you click a tool.';
        return;
      }
      runAutoClassify();
    });

    function runAutoClassify() {
    bg('CLASSIFY_EMAIL', { subject, body }).then(analysis => {
      if (!analysis || analysis.error) {
        const noKey = analysis?.error?.includes('No Groq');
        catTag.textContent = analysis?.consentRequired ? '🔒 AI off' : noKey ? '⚙️ Add Groq key in Settings' : '⚠️ Analysis error';
        catTag.className = 'pa-ai-cat-tag pa-ai-cat-error';
        return;
      }

      bg('SAVE_AI_ANALYSIS', { analysis });

      const catPalette = {
        Work: ['#dbeafe', '#1d4ed8'], Personal: ['#d1fae5', '#065f46'],
        Urgent: ['#fee2e2', '#991b1b'], Spam: ['#f3f4f6', '#374151'],
        Finance: ['#fef3c7', '#92400e'], Newsletter: ['#ede9fe', '#5b21b6'],
        Promotional: ['#fce7f3', '#9d174d'], Social: ['#e0f2fe', '#0369a1']
      };
      const [cbg, cfg] = catPalette[analysis.category] || ['#f3f4f6', '#374151'];
      catTag.textContent = `📋 ${analysis.category || 'Unknown'}`;
      catTag.className = 'pa-ai-cat-tag';
      catTag.style.background = cbg;
      catTag.style.color = cfg;

      // Priority badge
      const priColors = { High: ['#fee2e2', '#b91c1c'], Medium: ['#fef3c7', '#92400e'], Low: ['#d1fae5', '#065f46'] };
      const priIcons = { High: '🔴', Medium: '🟡', Low: '🟢' };
      const [pbg, pfg] = priColors[analysis.priority] || ['#f3f4f6', '#374151'];
      const priTag = document.createElement('span');
      priTag.className = 'pa-ai-priority-tag';
      priTag.textContent = `${priIcons[analysis.priority] || ''} ${analysis.priority || 'Unknown'}`;
      priTag.style.cssText = `background:${pbg};color:${pfg};`;
      barLeft.appendChild(priTag);

      // Deadline / reason row
      if (analysis.deadline || analysis.priorityReason) {
        const infoRow = document.createElement('div');
        infoRow.className = 'pa-ai-info-row';
        infoRow.textContent = analysis.deadline
          ? `⏰ Deadline: ${analysis.deadline}`
          : `ℹ️ ${analysis.priorityReason}`;
        wrap.querySelector('.pa-ai-tools-bar').insertAdjacentElement('afterend', infoRow);
      }
    });
    }

    // ── Summarize ───────────────────────────────────────────────────────────
    const summarizeBtn = wrap.querySelector('[data-action="summarize"]');
    summarizeBtn.addEventListener('click', async () => {
      if (resultArea.style.display !== 'none' && resultArea.dataset.mode === 'summarize') {
        showOnlyPanel(null); return;
      }
      showOnlyPanel(resultArea);
      resultArea.dataset.mode = 'summarize';
      summarizeBtn.textContent = '📝 Hide';
      resultArea.innerHTML = '<div class="pa-ai-loading">⏳ Summarizing email…</div>';

      const a = await bg('CLASSIFY_EMAIL', { subject, body });
      if (!a || a.error) {
        resultArea.innerHTML = `<div class="pa-ai-error">⚠️ ${paEsc(a?.error || 'Error')}</div>`;
        return;
      }
      const pts = (a.keyPoints || []).map(p => `<li>${paEsc(p)}</li>`).join('');
      const acts = (a.actionItems || []).map(x => `<li>✅ ${paEsc(x)}</li>`).join('');
      resultArea.innerHTML = `
        <div class="pa-ai-summary-card">
          <p class="pa-ai-summary-text">${paEsc(a.summary || 'No summary available.')}</p>
          ${pts ? `<div class="pa-ai-subsection"><strong>Key Points</strong><ul>${pts}</ul></div>` : ''}
          ${acts ? `<div class="pa-ai-subsection"><strong>Action Items</strong><ul>${acts}</ul></div>` : ''}
          ${a.deadline ? `<div class="pa-ai-deadline-row">⏰ Deadline: <strong>${paEsc(a.deadline)}</strong></div>` : ''}
        </div>`;
    });

    // ── Tone Analyzer ───────────────────────────────────────────────────────
    const toneBtn = wrap.querySelector('[data-action="tone"]');
    toneBtn.addEventListener('click', async () => {
      if (resultArea.style.display !== 'none' && resultArea.dataset.mode === 'tone') {
        showOnlyPanel(null); return;
      }
      showOnlyPanel(resultArea);
      resultArea.dataset.mode = 'tone';
      toneBtn.textContent = '🧠 Hide';
      resultArea.innerHTML = '<div class="pa-ai-loading">⏳ Analyzing psychological tactics…</div>';

      const a = await bg('ANALYZE_TONE', { subject, body });
      if (!a || a.error) {
        resultArea.innerHTML = `<div class="pa-ai-error">⚠️ ${paEsc(a?.error || 'Error')}</div>`;
        return;
      }

      const riskColors = { high: '#dc2626', medium: '#d97706', low: '#f59e0b', safe: '#16a34a' };
      const riskColor = riskColors[a.overallRisk] || '#374151';
      const tacticSeverityColors = { high: '#fee2e2', medium: '#fef3c7', low: '#f0fdf4' };

      const tacticsHtml = (a.tactics || []).length === 0
        ? '<div class="pa-ai-tone-safe">✅ No manipulation tactics detected</div>'
        : (a.tactics || []).map(t => `
          <div class="pa-ai-tone-tactic" style="background:${tacticSeverityColors[t.severity] || '#f9fafb'}">
            <div class="pa-ai-tone-tactic-header">
              <span class="pa-ai-tone-label-badge">${paEsc(t.label)}</span>
              <span class="pa-ai-tone-sev pa-ai-tone-sev-${['high', 'medium', 'low'].includes(t.severity) ? t.severity : 'low'}">${paEsc(String(t.severity || '').toUpperCase())}</span>
            </div>
            <div class="pa-ai-tone-evidence">💬 "${paEsc(t.evidence)}"</div>
            <div class="pa-ai-tone-why">${paEsc(t.explanation)}</div>
          </div>`).join('');

      resultArea.innerHTML = `
        <div class="pa-ai-tone-card">
          <div class="pa-ai-tone-risk" style="color:${riskColor}">
            Risk Level: <strong>${paEsc(String(a.overallRisk || 'unknown').toUpperCase())}</strong>
          </div>
          <p class="pa-ai-tone-summary">${paEsc(a.summary || '')}</p>
          <div class="pa-ai-tone-tactics">${tacticsHtml}</div>
          ${a.recommendation ? `<div class="pa-ai-tone-rec">💡 ${paEsc(a.recommendation)}</div>` : ''}
        </div>`;
    });

    // ── Phishing Explanation ────────────────────────────────────────────────
    const explainBtn = wrap.querySelector('[data-action="explain"]');
    explainBtn.addEventListener('click', async () => {
      if (resultArea.style.display !== 'none' && resultArea.dataset.mode === 'explain') {
        showOnlyPanel(null); return;
      }
      showOnlyPanel(resultArea);
      resultArea.dataset.mode = 'explain';
      explainBtn.textContent = '🔍 Hide';
      resultArea.innerHTML = '<div class="pa-ai-loading">⏳ Analyzing why this might be dangerous…</div>';

      const scanData = await bg('GET_LAST_SCAN');
      const a = await bg('EXPLAIN_PHISHING', { subject, body, scanData });
      if (!a || a.error) {
        resultArea.innerHTML = `<div class="pa-ai-error">⚠️ ${paEsc(a?.error || 'Error')}</div>`;
        return;
      }
      resultArea.innerHTML = `
        <div class="pa-ai-explain-card">
          <div class="pa-ai-explain-icon">🔍</div>
          <div class="pa-ai-explain-text">${paEscBr(a.explanation || '')}</div>
        </div>`;
    });

    // ── Draft Reply ─────────────────────────────────────────────────────────
    const draftBtn = wrap.querySelector('[data-action="draft"]');
    draftBtn.addEventListener('click', () => {
      if (draftArea.style.display !== 'none') {
        showOnlyPanel(null); return;
      }
      showOnlyPanel(draftArea);
      draftBtn.textContent = '✍️ Hide';
    });

    // Tone buttons
    wrap.querySelectorAll('.pa-ai-tone-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        wrap.querySelectorAll('.pa-ai-tone-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
      });
    });

    // Generate draft (thread-aware or single)
    const draftOutput = wrap.querySelector('.pa-ai-draft-output');
    const copyBtn = wrap.querySelector('.pa-ai-copy-btn');
    let lastDraft = '';

    wrap.querySelector('.pa-ai-generate-btn').addEventListener('click', async () => {
      const tone = wrap.querySelector('.pa-ai-tone-btn.active')?.dataset.tone || 'formal';
      const isThreadAware = wrap.querySelector('.pa-ai-thread-check')?.checked;
      draftOutput.style.display = 'block';
      draftOutput.innerHTML = '<div class="pa-ai-loading">⏳ Drafting your reply…</div>';
      copyBtn.style.display = 'none';

      let res;
      if (isThreadAware) {
        const threadMessages = extractThreadMessages();
        if (threadMessages.length > 1) {
          res = await bg('DRAFT_THREAD_REPLY', { subject, threadMessages, tone });
        } else {
          res = await bg('DRAFT_REPLY', { subject, body, tone });
        }
      } else {
        res = await bg('DRAFT_REPLY', { subject, body, tone });
      }

      if (!res || res.error) {
        draftOutput.innerHTML = `<div class="pa-ai-error">⚠️ ${paEsc(res?.error || 'Error')}</div>`;
        return;
      }
      lastDraft = res.draft || '';
      const threadNote = res.threadAware && extractThreadMessages().length > 1
        ? '<div class="pa-ai-thread-note">🧵 Thread-aware: read full conversation</div>'
        : '';
      draftOutput.innerHTML = `${threadNote}<div class="pa-ai-draft-text">${paEscBr(lastDraft)}</div>`;
      copyBtn.style.display = 'inline-block';
    });

    copyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(lastDraft);
      copyBtn.textContent = '✅ Copied!';
      setTimeout(() => { copyBtn.textContent = '📋 Copy Draft'; }, 2000);
    });

    // Collapse toggle
    wrap.querySelector('.pa-ai-collapse-btn').addEventListener('click', e => {
      const collapsed = wrap.dataset.collapsed === 'true';
      const barRight = wrap.querySelector('.pa-ai-bar-right');
      if (collapsed) {
        barRight.style.display = 'flex';
        showOnlyPanel(null);
        e.currentTarget.textContent = '▲';
        wrap.dataset.collapsed = 'false';
      } else {
        barRight.style.display = 'none';
        showOnlyPanel(null);
        e.currentTarget.textContent = '▼';
        wrap.dataset.collapsed = 'true';
      }
    });
  }


  // ═══════════════════════════════════════════════════════════════════════
  // FEATURE NEW 4 — Outgoing Email Scan (hold the Gmail Send click)
  // Shared guard lives in content-shared.js. It stops the click synchronously,
  // scans, and only re-fires Send if the mail is clean or the user confirms.
  // (The old handler awaited the scan before calling preventDefault(), which
  // was too late — the mail had already been sent.)
  // ═══════════════════════════════════════════════════════════════════════
  window.paOutgoingGuard && window.paOutgoingGuard({
    bg,
    client: 'gmail',
    sendSelector: '[data-tooltip="Send"], [aria-label^="Send"], .T-I.J-J5-Ji.aoO',
    composeRootSelectors: ['[role="dialog"]', '.I5 .nH', 'form'],
    recipientSelectors: [
      '.vR span[email]', '.vN span[email]',
      'textarea[name="to"]', 'textarea[name="cc"]', 'textarea[name="bcc"]',
      'input[aria-label="To"]', 'input[aria-label="Cc"]', 'input[aria-label="Bcc"]'
    ],
    subjectSelectors: ['input[name="subjectbox"]'],
    bodySelectors: ['div[aria-label="Message Body"]', '.Am.Al.editable']
  });

  // ─── Gmail Observer ────────────────────────────────────────────────────────
  function observeGmail() {
    // Debounce inbox scanning to avoid hammering on rapid DOM changes
    let inboxScanTimer = null;
    function scheduleScan() {
      clearTimeout(inboxScanTimer);
      inboxScanTimer = setTimeout(scanInboxRows, 300);
    }

    const observer = new MutationObserver((mutations) => {
      let needsInboxScan = false;

      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) continue;

          // ── Open email view — find outermost email containers only ──────────
          // We prefer [data-message-id] as it is the unique root per message.
          // Fallback to .adn / .h7 only if no data-message-id ancestor exists.
          // This prevents nested selectors from injecting multiple badges.
          const byMsgId = node.querySelectorAll?.('[data-message-id]') || [];
          if (byMsgId.length > 0) {
            byMsgId.forEach(injectBadge);
          } else {
            const views = node.querySelectorAll?.('.adn, .h7, .gs') || [];
            views.forEach(injectBadge);
            if (node.matches?.('[data-message-id], .adn, .h7, .gs')) injectBadge(node);
          }
          if (node.matches?.('[data-message-id]')) injectBadge(node);

          // ── Inbox rows / sender spans added ──
          // Direct .zF span added — only if inside a real inbox row
          if (node.matches?.('.zF') && node.closest('tr.zA')) {
            processInboxSenderSpan(node);
          }
          // New tr row added
          if (node.matches?.('tr.zA') || node.querySelector?.('tr.zA')) {
            needsInboxScan = true;
          }
          // Any subtree that contains inbox rows
          if (node.querySelector?.('tr.zA .zF[data-hovercard-id]')) {
            needsInboxScan = true;
          }
        }
      }

      if (needsInboxScan) scheduleScan();
    });

    observer.observe(document.body, { childList: true, subtree: true });

    // Initial scan — first call deferred 500 ms to allow the background service
    // worker to fully start before we send any messages. Subsequent calls use
    // the retry backoff built into bg() so they're safe to fire immediately.
    setTimeout(scanInboxRows, 500);
    setTimeout(scanInboxRows, 800);
    setTimeout(scanInboxRows, 1500);
    setTimeout(scanInboxRows, 2500);
    setTimeout(scanInboxRows, 4000);
    setTimeout(scanInboxRows, 6000);

    // Scan when user navigates between inbox tabs (Primary, Promotions, Social)
    // Ignore clicks inside the search box area
    document.addEventListener('click', (e) => {
      if (e.target.closest('form[role="search"], .gb_Lf, .aKt')) return;
      const tab = e.target.closest('[data-view-type],.aKz,.aim');
      if (tab) setTimeout(scanInboxRows, 600);
    });

    // Process already-open email views — prefer data-message-id root elements
    const openEmails = document.querySelectorAll('[data-message-id]');
    if (openEmails.length > 0) {
      openEmails.forEach(injectBadge);
    } else {
      document.querySelectorAll('.adn, .h7, .gs').forEach(injectBadge);
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', observeGmail);
  } else {
    observeGmail();
  }

  // FEATURE: Cleanup floating UI when navigating away from an email
  window.addEventListener('hashchange', () => {
    document.querySelectorAll('.pa-floating-panel, .pa-hibp-modal, .pa-ai-tools-wrap').forEach(el => el.remove());
  });
  window.addEventListener('popstate', () => {
    document.querySelectorAll('.pa-floating-panel, .pa-hibp-modal, .pa-ai-tools-wrap').forEach(el => el.remove());
  });



  // ═══════════════════════════════════════════════════════════════════════
  // FEATURE 6 — Inline Threat Banner (colored bar below email subject)
  // ═══════════════════════════════════════════════════════════════════════

  function injectInlineBanner(emailContainer, scanResult) {
    if (!emailContainer || !scanResult) return;
    const prev = emailContainer.querySelector('.pa-inline-banner');
    if (prev) prev.remove();

    const score = scanResult.score ?? 50;
    const domain = scanResult.domain || '';
    const checks = scanResult.checks || {};
    const threats = scanResult.threats || {};

    const hasCritical = score < 60
      || threats.displayNameSpoof?.spoofing
      || threats.homograph?.detected
      || threats.punycode?.suspicious
      || checks.vt?.isMalicious;

    const isSafe = score >= 90 && !hasCritical;

    let bannerClass, icon, title, detail;

    if (hasCritical) {
      bannerClass = 'pa-inline-banner-critical';
      icon = '🚨';
      title = 'Critical Threat Detected';
      const parts = [];
      if (threats.displayNameSpoof?.spoofing) parts.push('Display name spoofing');
      if (threats.homograph?.detected) parts.push(`IDN homograph mimics "${threats.homograph.targetBrand}"`);
      if (threats.punycode?.suspicious) parts.push('Punycode domain attack');
      if (checks.vt?.isMalicious) parts.push(`VirusTotal: ${checks.vt.maliciousCount} of ${checks.vt.totalEngines} engines flagged`);
      detail = parts.length
        ? parts.join(' · ')
        : `Trust score: ${score}/100 — Do not click links or open attachments`;
    } else if (!isSafe) {
      bannerClass = 'pa-inline-banner-suspicious';
      icon = '⚠️';
      title = `Suspicious Sender — Score ${score}/100`;
      const failing = [];
      if (!checks.spf?.pass) failing.push('SPF');
      if (!checks.dkim?.pass && !checks.dkim?.inconclusive) failing.push('DKIM');
      if (!checks.dmarc?.pass) failing.push('DMARC');
      detail = failing.length
        ? `Failed checks: ${failing.join(', ')} — Exercise caution`
        : 'Some authentication checks failed — Exercise caution';
    } else {
      bannerClass = 'pa-inline-banner-safe';
      icon = '✅';
      title = `Trusted Sender — Score ${score}/100`;
      detail = `${domain} — All authentication checks passed`;
    }

    const banner = document.createElement('div');
    banner.className = `pa-inline-banner ${bannerClass}`;
    banner.setAttribute('data-pa-banner', '1');
    banner.innerHTML = `
      <span class="pa-inline-banner-icon">${icon}</span>
      <span class="pa-inline-banner-text">
        <div class="pa-inline-banner-title">PhishAlert: ${paEsc(title)}</div>
        <div class="pa-inline-banner-detail">${paEsc(detail)}</div>
      </span>
      ${domain && !isSafe ? `<button class="pa-inline-banner-trust" title="Trust ${paEsc(domain)}">✓ Trust</button>` : ''}
      <button class="pa-inline-banner-close" title="Dismiss">✕</button>
    `;

    banner.querySelector('.pa-inline-banner-close').addEventListener('click', (e) => {
      e.stopPropagation();
      banner.style.transition = 'opacity 0.2s, transform 0.2s';
      banner.style.opacity = '0';
      banner.style.transform = 'translateY(-4px)';
      setTimeout(() => banner.remove(), 220);
    });

    const trustBtn = banner.querySelector('.pa-inline-banner-trust');
    if (trustBtn) {
      trustBtn.addEventListener('click', async (e) => {
        e.stopPropagation();
        await bg('WHITELIST_ADD', { domain });
        banner.className = 'pa-inline-banner pa-inline-banner-safe';
        banner.querySelector('.pa-inline-banner-icon').textContent = '✅';
        banner.querySelector('.pa-inline-banner-title').textContent = `PhishAlert: ${domain} added to whitelist`;
        banner.querySelector('.pa-inline-banner-detail').textContent = 'Future emails from this domain will be trusted automatically';
        trustBtn.remove();
      });
    }

    let inserted = false;
    const insertAfter = (el) => {
      if (el && el.parentNode && !inserted) {
        el.parentNode.insertBefore(banner, el.nextSibling);
        inserted = true;
      }
    };

    const subjectEl =
      emailContainer.querySelector('h2.hP') ||
      emailContainer.querySelector('[data-thread-perm-id] h2') ||
      emailContainer.querySelector('.ha h2') ||
      emailContainer.querySelector('.ha .hP');
    if (subjectEl) insertAfter(subjectEl);

    if (!inserted) {
      const body = emailContainer.querySelector('.a3s, .gmail_quote, .adP');
      if (body) { body.parentNode.insertBefore(banner, body); inserted = true; }
    }
    if (!inserted) emailContainer.prepend(banner);
  }

  // Auto-inject banner whenever a scan completes
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type !== '_SCAN_UPDATED') return;
    setTimeout(async () => {
      const scanResult = await bg('GET_LAST_SCAN');
      if (!scanResult) return;
      const containers = document.querySelectorAll('[data-message-id]');
      if (containers.length > 0) {
        injectInlineBanner(containers[containers.length - 1], scanResult);
      }
    }, 800);
  });


  // ═══════════════════════════════════════════════════════════════════════
  // FEATURE 14 — Thread Hijack Warning Banner
  // FIX (Bug #4): Gmail used to have its own inline, persist-until-dismissed
  // banner here (_injectThreadHijackBanner), while Outlook/Proton/Yahoo all
  // used the floating top-right modal from content-shared.js
  // (window.showHijackAlert), auto-dismissing after 14s. That made the same
  // alert look and behave differently depending on which mail client the
  // user was in. Gmail now calls window.showHijackAlert() too — see the
  // call site above — so all four clients share one implementation.
  // ═══════════════════════════════════════════════════════════════════════
  // FEATURE 12 — Gmail Outgoing Send Hook (Contact Domain Learning)
  // Records recipient domains when the user sends an email from Gmail so
  // that future incoming emails can be checked for lookalike impersonation.
  // ═══════════════════════════════════════════════════════════════════════

  document.addEventListener('click', async (e) => {
    // Gmail send button: various selectors across Gmail versions
    const sendBtn = e.target.closest(
      '[data-tooltip="Send"], [aria-label*="Send"], .T-I[data-tooltip*="Send"], ' +
      '.T-I.J-J5-Ji[data-tooltip="Send ⌘Enter"], [data-tooltip="Send ⌘Enter"]'
    );
    if (!sendBtn) return;

    // Find the compose window ancestor
    const compose = sendBtn.closest('.M9, .dw, [role="dialog"]') || document;

    // Extract all recipient fields (To, Cc, Bcc)
    const recipientSelectors = [
      '.vO[email]',      // Gmail To chips
      '.afV[email]',     // Gmail Cc chips
      '.aKS[email]',     // Gmail Bcc chips
      'span[email]',     // fallback — any email-bearing span in compose
      '[data-hovercard-id*="@"]'
    ];

    const recipientEmails = new Set();
    recipientSelectors.forEach(sel => {
      compose.querySelectorAll(sel).forEach(el => {
        const addr = el.getAttribute('email') || el.getAttribute('data-hovercard-id') || '';
        if (addr.includes('@')) recipientEmails.add(addr.toLowerCase());
      });
    });

    // Also try extracting from the To/Cc text input if chips aren't rendered
    compose.querySelectorAll('input[name="to"], input[name="cc"], input[name="bcc"], [aria-label="To"]').forEach(inp => {
      const val = inp.value || '';
      const matches = val.match(/[\w.+%-]+@[\w.-]+\.[a-z]{2,}/gi) || [];
      matches.forEach(addr => recipientEmails.add(addr.toLowerCase()));
    });

    if (recipientEmails.size === 0) return;

    // Record each unique recipient domain for Feature 12
    const domains = [...new Set(
      [...recipientEmails]
        .map(addr => addr.split('@')[1])
        .filter(Boolean)
    )];

    for (const domain of domains) {
      bg('ADD_CONTACT_DOMAIN', { domain });
    }
  }, true); // capture phase so we fire before Gmail's own handler

  document.addEventListener('keydown', async (e) => {
    if (!e.altKey || !e.shiftKey) return;
    if (e.key !== 'S' && e.key !== 's') return;
    if (e.target.matches('input, textarea, [contenteditable]')) return;
    e.preventDefault();
    // Ask the background service worker to open the extension popup
    await bg('OPEN_POPUP');
  });

  // FEATURE NEW 3: Active Link Protection — intercept real link clicks
  window.paActiveLinkGuard && window.paActiveLinkGuard({ bg });

})();