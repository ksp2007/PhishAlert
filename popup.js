(function () {
  'use strict';

  // Safe wrapper around chrome.runtime.sendMessage
  function send(msg) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(msg, (res) => {
          if (chrome.runtime.lastError) {
            console.warn('[PhishAlert popup]', chrome.runtime.lastError.message);
            resolve(null);
          } else {
            resolve(res);
          }
        });
      } catch (e) {
        console.warn('[PhishAlert popup] sendMessage error:', e);
        resolve(null);
      }
    });
  }

  // ── Shared 5-tier trust scale ────────────────────────────────────────────
  // FIX: single source of truth for score→label/color, used by both the
  // Threats tab badge and the exported PDF report. Previously the PDF
  // export had its own hardcoded 60/90 three-tier scale (TRUSTED/
  // SUSPICIOUS/CRITICAL) that drifted out of sync with the Threats tab's
  // 45/70/90 five-tier scale — e.g. a score of 75 showed "Likely safe" in
  // the popup but "SUSPICIOUS" in the exported report.
  var PA_SCORE_TIERS = [
    { min: 90, label: 'TRUSTED',      level: 'safe',     color: '#16a34a',
      svg: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#16a34a" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.5-3 8-7 9-4-1-7-4.5-7-9V6l7-3z"/><path d="M9 12l2 2 4-4"/></svg>' },
    { min: 70, label: 'LIKELY SAFE',  level: 'safe',     color: '#2563eb',
      svg: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.5-3 8-7 9-4-1-7-4.5-7-9V6l7-3z"/></svg>' },
    { min: 45, label: 'SUSPICIOUS',   level: 'warn',     color: '#d97706',
      svg: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#d97706" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 4l9 16H3L12 4z"/><path d="M12 10v4"/><path d="M12 17h.01"/></svg>' },
    { min: 20, label: 'HIGH RISK',    level: 'warn',     color: '#ea580c',
      svg: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#ea580c" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v6c0 4.5-3 8-7 9-4-1-7-4.5-7-9V6l7-3z"/><path d="M9.5 9.5l5 5M14.5 9.5l-5 5"/></svg>' },
    { min: -1, label: 'CRITICAL',     level: 'critical', color: '#dc2626',
      svg: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#dc2626" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M8.5 3h7L21 8.5v7L15.5 21h-7L3 15.5v-7L8.5 3z"/><path d="M12 8v4"/><path d="M12 16h.01"/></svg>' }
  ];
  var PA_VERIFIED_TIER = { label: 'VERIFIED', level: 'safe', color: '#7c3aed',
    svg: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#7c3aed" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="5"/><path d="M9.5 8l1.5 1.5 3.5-3.5"/><path d="M8.5 12.5l-2.5 7.5 6-3 6 3-2.5-7.5"/></svg>' };

  function paGetScoreTier(sc, isWhitelisted) {
    if (isWhitelisted) return PA_VERIFIED_TIER;
    return PA_SCORE_TIERS.find(function (t) { return sc >= t.min; }) || PA_SCORE_TIERS[PA_SCORE_TIERS.length - 1];
  }

  // ── Sidebar nav switching ──────────────────────────────────────────────
  document.querySelectorAll('.nav-item').forEach(function (nav) {
    nav.addEventListener('click', function () {
      document.querySelectorAll('.nav-item').forEach(function (n) { n.classList.remove('active'); });
      document.querySelectorAll('.panel').forEach(function (p) { p.classList.remove('active'); });
      nav.classList.add('active');
      var panelId = 'tab-' + nav.dataset.tab;
      var panel = document.getElementById(panelId);
      if (panel) panel.classList.add('active');

      // Stop AI polling whenever we leave the AI tab
      if (nav.dataset.tab !== 'ai' && aiPollInterval) {
        clearInterval(aiPollInterval);
        aiPollInterval = null;
      }
      if (nav.dataset.tab === 'productivity') loadProductivity();
      if (nav.dataset.tab === 'log') loadLog();
      if (nav.dataset.tab === 'reports') loadReports();
      if (nav.dataset.tab === 'settings') loadSettings();
      if (nav.dataset.tab === 'overview') loadStats();
      if (nav.dataset.tab === 'ai') initAiChat();
      if (nav.dataset.tab === 'tools') loadTools();
      if (nav.dataset.tab === 'threats') loadThreats();
      if (nav.dataset.tab === 'weekly') loadWeeklyReport();
      if (nav.dataset.tab === 'campaigns') loadCampaigns();
    });
  });

  // ── Groq-missing notice: jump to Settings tab ────────────────────────────
  var gotoSettingsBtn = document.getElementById('pa-groq-goto-settings');
  if (gotoSettingsBtn) {
    gotoSettingsBtn.addEventListener('click', function () {
      var settingsNav = document.querySelector('[data-tab="settings"]');
      if (settingsNav) settingsNav.click();
    });
  }

  // ── Threats & Forensics Tab (merged Threats + Investigation Mode) ─────────
  // Single-email security investigation workspace: verdict → evidence →
  // attack path → IOCs → forensic timeline → campaign correlation →
  // evidence fingerprint → response actions. Detailed per-check cards are
  // preserved below under "Detailed Evidence" — nothing from the old
  // Threats or Investigation tabs was dropped, just reorganized.
  var _tfScan = null;
  var _tfIocs = null;
  var _tfCampaign = null;
  var _tfReportBtnAttached = false;
  var _tfGroups = null;
  var _tfGroupHandlers = {};
  var _tfActiveGroup = 'overview';
  var _tfSubnavAttached = false;

  function tfSetCount(id, n) {
    var el = document.getElementById(id);
    if (el) el.textContent = n > 0 ? String(n) : '';
  }

  function tfShowGroup(name) {
    if (!_tfGroups) return;
    _tfActiveGroup = name;
    var container = document.getElementById('threats-container');
    if (container) container.innerHTML = _tfGroups[name] || '<div class="tf-group-empty">Nothing here yet.</div>';
    document.querySelectorAll('.tf-subnav-btn').forEach(function (b) {
      b.classList.toggle('active', b.getAttribute('data-tfgroup') === name);
    });
    if (typeof _tfGroupHandlers[name] === 'function') _tfGroupHandlers[name]();
  }

  function tfBuildCaseId(scanData, scanLog) {
    var ts = (scanData && scanData.timestamp) || Date.now();
    var d = new Date(ts);
    var y = d.getFullYear(), m = String(d.getMonth() + 1).padStart(2, '0'), day = String(d.getDate()).padStart(2, '0');
    var dateStr = '' + y + m + day;
    var sameDay = (scanLog || []).filter(function (e) {
      var ed = new Date(e.timestamp || 0);
      return ed.getFullYear() === y && ed.getMonth() === d.getMonth() && ed.getDate() === d.getDate();
    });
    var seq = String(Math.max(1, sameDay.length)).padStart(3, '0');
    return 'Case PA-' + dateStr + '-' + seq;
  }

  async function tfSha256Hex(str) {
    var enc = new TextEncoder().encode(str);
    var buf = await crypto.subtle.digest('SHA-256', enc);
    return Array.from(new Uint8Array(buf)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
  }

  function tfEvidenceRow(label, pass, detail, na) {
    if (na) return '<tr><td>' + label + '</td><td style="color:var(--text3)">N/A</td><td>' + (detail || '') + '</td></tr>';
    if (!pass && na === 'unverified') return '<tr><td>' + label + '</td><td style="color:var(--text3)">UNVERIFIED</td><td>' + invEsc(detail || '') + '</td></tr>';
    return '<tr><td>' + label + '</td><td class="' + (pass ? 'tf-ev-pass' : 'tf-ev-fail') + '">' + (pass ? 'PASS' : 'FAIL') + '</td><td>' + invEsc(detail || '') + '</td></tr>';
  }

  function tfTimelineItem(text, ts, flagged) {
    var time = ts ? new Date(ts).toLocaleTimeString() : '';
    return '<div class="tf-timeline-item">' +
      '<div class="tf-timeline-dot' + (flagged ? ' flag' : '') + '"></div>' +
      '<div><div class="tf-timeline-text">' + text + '</div>' +
      (time ? '<div class="tf-timeline-time">' + time + '</div>' : '') + '</div></div>';
  }

  // ── Active Defense (Canary Intelligence) rendering helpers ────────────────
  var CANARY_LABELS = {
    automated_infrastructure: { text: 'Automated Infrastructure', color: '#6b7280', icon: '🤖' },
    likely_automated:         { text: 'Likely Automated',         color: '#f59e0b', icon: '⚙️' },
    indeterminate:            { text: 'Indeterminate',            color: '#9ca3af', icon: '❔' },
    suspicious_interaction:   { text: 'Suspicious Interaction',   color: '#ef4444', icon: '🕷️' },
    likely_human_driven:      { text: 'Likely Human-Driven',      color: '#dc2626', icon: '🧑' }
  };

  function tfCanaryEventRow(e) {
    var label = CANARY_LABELS[e.classification] || { text: e.classification, color: '#9ca3af', icon: '❔' };
    var net = e.network || {};
    var where = [net.city, net.region, net.country].filter(Boolean).join(', ');
    return '<div class="tf-canary-event">' +
      '<div class="tf-canary-event-head"><span>' + label.icon + '</span>' +
      '<span style="color:' + label.color + ';font-weight:700">' + invEsc(label.text) + '</span>' +
      '<span style="color:var(--text3);font-size:11px;margin-left:auto">' + Math.round((e.confidence || 0) * 100) + '% confidence</span></div>' +
      '<div class="tf-canary-event-detail">' +
      (net.ip ? invEsc(net.ip) + ' · ' : '') +
      (net.asOrganization ? invEsc(net.asOrganization) + ' · ' : '') +
      (where ? invEsc(where) + ' · ' : '') +
      new Date(e.timestampMs).toLocaleString() +
      '</div>' +
      (e.signals && e.signals.length ? '<div class="tf-canary-event-signals">' + invChipRow(e.signals) + '</div>' : '') +
      '</div>';
  }

  function tfActiveDefenseHtml(scanData, canaryDeployment) {
    var html = '<div class="tf-section"><div class="tf-section-title">🎯 Active Defense — Canary Intelligence</div>';

    if (!canaryDeployment) {
      html += '<div class="tf-canary-box">' +
        '<div class="inv-empty">No canary deployed against this email yet. Deploying a canary gives you a controlled, synthetic artifact (an invisible pixel and a decoy link) — if the sender\'s infrastructure ever touches it, PhishAlert classifies who did, without ever claiming to identify the attacker personally.</div>' +
        '<button class="tf-response-btn" id="tf-deploy-bait-btn" style="margin-top:8px">🎯 Deploy Bait</button>' +
        '<div class="tf-response-feedback" id="tf-canary-feedback"></div>' +
        '</div>';
      html += '</div>';
      return html;
    }

    html += '<div class="tf-canary-box">';
    html += '<div>Canary <strong>' + invEsc(canaryDeployment.canaryId) + '</strong> deployed ' +
      new Date(canaryDeployment.createdAtMs).toLocaleString() + '.</div>';

    html += '<div class="tf-section-title" style="margin-top:10px;font-size:11px">✉️ Decoy Reply (review, then paste into your own reply and send it yourself — PhishAlert never sends this for you)</div>';
    html += '<textarea class="tf-canary-decoy-text" id="tf-canary-decoy-text" readonly rows="4">' + invEsc(canaryDeployment.decoyReply.plain) + '</textarea>';
    html += '<button class="inv-copy-btn" id="tf-copy-decoy-btn">📋 Copy Decoy Reply</button>';

    html += '<div class="tf-section-title" style="margin-top:14px;font-size:11px">📡 Telemetry (' + (canaryDeployment.events || []).length + ' hit' + ((canaryDeployment.events || []).length !== 1 ? 's' : '') + ')</div>';
    if (canaryDeployment.events && canaryDeployment.events.length) {
      html += canaryDeployment.events.map(tfCanaryEventRow).join('');
    } else {
      html += '<div class="inv-empty">No hits recorded yet. Once the decoy reply is sent and the recipient\'s infrastructure loads the pixel or clicks the link, telemetry appears here.</div>';
    }
    html += '<button class="inv-copy-btn" id="tf-refresh-canary-btn">🔄 Refresh Telemetry</button>';
    html += '<div class="tf-response-feedback" id="tf-canary-feedback"></div>';
    html += '</div></div>';
    return html;
  }

  // ── Threats Tab (detailed per-check cards — unchanged detection logic) ───
  async function loadThreats() {
    var container = document.getElementById('threats-container');
    var caseIdEl = document.getElementById('tf-case-id');
    container.innerHTML = '<div class="loading">Loading threat &amp; forensic data…</div>';
    try {
      var scanData = await send({ type: 'GET_LAST_SCAN' });
      var phase4 = await send({ type: 'GET_PHASE4' });
      var scanLog = await send({ type: 'GET_SCAN_LOG' });
      var campaigns = await send({ type: 'GET_CAMPAIGNS' });
      var canaryDeployment = scanData && scanData.iocScanKey
        ? await send({ type: 'GET_CANARY_DEPLOYMENT', scanKey: scanData.iocScanKey })
        : null;

      _tfScan = scanData;

      if (!scanData) {
        if (caseIdEl) caseIdEl.textContent = 'Case —';
        _tfGroups = null;
        var subnavEmpty = document.getElementById('tf-subnav');
        if (subnavEmpty) subnavEmpty.classList.add('hidden');
        container.innerHTML = '<div class="threat-empty"><span class="threat-empty-icon">🔬</span><strong>No scan data yet</strong><br><span style="font-size:12px;margin-top:6px;display:block">Open any email — PhishAlert will scan it and reconstruct the full evidence case here.</span></div>';
        return;
      }

      if (caseIdEl) caseIdEl.textContent = tfBuildCaseId(scanData, scanLog || []);

      var iocs = scanData.iocs || { urls: [], domains: [], ipAddresses: [], emailAddresses: [], replyTo: [], redirects: [], attachments: [] };
      _tfIocs = iocs;

      var cards = [];
      var findings = []; // condensed {icon,title,level}
      var threatCount = 0;

      // ── Score card ──
      var sc = scanData.score !== undefined ? scanData.score : 50;
      var isWhitelisted = !!scanData.whitelisted;
      var scoreTier = paGetScoreTier(sc, isWhitelisted);
      var scoreColor = scoreTier.level;
      var scoreIcon = scoreTier.svg;
      cards.push(makeThreatCard(
        scoreIcon, 'Trust Score: ' + sc + '/100',
        scoreTier.label,
        scoreColor,
        'Sender domain: ' + (scanData.domain || 'unknown'),
        isWhitelisted ? 'You manually whitelisted this domain — all automated checks were skipped.' :
        sc < 45 ? 'Score below 45 indicates significant authentication failures or active threat signals.' : sc < 70 ? 'Moderate risk — some checks failed. Exercise caution.' : sc < 90 ? 'Mostly clean, but not every check passed. Low risk.' : 'All major checks passed.',
        scoreColor === 'critical'
      ));

      // ── First-time sender card ──
      var sh = scanData.senderHistory;
      var isFirstTime = !isWhitelisted && !!sh && (sh.replyCount || 0) === 0 && (sh.seenCount || 0) === 0;
      if (isFirstTime) {
        cards.push(makeThreatCard(
          '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#0891b2" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="8" r="3.5"/><path d="M3 20c0-3.6 2.7-6 6-6s6 2.4 6 6"/><path d="M18 8v4"/><path d="M18 15h.01"/></svg>',
          'First-Time Sender', 'INFO', 'info',
          'No prior replies or sightings for this address',
          'This is the first email PhishAlert has recorded from this exact address — worth a closer look before acting on any links or requests.',
          false
        ));
      }

      var checks = scanData.checks || {};
      var threats = scanData.threats || {};

      // ── SPF / DKIM / DMARC ──
      ['spf', 'dkim', 'dmarc'].forEach(function (k) {
        var c = checks[k];
        if (!c) return;
        var icons = { spf: '🔒', dkim: '✍️', dmarc: '📋' };
        var labels = { spf: 'SPF', dkim: 'DKIM', dmarc: 'DMARC' };
        if (!c.pass) {
          threatCount++;
          findings.push({ icon: icons[k], title: labels[k] + ' Failure', level: 'warn' });
          cards.push(makeThreatCard(icons[k], labels[k] + ' Failure', 'FAIL', 'warn',
            c.detail || 'Record not found or invalid',
            labels[k] === 'DMARC' ? 'No DMARC means attackers can freely spoof this domain.' :
              labels[k] === 'SPF' ? 'SPF failure means the sending server is not authorized by the domain.' :
                'DKIM failure means the email signature could not be verified.',
            false));
        }
      });

      // ── MX Record ──
      var mx = checks.mx;
      if (mx && mx.suspicious) {
        threatCount++;
        findings.push({ icon: '📮', title: 'No MX Records', level: 'critical' });
        cards.push(makeThreatCard('📮', 'No MX Records', 'CRITICAL', 'critical',
          'This domain cannot receive email — it only sends',
          'Phishing domains are often set up purely to send emails and never receive replies. Having no MX records is a strong phishing signal.',
          true));
      }

      // ── Display name spoofing ──
      var spoof = threats.displayNameSpoof;
      if (spoof && spoof.spoofing) {
        threatCount++;
        findings.push({ icon: '🎭', title: 'Display Name Spoofing', level: 'critical' });
        cards.push(makeThreatCard('🎭', 'Display Name Spoofing', 'CRITICAL', 'critical',
          spoof.detail || '',
          'The sender\'s display name claims to be a known brand, but the actual email domain doesn\'t match. This is a classic impersonation attack.',
          true));
      }

      // ── Punycode ──
      var puny = threats.punycode;
      if (puny && puny.suspicious) {
        threatCount++;
        findings.push({ icon: '🔤', title: 'Punycode / IDN Attack', level: 'critical' });
        cards.push(makeThreatCard('🔤', 'Punycode / IDN Attack', 'CRITICAL', 'critical',
          puny.detail || '',
          'The domain uses punycode encoding (xn--) to display lookalike characters. When rendered, it appears identical to a trusted brand domain.',
          true));
      }

      // ── Homograph ──
      var hom = threats.homograph;
      if (hom && hom.detected) {
        threatCount++;
        findings.push({ icon: '🔤', title: 'IDN Homograph: Mimics "' + (hom.targetBrand || '') + '"', level: 'critical' });
        cards.push(makeThreatCard('🔤', 'IDN Homograph: Mimics "' + (hom.targetBrand || '') + '"', 'CRITICAL', 'critical',
          hom.detail || '',
          'The domain uses visually similar characters (e.g. Cyrillic "а" instead of Latin "a") to impersonate a known brand.',
          true));
      }

      // ── VirusTotal ──
      var vt = checks.vt;
      if (vt && vt.available && vt.isMalicious) {
        threatCount++;
        findings.push({ icon: '🦠', title: 'VirusTotal: Malicious', level: 'critical' });
        cards.push(makeThreatCard('🦠', 'VirusTotal: Malicious', 'CRITICAL', 'critical',
          vt.maliciousCount + ' of ' + vt.totalEngines + ' security engines flagged this domain',
          'Multiple independent antivirus and threat intelligence engines have confirmed this domain is associated with malware or phishing.',
          true));
      }

      // ── Deep headers ──
      var ha = phase4 && phase4.headerAnalysis;
      if (ha && ha.issues && ha.issues.length > 0) {
        ha.issues.forEach(function (issue) {
          threatCount++;
          var isHigh = issue.severity === 'high';
          findings.push({ icon: '📨', title: formatHeaderLabel(issue.type), level: isHigh ? 'critical' : 'warn' });
          cards.push(makeThreatCard('📨', formatHeaderLabel(issue.type),
            isHigh ? 'HIGH' : 'MEDIUM',
            isHigh ? 'critical' : 'warn',
            issue.detail || '',
            getHeaderIssueExplanation(issue.type),
            isHigh));
        });
      }

      // ── Tracking pixels ──
      var tr = phase4 && phase4.trackerResult;
      if (tr && tr.trackerCount > 0) {
        var tDomains = (tr.trackers || []).map(function (t) { return t.domain || ''; }).filter(Boolean).slice(0, 3).join(', ');
        cards.push(makeThreatCard('👁️', tr.trackerCount + ' Tracking Pixel' + (tr.trackerCount > 1 ? 's' : '') + ' Detected', 'WARNING', 'warn',
          tDomains || 'Invisible 1×1 images found',
          'Tracking pixels notify the sender the moment you open the email, revealing your IP address, device type, and exact open time.',
          false));
      }

      // ── QR codes ──
      var qr = phase4 && phase4.qrResult;
      if (qr && qr.qrCount > 0) {
        cards.push(makeThreatCard('📷', 'QR Code Detected', 'WARNING', 'warn',
          (qr.qrFindings && qr.qrFindings[0] && qr.qrFindings[0].detail) || 'QR code found in email body',
          'QR codes bypass URL scanning — the destination is invisible until you scan it. Phishing attacks increasingly use QR codes to evade filters.',
          false));
      }

      // ── Attachments ──
      var atts = phase4 && phase4.attachmentResults;
      if (atts) {
        var dangerAtts = atts.filter(function (a) { return a.riskLevel === 'dangerous'; });
        dangerAtts.forEach(function (att) {
          threatCount++;
          findings.push({ icon: '📎', title: 'Dangerous Attachment: ' + att.fileName, level: 'critical' });
          cards.push(makeThreatCard('📎', 'Dangerous Attachment: ' + att.fileName, 'CRITICAL', 'critical',
            att.detail || 'Executable or macro-enabled file',
            'This attachment type can execute code on your machine. Never open executable files from untrusted senders.',
            true));
        });
      }

      // ── Threat list from scan (Reply-To mismatch, urgency, lookalike, DNSBL, BIMI, community) ──
      var tList = scanData.threatList || scanData.threats || [];
      if (Array.isArray(tList) && tList.length > 0) {
        tList.filter(function (t) { return typeof t === 'string'; }).forEach(function (t) {
          var alreadyCovered = ['Display name spoofing', 'VirusTotal: Malicious'].some(function (k) { return t.includes(k); });
          if (!alreadyCovered) {
            threatCount++;
            findings.push({ icon: '⚠️', title: t, level: 'warn' });
            cards.push(makeThreatCard('⚠️', t, 'THREAT', 'warn', '', '', false));
          }
        });
      }

      // ── Confirmed vs heuristic verdict ──
      // "Confirmed" = an independent threat-intel source made a positive
      // match (not just a heuristic score deduction) — mirrors the same
      // signals background.js's Layer-1 override already treats as
      // decisive, so the banner never claims more certainty than the
      // underlying checks actually support.
      var isConfirmed = !!((checks.vt && checks.vt.isMalicious) || (checks.urlhaus && checks.urlhaus.malicious) ||
        (checks.dnsbl && checks.dnsbl.listed) || (checks.community && checks.community.count >= 3));
      var attackType = invAttackType(scanData);
      var targetBrand = (threats.bimi && threats.bimi.claimedBrand) || (threats.homograph && threats.homograph.targetBrand) || (threats.contactLookalike && threats.contactLookalike.targetDomain) || null;

      var verdictClass = isConfirmed ? 'confirmed' : scoreColor;
      var verdictIcon = isConfirmed ? '🔴' : scoreColor === 'critical' ? '🔴' : scoreColor === 'warn' ? '🟠' : '🟢';
      var verdictLabel = isConfirmed ? 'CONFIRMED PHISHING' : scoreTier.label;

      // ── OVERVIEW: verdict, condensed findings, quick response actions ────
      var ov = '';
      ov += '<div class="tf-verdict ' + verdictClass + '">' +
        '<div class="tf-verdict-icon">' + verdictIcon + '</div>' +
        '<div><div class="tf-verdict-label" style="color:' + scoreTier.color + '">' + invEsc(verdictLabel) + '</div>' +
        '<div class="tf-verdict-sub">' + invEsc(attackType) + (targetBrand ? ' · targets ' + invEsc(targetBrand) : '') + '</div></div>' +
        '<div class="tf-verdict-meta">' +
        '<div><div class="tf-verdict-meta-num" style="color:' + scoreTier.color + '">' + sc + '</div><div class="tf-verdict-meta-label">Score</div></div>' +
        '<div><div class="tf-verdict-meta-num">' + threatCount + '</div><div class="tf-verdict-meta-label">Findings</div></div>' +
        '</div></div>';

      ov += '<div class="threats-scan-info">📧 ' + (scanData.domain || 'unknown') + ' · ' + threatCount + ' threat' + (threatCount !== 1 ? 's' : '') + ' detected · Evidence: ' + (isConfirmed ? 'CONFIRMED' : 'heuristic') + '</div>';

      if (findings.length > 0) {
        ov += '<div class="tf-section"><div class="tf-section-title">🚨 Threat Findings</div><div class="tf-findings-list">';
        findings.forEach(function (f) {
          var dotColor = f.level === 'critical' ? 'var(--red2)' : 'var(--yellow)';
          ov += '<div class="tf-finding-row sev-' + f.level + '"><span class="tf-finding-dot" style="background:' + dotColor + '"></span><span>' + f.icon + '</span><span>' + invEsc(f.title) + '</span></div>';
        });
        ov += '</div></div>';
      } else {
        ov += '<div class="tf-section"><div class="tf-group-empty">No threat signals on this email — see Evidence for the full check breakdown.</div></div>';
      }

      ov += '<div class="tf-section"><div class="tf-section-title">⚡ Response</div><div class="tf-response-row">' +
        '<button class="tf-response-btn block" id="tf-block-sender-btn">🚫 Block Sender</button>' +
        '<button class="tf-response-btn report" id="tf-report-btn">🚨 Report Phishing</button>' +
        '</div><div class="tf-response-feedback" id="tf-response-feedback"></div></div>';

      // ── EVIDENCE: raw auth checks, expandable per-check cards, integrity hash ──
      var ev = '';
      ev += '<div class="tf-section"><div class="tf-section-title">🔐 Email Security Evidence</div><table class="tf-evidence-table">';
      if (checks.spf) ev += tfEvidenceRow('SPF', checks.spf.pass, checks.spf.detail);
      if (checks.dkim) ev += tfEvidenceRow('DKIM', checks.dkim.pass, checks.dkim.detail, checks.dkim.inconclusive ? 'unverified' : false);
      if (checks.dmarc) ev += tfEvidenceRow('DMARC', checks.dmarc.pass, checks.dmarc.detail);
      if (checks.mx) ev += tfEvidenceRow('MX', !checks.mx.suspicious, checks.mx.detail);
      ev += tfEvidenceRow('Reply-To', !threats.replyToMismatch, threats.replyToMismatch ? threats.replyToMismatch.detail : 'No mismatch detected');
      if (checks.bimi) ev += tfEvidenceRow('BIMI', checks.bimi.hasBIMI && checks.bimi.hasVMC, checks.bimi.isImpersonatingBrand ? 'No record — impersonates ' + (checks.bimi.claimedBrand || 'a known brand') : (checks.bimi.hasBIMI ? 'Verified' : 'Not published'), !checks.bimi.hasBIMI && !checks.bimi.isImpersonatingBrand);
      if (checks.dnsbl) ev += tfEvidenceRow('DNSBL', !checks.dnsbl.listed, checks.dnsbl.listed ? (checks.dnsbl.listings || []).map(function (l) { return l.source; }).join(', ') : 'Not blacklisted');
      if (checks.urlhaus) ev += tfEvidenceRow('URLhaus', !checks.urlhaus.malicious, checks.urlhaus.malicious ? checks.urlhaus.threat : 'No malware match');
      ev += '</table></div>';

      var nonEmptyCards = cards.filter(Boolean);
      ev += '<div class="tf-section"><div class="tf-section-title">📋 Detailed Evidence <span style="font-weight:400;text-transform:none;letter-spacing:0;color:var(--text3)">— tap to expand</span></div>' + (nonEmptyCards.length ? nonEmptyCards.join('') : '<div class="tf-group-empty">No per-check detail beyond the table above.</div>') + '</div>';

      var evidenceItemCount = Object.keys(checks).filter(function (k) { return checks[k]; }).length +
        Object.keys(threats).filter(function (k) { return threats[k]; }).length +
        (iocs.domains || []).length + (iocs.urls || []).length + (iocs.ipAddresses || []).length + (iocs.emailAddresses || []).length;
      ev += '<div class="tf-section"><div class="tf-section-title">🔐 Evidence Fingerprint</div><div class="tf-integrity-box">' +
        '<div>Evidence items: <strong>' + evidenceItemCount + '</strong></div>' +
        '<div class="tf-integrity-hash" id="tf-integrity-hash">SHA-256: computing…</div>' +
        '</div></div>';

      // ── IOCs & PATH: attack chain + extracted indicators ──────────────────
      var io = '';
      io += '<div class="tf-section"><div class="tf-section-title">🔗 Attack Path</div><div class="inv-chain">';
      io += '<div class="inv-chain-node"><div class="inv-chain-node-label">Sender</div><div class="inv-chain-node-value">' + invEsc(scanData.sender || scanData.domain || 'unknown') + '</div></div>';
      if (iocs.replyTo && iocs.replyTo.length) {
        io += '<div class="inv-chain-arrow">↓</div>';
        io += '<div class="inv-chain-node"><div class="inv-chain-node-label">Reply-To</div><div class="inv-chain-node-value">' + invEsc(iocs.replyTo.join(', ')) + '</div></div>';
      }
      if (iocs.redirects && iocs.redirects.length) {
        iocs.redirects.forEach(function (r) {
          io += '<div class="inv-chain-arrow">↓</div>';
          var path = [r.originalUrl].concat(r.chain || []).concat([r.finalUrl]).filter(Boolean);
          io += '<div class="inv-chain-node"><div class="inv-chain-node-label">Redirect Chain</div><div class="inv-chain-node-value">' + invEsc(path.join(' → ') || 'no data') + '</div></div>';
        });
      } else if (iocs.urls && iocs.urls.length) {
        io += '<div class="inv-chain-arrow">↓</div>';
        io += '<div class="inv-chain-node"><div class="inv-chain-node-label">URL</div><div class="inv-chain-node-value">' + invEsc(iocs.urls[0]) + (iocs.urls.length > 1 ? ' (+' + (iocs.urls.length - 1) + ' more)' : '') + '</div></div>';
      }
      io += '</div></div>';

      io += '<div class="tf-section"><div class="tf-section-title">🔎 Indicators of Compromise</div>';
      io += '<div class="inv-section"><div class="inv-section-title">🌐 Domains (' + (iocs.domains || []).length + ')</div>' + invChipRow(iocs.domains) + '</div>';
      io += '<div class="inv-section"><div class="inv-section-title">🔗 URLs (' + (iocs.urls || []).length + ')</div>' + invChipRow(iocs.urls) + '</div>';
      if (iocs.ipAddresses && iocs.ipAddresses.length) {
        io += '<div class="inv-section"><div class="inv-section-title">🖥️ IP Addresses</div>' + invChipRow(iocs.ipAddresses) + '</div>';
      }
      io += '<div class="inv-section"><div class="inv-section-title">📧 Email Addresses</div>' + invChipRow(iocs.emailAddresses) + '</div>';
      if (iocs.attachments && iocs.attachments.length) {
        io += '<div class="inv-section"><div class="inv-section-title">📎 Attachments</div>' + invChipRow(iocs.attachments.map(function (a) { return a.fileName + (a.riskLevel ? ' (' + a.riskLevel + ')' : ''); })) + '</div>';
      }
      io += '<button class="inv-copy-btn" id="tf-copy-iocs-btn">📋 Copy All IOCs</button>';
      io += '</div>';

      io += tfActiveDefenseHtml(scanData, canaryDeployment);

      var iocTotal = (iocs.domains || []).length + (iocs.urls || []).length + (iocs.ipAddresses || []).length + (iocs.emailAddresses || []).length;

      // ── TIMELINE: forensic timeline + campaign correlation ────────────────
      var timelineEntries = [];
      timelineEntries.push({ t: scanData.timestamp || Date.now(), text: 'Email received &amp; scanned by PhishAlert', flagged: false });
      timelineEntries.push({ t: scanData.timestamp || Date.now(), text: 'Sender authentication checked (SPF / DKIM / DMARC / MX)', flagged: threatCount > 0 });
      if (iocs.extractedAt) timelineEntries.push({ t: iocs.extractedAt, text: 'Indicators of compromise extracted', flagged: false });
      if (iocs.redirects && iocs.redirects.length) timelineEntries.push({ t: iocs.extractedAt || scanData.timestamp, text: 'Redirect chain resolved (' + iocs.redirects.length + ' hop' + (iocs.redirects.length !== 1 ? 's' : '') + ')', flagged: true });
      if (isConfirmed) timelineEntries.push({ t: scanData.timestamp, text: 'Threat intelligence match confirmed', flagged: true });
      if (threats.replyToMismatch) timelineEntries.push({ t: scanData.timestamp, text: 'Reply-To mismatch detected', flagged: true });
      var campaignForDomain = (campaigns || []).find(function (c) { return c.domains && c.domains.indexOf(scanData.domain) !== -1; }) || null;
      _tfCampaign = campaignForDomain;
      if (campaignForDomain) timelineEntries.push({ t: campaignForDomain.lastSeen, text: 'Correlated to existing campaign (' + campaignForDomain.emailCount + ' related emails)', flagged: true });
      if (canaryDeployment) {
        timelineEntries.push({ t: canaryDeployment.createdAtMs, text: 'Canary bait deployed (' + canaryDeployment.canaryId + ')', flagged: false });
        (canaryDeployment.events || []).forEach(function (e) {
          var label = CANARY_LABELS[e.classification] || { text: e.classification };
          timelineEntries.push({ t: e.timestampMs, text: 'Canary triggered — ' + label.text + ' (' + Math.round((e.confidence || 0) * 100) + '% confidence)', flagged: e.classification === 'suspicious_interaction' || e.classification === 'likely_human_driven' });
        });
      }
      timelineEntries.sort(function (a, b) { return (a.t || 0) - (b.t || 0); });

      var tl = '';
      tl += '<div class="tf-section"><div class="tf-section-title">🕒 Forensic Timeline</div><div class="tf-timeline">';
      timelineEntries.forEach(function (e) { tl += tfTimelineItem(e.text, e.t, e.flagged); });
      tl += '</div></div>';

      tl += '<div class="tf-section"><div class="tf-section-title">🧬 Campaign Connection</div><div class="tf-campaign-box">';
      if (campaignForDomain) {
        tl += '<div>' + (campaignForDomain.brand ? 'Impersonating <strong>' + invEsc(campaignForDomain.brand) + '</strong> — ' : '') + 'part of a coordinated cluster (' + campaignForDomain.confidence + '% confidence).</div>';
        tl += '<div class="tf-campaign-stats">' +
          '<div><div class="tf-campaign-stat-num">' + campaignForDomain.emailCount + '</div><div class="tf-campaign-stat-label">Related emails</div></div>' +
          '<div><div class="tf-campaign-stat-num">' + campaignForDomain.domainCount + '</div><div class="tf-campaign-stat-label">Domains</div></div>' +
          (campaignForDomain.urlCount ? '<div><div class="tf-campaign-stat-num">' + campaignForDomain.urlCount + '</div><div class="tf-campaign-stat-label">URLs</div></div>' : '') +
          '</div>';
        tl += '<button class="tf-campaign-link" id="tf-view-dna-btn">View in Phishing DNA →</button>';
      } else {
        tl += '<div class="inv-empty">No related campaign yet — PhishAlert needs at least two correlated emails (shared brand, Reply-To, links, subject, or a typosquat sibling domain) to flag one.</div>';
      }
      tl += '</div></div>';

      // ── Assemble groups + subnav counts, show the active group ───────────
      _tfGroups = { overview: ov, evidence: ev, iocs: io, timeline: tl };
      var subnav = document.getElementById('tf-subnav');
      if (subnav) subnav.classList.remove('hidden');
      tfSetCount('tf-count-overview', threatCount);
      tfSetCount('tf-count-evidence', nonEmptyCards.length);
      tfSetCount('tf-count-iocs', iocTotal);
      tfSetCount('tf-count-timeline', timelineEntries.length);

      // Per-group interactive handlers — re-run whenever that group is shown,
      // since switching groups replaces threats-container's innerHTML.
      _tfGroupHandlers.evidence = function () {
        tfSha256Hex(JSON.stringify({ domain: scanData.domain, score: sc, checks: checks, threats: threats, iocs: iocs, threatList: tList })).then(function (hash) {
          var text = 'SHA-256: ' + hash.substring(0, 16) + '…' + hash.substring(hash.length - 8);
          if (_tfGroups) _tfGroups.evidence = _tfGroups.evidence.replace('SHA-256: computing…', text);
          var el = document.getElementById('tf-integrity-hash');
          if (el) el.textContent = text;
        }).catch(function () {
          if (_tfGroups) _tfGroups.evidence = _tfGroups.evidence.replace('SHA-256: computing…', 'SHA-256: unavailable');
          var el = document.getElementById('tf-integrity-hash');
          if (el) el.textContent = 'SHA-256: unavailable';
        });
      };

      _tfGroupHandlers.iocs = function () {
        var copyIocsBtn = document.getElementById('tf-copy-iocs-btn');
        if (copyIocsBtn) {
          copyIocsBtn.addEventListener('click', function () {
            var lines = [];
            if (iocs.domains && iocs.domains.length) lines.push('Domains:', iocs.domains.join('\n'), '');
            if (iocs.urls && iocs.urls.length) lines.push('URLs:', iocs.urls.join('\n'), '');
            if (iocs.ipAddresses && iocs.ipAddresses.length) lines.push('IPs:', iocs.ipAddresses.join('\n'), '');
            if (iocs.emailAddresses && iocs.emailAddresses.length) lines.push('Emails:', iocs.emailAddresses.join('\n'), '');
            navigator.clipboard.writeText(lines.join('\n')).then(function () {
              copyIocsBtn.textContent = '✅ Copied!';
              setTimeout(function () { copyIocsBtn.textContent = '📋 Copy All IOCs'; }, 2000);
            });
          });
        }

        // ── Active Defense: Deploy Bait ──
        var deployBtn = document.getElementById('tf-deploy-bait-btn');
        if (deployBtn) {
          deployBtn.addEventListener('click', async function () {
            var fb = document.getElementById('tf-canary-feedback');
            if (!scanData.iocScanKey) { if (fb) fb.textContent = '⚠️ No scan context available yet — reopen the email and try again.'; return; }
            if (!confirm('Deploy a canary against this email?\n\nThis creates a synthetic tracking pixel and decoy link. No real credentials or email content are ever sent — you\'ll be shown a decoy reply to review and send yourself.')) return;
            var deploySettings = await send({ type: 'GET_SETTINGS' }) || {};
            var deployPerm = await ensureCanaryOriginPermission(deploySettings.canaryWorkerUrl);
            if (!deployPerm.granted) { if (fb) fb.textContent = '⚠️ ' + deployPerm.error; return; }
            deployBtn.disabled = true;
            deployBtn.textContent = '⏳ Deploying…';
            var result = await send({ type: 'DEPLOY_CANARY_BAIT', scanKey: scanData.iocScanKey, domain: scanData.domain || '', riskScore: sc, baitType: 'pixel' });
            deployBtn.disabled = false;
            deployBtn.textContent = '🎯 Deploy Bait';
            if (!result || result.error) { if (fb) fb.textContent = '⚠️ ' + ((result && result.error) || 'Deployment failed'); return; }
            loadThreats();
          });
        }

        // ── Active Defense: Copy Decoy Reply ──
        var copyDecoyBtn = document.getElementById('tf-copy-decoy-btn');
        if (copyDecoyBtn) {
          copyDecoyBtn.addEventListener('click', function () {
            var ta = document.getElementById('tf-canary-decoy-text');
            navigator.clipboard.writeText(ta ? ta.value : '').then(function () {
              copyDecoyBtn.textContent = '✅ Copied!';
              setTimeout(function () { copyDecoyBtn.textContent = '📋 Copy Decoy Reply'; }, 2000);
            });
          });
        }

        // ── Active Defense: Refresh Telemetry ──
        var refreshBtn = document.getElementById('tf-refresh-canary-btn');
        if (refreshBtn) {
          refreshBtn.addEventListener('click', async function () {
            var fb = document.getElementById('tf-canary-feedback');
            var refreshSettings = await send({ type: 'GET_SETTINGS' }) || {};
            var refreshPerm = await ensureCanaryOriginPermission(refreshSettings.canaryWorkerUrl);
            if (!refreshPerm.granted) { if (fb) fb.textContent = '⚠️ ' + refreshPerm.error; return; }
            refreshBtn.disabled = true;
            refreshBtn.textContent = '⏳ Checking…';
            var result = await send({ type: 'GET_CANARY_EVENTS', scanKey: scanData.iocScanKey });
            refreshBtn.disabled = false;
            refreshBtn.textContent = '🔄 Refresh Telemetry';
            if (!result) { if (fb) fb.textContent = '⚠️ Could not reach canary worker.'; return; }
            loadThreats();
          });
        }
      };

      _tfGroupHandlers.timeline = function () {
        var viewDnaBtn = document.getElementById('tf-view-dna-btn');
        if (!viewDnaBtn) return;
        viewDnaBtn.addEventListener('click', function () {
          var nav = document.querySelector('[data-tab="campaigns"]');
          if (nav) nav.click();
        });
      };

      _tfGroupHandlers.overview = function () {
        document.getElementById('tf-block-sender-btn').addEventListener('click', async function () {
          var scan = _tfScan;
          var fb = document.getElementById('tf-response-feedback');
          if (!scan || !scan.sender) { if (fb) fb.textContent = 'No sender address available for this scan.'; return; }
          if (!confirm('Block sender ' + scan.sender + '?')) return;
          var btn = document.getElementById('tf-block-sender-btn');
          btn.disabled = true;
          await send({ type: 'BLOCK_SENDER', email: scan.sender, domain: scan.domain || '', reason: 'User blocked via Threats & Forensics' });
          await send({ type: 'ADAPTIVE_SENDER_ACTION', email: scan.sender, domain: scan.domain || '', action: 'block' });
          btn.disabled = false;
          if (fb) fb.textContent = '🚫 ' + scan.sender + ' blocked and marked as threat.';
        });

        document.getElementById('tf-report-btn').addEventListener('click', async function () {
          var scan = _tfScan;
          var fb = document.getElementById('tf-response-feedback');
          if (!scan) { if (fb) fb.textContent = 'No scan data available.'; return; }
          var btn = document.getElementById('tf-report-btn');
          btn.disabled = true;
          btn.textContent = '⏳ Reporting…';
          var result = await send({ type: 'REPORT_PHISHING_ONECLICK', domain: scan.domain || '', sender: scan.sender || '', subject: (scan.subject || ''), note: 'Reported via Threats & Forensics' });
          btn.disabled = false;
          btn.textContent = '🚨 Report Phishing';
          if (!result || result.error) { if (fb) fb.textContent = '⚠️ ' + ((result && result.error) || 'Report failed'); return; }
          if (fb) fb.textContent = '✅ Reported — see the Reports tab for external filing links.';
        });
      };

      // Sub-nav clicks — attached once; delegated so it survives re-renders.
      if (!_tfSubnavAttached) {
        _tfSubnavAttached = true;
        document.querySelectorAll('.tf-subnav-btn').forEach(function (btn) {
          btn.addEventListener('click', function () { tfShowGroup(btn.getAttribute('data-tfgroup')); });
        });
      }

      tfShowGroup(_tfActiveGroup);

    } catch (e) {
      _tfGroups = null;
      var subnavErr = document.getElementById('tf-subnav');
      if (subnavErr) subnavErr.classList.add('hidden');
      container.innerHTML = '<div class="error-msg">⚠️ Error loading threats: ' + invEsc(e.message) + '</div>';
    }
  }

  function makeThreatCard(icon, title, badgeText, level, detail, explanation, isCritical) {
    var badgeClass = level === 'critical' || badgeText === 'CRITICAL' ? 'threat-badge-critical'
      : badgeText === 'SAFE' || badgeText === 'TRUSTED' || badgeText === 'LIKELY SAFE' || badgeText === 'VERIFIED' ? 'threat-badge-safe'
        : badgeText === 'INFO' ? 'threat-badge-info'
          : 'threat-badge-warn';
    var body = (detail ? '<div class="threat-card-detail">' + detail + '</div>' : '') +
      (explanation ? '<div class="threat-card-sub">' + explanation + '</div>' : '');
    if (!body) return '';
    // Collapsible card: open by default only for critical items, so the
    // evidence list reads as a scannable stack instead of a wall of text.
    return '<details class="threat-card' + (isCritical ? ' is-critical' : level === 'warn' ? ' is-warn' : '') + '"' + (isCritical ? ' open' : '') + '>' +
      '<summary class="threat-card-header">' +
      '<span class="threat-card-icon">' + icon + '</span>' +
      '<span class="threat-card-title">' + title + '</span>' +
      '<span class="threat-card-badge ' + badgeClass + '">' + badgeText + '</span>' +
      '<span class="tf-acc-chevron">›</span>' +
      '</summary>' +
      '<div class="threat-card-body">' + body + '</div>' +
      '</details>';
  }

  // ── Phishing DNA Tab — Attack Campaign Detection ──────────────────────────
  var PD_SIGNAL_LABELS = {
    brand: '🏷️ Shared impersonated brand',
    'reply-to': '↩️ Shared Reply-To domain',
    'shared-url': '🔗 Shared link infrastructure',
    subject: '✉️ Matching subject template',
    typosquat: '🎭 Typosquat-sibling domains'
  };

  function pdTimeAgo(ts) {
    var mins = Math.round((Date.now() - ts) / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return mins + 'm ago';
    var hrs = Math.round(mins / 60);
    if (hrs < 24) return hrs + 'h ago';
    return Math.round(hrs / 24) + 'd ago';
  }

  function makeCampaignCard(c) {
    var confColor = c.confidence >= 75 ? 'var(--red2)' : c.confidence >= 55 ? '#f59e0b' : 'var(--blue2)';
    var title = c.brand
      ? 'Campaign impersonating ' + c.brand.charAt(0).toUpperCase() + c.brand.slice(1)
      : 'Coordinated phishing cluster';
    var signalChips = c.signalTypes.map(function (s) {
      return '<span class="threat-tag" style="border-color:#1e3a5f;color:var(--blue2);background:#0a1a2f">' + (PD_SIGNAL_LABELS[s] || s) + '</span>';
    }).join(' ');
    var domainList = c.domains.slice(0, 6).map(function (d) { return '<div style="font-family:var(--mono);font-size:11px;color:var(--text2)">• ' + d + '</div>'; }).join('');
    var urlList = c.urlDomains.slice(0, 6).map(function (d) { return '<div style="font-family:var(--mono);font-size:11px;color:var(--text2)">• ' + d + '</div>'; }).join('');

    return '<div class="threat-card is-critical" style="border-color:rgba(220,38,38,.35)">' +
      '<div class="threat-card-header">' +
        '<span class="threat-card-icon">🧬</span>' +
        '<span class="threat-card-title">' + title + '</span>' +
        '<span class="threat-card-badge threat-badge-critical">' + c.confidence + '% confidence</span>' +
      '</div>' +
      '<div class="threat-card-detail">' +
        c.emailCount + ' related emails across ' + c.domainCount + ' sender domain' + (c.domainCount !== 1 ? 's' : '') +
        (c.urlCount ? ' and ' + c.urlCount + ' malicious URL domain' + (c.urlCount !== 1 ? 's' : '') : '') +
        '. First seen ' + pdTimeAgo(c.firstSeen) + ', latest ' + pdTimeAgo(c.lastSeen) + '.' +
      '</div>' +
      '<div style="display:flex;flex-wrap:wrap;gap:5px;margin-top:8px">' + signalChips + '</div>' +
      '<div style="display:flex;gap:18px;margin-top:10px">' +
        '<div style="flex:1"><div style="font-size:9.5px;font-weight:700;letter-spacing:.4px;color:var(--text3);text-transform:uppercase;margin-bottom:3px">Related domains</div>' + domainList + '</div>' +
        (urlList ? '<div style="flex:1"><div style="font-size:9.5px;font-weight:700;letter-spacing:.4px;color:var(--text3);text-transform:uppercase;margin-bottom:3px">Related URLs</div>' + urlList + '</div>' : '') +
      '</div>' +
      '<div style="margin-top:9px;height:6px;border-radius:3px;background:#1a2436;overflow:hidden">' +
        '<div style="height:100%;width:' + c.confidence + '%;background:' + confColor + '"></div>' +
      '</div>' +
    '</div>';
  }

  async function loadCampaigns() {
    var container = document.getElementById('campaigns-container');
    container.innerHTML = '<div class="loading">Correlating scanned emails…</div>';
    try {
      var campaigns = await send({ type: 'GET_CAMPAIGNS' });
      if (!campaigns || !campaigns.length) {
        container.innerHTML = '<div class="threat-empty"><span class="threat-empty-icon">🧬</span>' +
          '<strong>No campaigns detected yet</strong><br>' +
          '<span style="font-size:12px;margin-top:6px;display:block">' +
          'PhishAlert needs at least two correlated emails (shared brand, Reply-To, links, subject, or a typosquat sibling domain) to flag a campaign. Keep scanning — this builds automatically in the background.' +
          '</span></div>';
        return;
      }
      container.innerHTML = campaigns.map(makeCampaignCard).join('');
    } catch (e) {
      container.innerHTML = '<div class="error-msg">⚠️ Error loading campaign data: ' + invEsc(e.message) + '</div>';
    }
  }

  // ── Shared helpers used by the Threats & Forensics tab ────────────────────
  function invEsc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }

  function invChipRow(items) {
    if (!items || !items.length) return '<div class="inv-empty">None found</div>';
    return '<div class="inv-chip-row">' + items.map(function (i) {
      return '<span class="inv-chip">' + invEsc(i) + '</span>';
    }).join('') + '</div>';
  }

  function invAttackType(scan) {
    var t = scan.threats || {}, c = scan.checks || {};
    if ((t.bimi && t.bimi.isImpersonatingBrand) || (t.homograph && t.homograph.targetBrand)) return 'Brand Impersonation / Credential Phishing';
    if (t.contactLookalike) return 'Contact Lookalike Domain Phishing';
    if (t.replyToMismatch) return 'Reply-To Redirection Phishing';
    if ((c.vt && c.vt.isMalicious) || (c.dnsbl && c.dnsbl.listed)) return 'Malware / Blacklisted Infrastructure';
    if (t.urgency) return 'Social-Engineering (Urgency) Phishing';
    return (scan.score || 0) < 45 ? 'Suspected Phishing' : 'Undetermined';
  }

  // ── Incident Report button (now lives in the case header, generated for
  //    whatever scan is currently loaded in the Threats & Forensics tab) ────
  if (!_tfReportBtnAttached) {
    var _invReportBtn = document.getElementById('inv-report-btn');
    if (_invReportBtn) {
      _tfReportBtnAttached = true;
      _invReportBtn.addEventListener('click', async function () {
        var scan = _tfScan;
        if (!scan) { alert('No scan data yet — open an email first.'); return; }
        _invReportBtn.disabled = true;
        _invReportBtn.textContent = '⏳ Generating…';
        var res = await send({ type: 'GENERATE_INCIDENT_REPORT', scanEntry: scan });
        _invReportBtn.disabled = false;
        _invReportBtn.textContent = '🧾 Incident Report';
        if (!res || !res.success) {
          alert('⚠️ ' + ((res && res.error) || 'Could not generate report'));
          return;
        }
        var container = document.getElementById('threats-container');
        var existing = document.getElementById('inv-report-output');
        if (existing) existing.remove();
        var out = document.createElement('div');
        out.id = 'inv-report-output';
        out.innerHTML = '<div class="inv-report-output">' + invEsc(res.report) + '</div>' +
          '<button class="inv-copy-btn" id="inv-copy-btn">📋 Copy Report</button>';
        container.prepend(out);
        document.getElementById('inv-copy-btn').addEventListener('click', function () {
          navigator.clipboard.writeText(res.report).then(function () {
            var cb = document.getElementById('inv-copy-btn');
            cb.textContent = '✅ Copied!';
            setTimeout(function () { cb.textContent = '📋 Copy Report'; }, 2000);
          });
        });
      });
    }
  }

  function formatHeaderLabel(type) {
    var m = { reply_to_mismatch: 'Reply-To Mismatch', return_path_mismatch: 'Return-Path Mismatch', suspicious_mailer: 'Suspicious Mail Client', excessive_hops: 'Excessive Mail Hops', unusual_routing: 'Unusual Mail Routing', geo_inconsistency: 'Geographic Inconsistency', auth_results_spf_fail: 'SPF Fail (Server-Reported)', auth_results_dkim_fail: 'DKIM Fail (Server-Reported)', auth_results_dmarc_fail: 'DMARC Fail (Server-Reported)', high_spam_score: 'High Spam Score', medium_spam_score: 'Medium Spam Score', spam_flagged: 'Spam-Flagged by Server', private_originating_ip: 'Private Originating IP' };
    return m[type] || (type || '').replace(/_/g, ' ');
  }

  function getHeaderIssueExplanation(type) {
    var ex = {
      reply_to_mismatch: 'Replies will go to a different domain than the sender — a classic way to harvest responses without the real domain.',
      return_path_mismatch: 'Bounce emails go to a different domain, suggesting the sender address is forged.',
      suspicious_mailer: 'The mail client used is commonly associated with bulk spam and phishing campaigns.',
      excessive_hops: 'Email passed through an unusually large number of servers, which may indicate deliberate routing to hide origin.',
      geo_inconsistency: 'The email claims to be from one country/organisation but was routed through servers in a different country.',
      auth_results_spf_fail: 'The receiving mail server itself confirmed this email failed SPF — the sender is not authorized.',
      auth_results_dkim_fail: 'The receiving mail server confirmed the DKIM cryptographic signature is invalid or missing.',
      auth_results_dmarc_fail: 'The receiving mail server confirmed DMARC authentication failed — the sender domain is likely spoofed.',
      high_spam_score: 'The receiving server assigned a very high spam score, indicating strong spam or phishing characteristics.',
      spam_flagged: 'The receiving mail server explicitly flagged this message as spam.',
      private_originating_ip: 'The claimed originating IP is a private/internal address, suggesting the header was forged.'
    };
    return ex[type] || '';
  }

  // ── Overview stats + Trust Score Gauge ────────────────────────────────
  // ── v5: OAuth Alert Panel ──────────────────────────────────────────────
  async function renderOAuthAlert() {
    document.getElementById('pa-oauth-alert-wrap')?.remove();
    try {
      var alert = await send({ type: 'GET_OAUTH_ALERT' });
      if (!alert || (Date.now() - alert.ts > 5 * 60 * 1000)) return;

      var level = alert.verdict;
      var colors = { critical: '#ef4444', suspicious: '#f59e0b' };
      var bgs = { critical: 'rgba(239,68,68,.08)', suspicious: 'rgba(245,158,11,.07)' };
      var borders = { critical: 'rgba(239,68,68,.35)', suspicious: 'rgba(245,158,11,.35)' };

      var scopeHtml = (alert.dangerousScopes || []).map(function (s) {
        return '<div style="font-size:11px;padding:3px 8px;background:rgba(239,68,68,.1);border-radius:4px;margin-bottom:3px;color:var(--red2);font-family:var(--mono)">' + s + '</div>';
      }).join('');

      var wrap = document.createElement('div');
      wrap.id = 'pa-oauth-alert-wrap';
      wrap.style.cssText = 'background:' + bgs[level] + ';border:1px solid ' + borders[level] + ';border-radius:10px;padding:13px 14px;margin-bottom:12px';
      wrap.innerHTML =
        '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">' +
        '<span style="font-size:18px">' + (level === 'critical' ? '🚨' : '⚠️') + '</span>' +
        '<div style="flex:1">' +
        '<div style="font-weight:800;font-size:13px;color:' + (colors[level] || '#f59e0b') + '">' +
        'OAuth Consent Phishing ' + (level === 'critical' ? 'Detected' : 'Warning') +
        '</div>' +
        '<div style="font-size:11px;color:var(--text3)">Risk score: ' + alert.riskScore + '/100 · Provider: ' + (alert.provider || 'Google') + '</div>' +
        '</div>' +
        '<button id="pa-oauth-dismiss" style="margin-left:auto;background:none;border:none;cursor:pointer;font-size:14px;color:var(--text3)">✕</button>' +
        '</div>' +
        (scopeHtml ? '<div style="font-size:11px;font-weight:700;color:var(--text2);margin-bottom:5px;text-transform:uppercase;letter-spacing:.5px">Dangerous permissions:</div>' + scopeHtml : '') +
        (alert.suspiciousRedirect ? '<div style="font-size:12px;color:var(--yellow);margin-top:6px">⚠️ Suspicious redirect: ' + (alert.redirectUri || '').slice(0, 60) + '</div>' : '') +
        '<div style="font-size:11px;color:var(--text3);margin-top:8px">Do not grant consent unless you recognize and trust this application.</div>' +
        '<div style="display:flex;gap:7px;margin-top:10px">' +
        '<a href="' + (alert.url || '#') + '" target="_blank" style="flex:1;text-align:center;padding:7px;background:rgba(239,68,68,.12);color:var(--red2);border:1px solid rgba(239,68,68,.3);border-radius:7px;font-size:12px;font-weight:700;text-decoration:none">View OAuth Page</a>' +
        '<button id="pa-oauth-dismiss2" style="flex:1;padding:7px;background:var(--surface);color:var(--text2);border:1px solid var(--border);border-radius:7px;cursor:pointer;font-size:12px;font-weight:700">Dismiss</button>' +
        '</div>';

      var overview = document.getElementById('tab-overview');
      if (overview) overview.prepend(wrap);

      function dismiss() {
        wrap.remove();
        send({ type: 'CLEAR_OAUTH_ALERT' });
      }
      document.getElementById('pa-oauth-dismiss')?.addEventListener('click', dismiss);
      document.getElementById('pa-oauth-dismiss2')?.addEventListener('click', dismiss);
    } catch { }
  }

  // ── v5: Multi-client status in overview ────────────────────────────────
  function renderClientStatus() {
    if (document.getElementById('pa-client-status')) return;
    var overview = document.getElementById('tab-overview');
    if (!overview) return;

    var el = document.createElement('div');
    el.id = 'pa-client-status';
    el.style.marginBottom = '12px';
    el.innerHTML =
      '<div class="section-label" style="margin-bottom:7px">Protected Clients (v5)</div>' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:5px">' +
      [
        ['📧', 'Gmail', 'mail.google.com'],
        ['🔵', 'Outlook', 'outlook.live.com'],
        ['💜', 'Yahoo Mail', 'mail.yahoo.com'],
        ['🛡️', 'ProtonMail', 'mail.proton.me']
      ].map(function (c) {
        return '<div style="display:flex;align-items:center;gap:7px;padding:7px 9px;background:var(--surface);border:1px solid var(--border);border-radius:8px;font-size:11.5px;color:var(--text2)">' +
          '<span>' + c[0] + '</span><span style="flex:1;font-weight:600">' + c[1] + '</span>' +
          '<span style="width:7px;height:7px;border-radius:50%;background:#22c55e;flex-shrink:0"></span>' +
          '</div>';
      }).join('') +
      '</div>';

    var statsRow = document.getElementById('stats-row');
    if (statsRow && statsRow.nextSibling) overview.insertBefore(el, statsRow.nextSibling);
    else if (statsRow) statsRow.after(el);
    else overview.prepend(el);
  }

  async function loadStats() {
    try {
      var log = await send({ type: 'GET_SCAN_LOG' });
      var totalRes = await send({ type: 'GET_SCAN_TOTAL' });
      if (!log || !Array.isArray(log) || log.length === 0) return;
      document.getElementById('stats-row').style.display = 'grid';
      var realTotal = (totalRes && totalRes.total) ? totalRes.total : log.length;
      var safe = log.filter(function (e) { return e.isTrusted; }).length;
      var threats = log.filter(function (e) { return e.threats && e.threats.length > 0; }).length;
      document.getElementById('stat-total').textContent = realTotal;
      document.getElementById('stat-safe').textContent = safe;
      document.getElementById('stat-threats').textContent = threats;
      var countEl = document.getElementById('status-count');
      countEl.textContent = realTotal + ' scanned';
      countEl.style.display = 'inline';
      // Animate Trust Score Gauge for last scanned email
      var lastScan = await send({ type: 'GET_LAST_SCAN' });
      if (lastScan && lastScan.score !== undefined) renderGauge(lastScan.score, lastScan.domain);
      renderClientStatus();
      renderOAuthAlert();
    } catch (e) {
      console.warn('[PhishAlert] loadStats error:', e);
    }
  }

  // ── Visual Trust Score Gauge ───────────────────────────────────────────
  function renderGauge(score, domain) {
    var wrap = document.getElementById('gauge-wrap');
    if (!wrap) return;
    wrap.style.display = 'flex';
    var cx = 90, cy = 88, r = 68;
    function polarXY(angle) {
      return { x: cx + r * Math.cos(angle), y: cy + r * Math.sin(angle) };
    }
    function arcPath(from, to) {
      var s = polarXY(from), e = polarXY(to);
      return 'M ' + s.x.toFixed(2) + ' ' + s.y.toFixed(2) +
        ' A ' + r + ' ' + r + ' 0 1 1 ' + e.x.toFixed(2) + ' ' + e.y.toFixed(2);
    }
    var bgArc = document.getElementById('gauge-bg-arc');
    var fgArc = document.getElementById('gauge-arc');
    var scoreEl = document.getElementById('gauge-score');
    var statusEl = document.getElementById('gauge-status');
    var domainEl = document.getElementById('gauge-domain-label');
    if (!bgArc || !fgArc || !scoreEl) return;
    // Arc from left (180deg) to right (0deg) - semicircle on top
    var startAngle = Math.PI; // 180deg
    var endAngle = 0;         // 0deg
    bgArc.setAttribute('d', arcPath(startAngle, endAngle));
    fgArc.setAttribute('d', arcPath(startAngle, endAngle));
    var totalLen = Math.PI * r;
    var fill = Math.max(0, Math.min(100, score)) / 100 * totalLen;
    fgArc.style.strokeDasharray = fill.toFixed(1) + ' ' + (totalLen * 10);
    fgArc.style.strokeDashoffset = '0';
    var color = score >= 90 ? '#22c55e' : score >= 60 ? '#f59e0b' : '#ef4444';
    var label = score >= 90 ? 'TRUSTED' : score >= 60 ? 'SUSPICIOUS' : 'DANGEROUS';
    scoreEl.textContent = score;
    scoreEl.setAttribute('fill', color);
    statusEl.textContent = label;
    statusEl.setAttribute('fill', color);
    if (domainEl) domainEl.textContent = domain ? '📧 ' + domain : '';
  }

  // ── Scan Log ───────────────────────────────────────────────────────────
  async function loadLog() {
    var container = document.getElementById('log-container');
    container.innerHTML = '<div class="loading">Loading scan history…</div>';
    try {
      var log = await send({ type: 'GET_SCAN_LOG' });
      if (!log || !Array.isArray(log) || log.length === 0) {
        container.innerHTML = '<div class="empty"><span class="empty-icon">📭</span><strong>No scans yet</strong>Open any email in Gmail — PhishAlert will automatically scan it and show results here.</div>';
        return;
      }
      var html = '';
      var shown = log.slice(0, 50);
      for (var i = 0; i < shown.length; i++) {
        var e = shown[i];
        var hasCrit = e.threats && e.threats.length > 0;
        var cls = e.isTrusted ? 'ok' : hasCrit ? 'crit' : 'warn';
        var icon = e.isTrusted ? '🟢' : hasCrit ? '🚨' : '⚠️';
        var score = (e.score !== undefined && e.score !== null) ? e.score : '?';
        var scoreColor = score >= 90 ? 'var(--green2)' : score >= 50 ? 'var(--yellow)' : 'var(--red2)';
        var d = new Date(e.timestamp);
        var timeStr = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        var dateStr = d.toLocaleDateString();
        var tags = '';
        if (hasCrit) {
          tags = '<div class="log-threats">' + e.threats.map(function (t) { return '<span class="threat-tag">' + t + '</span>'; }).join('') + '</div>';
        }
        html += '<div class="log-entry ' + cls + '">' +
          '<div class="log-top"><span class="log-domain">' + icon + ' ' + (e.domain || 'unknown') + '</span><span class="log-time">' + timeStr + ' · ' + dateStr + '</span></div>' +
          '<div class="log-score" style="color:' + scoreColor + '">Score: ' + score + '/100</div>' +
          tags + '</div>';
      }
      if (log.length > 50) html += '<div style="text-align:center;font-size:11px;color:var(--text3);padding:6px">Showing 50 of ' + log.length + ' scans</div>';
      container.innerHTML = html;
    } catch (e) {
      container.innerHTML = '<div class="error-msg">⚠️ Could not load scan history: ' + invEsc(e.message) + '</div>';
    }
  }

  // ── Reports ────────────────────────────────────────────────────────────
  async function loadReports() {
    var container = document.getElementById('reports-container');
    container.innerHTML = '<div class="loading">Loading reports…</div>';
    try {
      var reports = await send({ type: 'GET_REPORTS' });
      var blocked = await send({ type: 'GET_BLOCKED' });
      var keys = Object.keys(reports || {});
      var blockedKeys = Object.keys(blocked || {});

      var html = '';

      // ── Export current scan button ────────────────────────────────────
      html += '<div class="export-bar">' +
        '<span class="export-bar-label">📤 Export Threat Report</span>' +
        '<div class="export-btns">' +
        '<button class="export-btn" id="export-current-csv">⬇ Current (CSV)</button>' +
        '<button class="export-btn export-btn-all" id="export-all-csv">⬇ All History (CSV)</button>' +
        '</div></div>';

      // ── Blocked senders ───────────────────────────────────────────────
      if (blockedKeys.length > 0) {
        html += '<div class="panel-heading" style="margin-top:10px">🚫 Blocked Senders</div>';
        for (var i = 0; i < blockedKeys.length; i++) {
          var email = blockedKeys[i];
          var b = blocked[email];
          var bDate = new Date(b.blockedAt).toLocaleDateString();
          html += '<div class="blocked-entry" data-email="' + email + '">' +
            '<div class="blocked-top">' +
            '<span class="blocked-email">🚫 ' + email + '</span>' +
            '<button class="unblock-btn" data-email="' + email + '">Unblock</button>' +
            '</div>' +
            '<div class="blocked-meta">' + (b.domain || '') + ' · Blocked ' + bDate + '</div>' +
            '</div>';
        }
      }

      // ── Community reports ─────────────────────────────────────────────
      html += '<div class="panel-heading" style="margin-top:10px">🚩 Community Reports</div>';
      if (keys.length === 0) {
        html += '<div class="empty" style="padding:16px 0"><span class="empty-icon" style="font-size:28px">🚩</span><strong>No reports yet</strong>Open a suspicious email and click 🚩 Report.</div>';
      } else {
        var sorted = keys.sort(function (a, b) { return reports[b].count - reports[a].count; });
        var maxCount = reports[sorted[0]].count;
        for (var j = 0; j < sorted.length; j++) {
          var domain = sorted[j];
          var r = reports[domain];
          var date = new Date(r.lastReported).toLocaleDateString();
          var barPct = Math.round((r.count / maxCount) * 100);
          html += '<div class="report-entry">' +
            '<div class="report-domain">🚩 ' + domain + '</div>' +
            '<div class="report-meta">Reported ' + r.count + ' time' + (r.count !== 1 ? 's' : '') + ' · Last: ' + date + '</div>' +
            '<div class="report-bar"><div class="report-bar-fill" style="width:' + barPct + '%"></div></div>' +
            '<div class="report-actions">' +
            '<button class="report-undo-btn" data-domain="' + domain + '" title="Remove this report and clear any penalty or block on its senders">\u21a9 Undo report</button>' +
            '</div>' +
            '</div>';
        }
      }

      container.innerHTML = html;

      // Wire up unblock buttons
      container.querySelectorAll('.unblock-btn').forEach(function (btn) {
        btn.addEventListener('click', async function () {
          var email = btn.dataset.email;
          if (!confirm('Unblock ' + email + '?')) return;
          await send({ type: 'UNBLOCK_SENDER', email: email });
          loadReports();
        });
      });

      // Wire up Undo report
      container.querySelectorAll('.report-undo-btn').forEach(function (btn) {
        btn.addEventListener('click', async function () {
          var domain = btn.dataset.domain;
          if (!confirm('Undo the report for ' + domain + '?\n\nThis removes the report and clears any penalty or block on its senders.')) return;
          btn.disabled = true;
          await send({ type: 'CLEAR_COMMUNITY_REPORT', domain: domain, whitelist: false });
          loadReports();
        });
      });

      // Wire up export buttons
      document.getElementById('export-current-csv').addEventListener('click', async function () {
        var scan = await send({ type: 'GET_LAST_SCAN' });
        if (!scan) { alert('No current email scan found. Open an email in Gmail first.'); return; }
        var res = await send({ type: 'EXPORT_CSV', mode: 'current', scanEntry: scan });
        if (res && res.csv) downloadCSV(res.csv, 'phishalert-current-scan.csv');
      });

      document.getElementById('export-all-csv').addEventListener('click', async function () {
        var res = await send({ type: 'EXPORT_CSV', mode: 'all' });
        if (res && res.csv) downloadCSV(res.csv, 'phishalert-scan-history.csv');
        else alert('No scan history to export.');
      });

    } catch (e) {
      container.innerHTML = '<div class="error-msg">⚠️ Could not load reports: ' + invEsc(e.message) + '</div>';
    }
  }

  function downloadCSV(csvContent, filename) {
    var blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ── Settings ───────────────────────────────────────────────────────────
  // Saves a partial settings object right away (background merges it into stored settings).
  // Shows the existing "saved" confirmation, and reverts the UI + tells the user if it failed.
  async function persistToggle(partial) {
    try {
      var r = await send({ type: 'SAVE_SETTINGS', settings: partial });
      if (!r || r.success === false) throw new Error((r && r.error) || 'save failed');
      var msg = document.getElementById('saved-msg');
      if (msg) { msg.style.display = 'block'; setTimeout(function () { msg.style.display = 'none'; }, 1500); }
    } catch (e) {
      var errEl = document.getElementById('settings-error');
      if (errEl) { errEl.className = 'error-msg'; errEl.textContent = '⚠️ Could not save setting: ' + e.message; errEl.style.display = 'block'; }
      loadSettings();   // re-sync the switches with what is actually stored
    }
  }

  async function loadSettings() {
    var errEl = document.getElementById('settings-error');
    errEl.style.display = 'none';
    try {
      var res = await send({ type: 'GET_SETTINGS' });
      // Notification toggle
      var notifToggle = document.getElementById('notif-toggle');
      if (notifToggle) notifToggle.checked = res ? (res.notificationsEnabled !== false) : true;

      // UPGRADE 3: Show encrypted key status
      var keyStatus = await send({ type: 'GET_API_KEYS' });
      // Keys exist only in the encrypted store (never in settings), so show the
      // masked value from there; the save handler below skips masked values, so
      // they are never written back.
      if (keyStatus) {
        [['vt-key', 'vtApiKey'], ['groq-key', 'groqApiKey'], ['phishtank-key', 'phishtankApiKey']].forEach(function (p) {
          var el = document.getElementById(p[0]);
          if (el && !el.value && keyStatus[p[1]]) el.value = keyStatus[p[1]];
        });
      }
      var encStatus = document.getElementById('enc-key-status');
      if (encStatus && keyStatus) {
        var parts = [];
        if (keyStatus.hasVT)   parts.push('🔑 VT key encrypted');
        if (keyStatus.hasGroq) parts.push('🔑 Groq key encrypted');
        if (keyStatus.hasPhishTank) parts.push('🔑 PhishTank key encrypted');
        if (keyStatus.hasCanary) parts.push('🔑 Canary key encrypted');
        encStatus.textContent = parts.length ? parts.join(' · ') : '🔓 No keys saved yet';
        encStatus.className = parts.length ? 'enc-status enc-ok' : 'enc-status enc-none';
      }

      // Active Defense: dedicated status readout for the canary section
      // (zero-setup: nothing to configure, so there is no status readout to maintain)

      // Privacy: AI features are opt-in (default OFF)
      var aiConsentToggle = document.getElementById('ai-consent-toggle');
      if (aiConsentToggle) aiConsentToggle.checked = !!(res && res.aiConsent === true);
      var aiAutoToggle = document.getElementById('ai-auto-toggle');
      if (aiAutoToggle) {
        aiAutoToggle.checked = !!(res && res.aiAutoClassify === true);
        aiAutoToggle.disabled = !(aiConsentToggle && aiConsentToggle.checked);
      }
      if (aiConsentToggle && !aiConsentToggle.dataset.bound) {
        aiConsentToggle.dataset.bound = '1';
        aiConsentToggle.addEventListener('change', function () {
          var a = document.getElementById('ai-auto-toggle');
          if (a) { a.disabled = !aiConsentToggle.checked; if (!aiConsentToggle.checked) a.checked = false; }
          // Persist immediately. These switches used to be written only by the "Save Settings"
          // button far below, so the popup closing/refreshing silently threw the change away.
          persistToggle({ aiConsent: aiConsentToggle.checked, aiAutoClassify: a ? (aiConsentToggle.checked && a.checked) : false });
        });
      }
      var aiAutoEl = document.getElementById('ai-auto-toggle');
      if (aiAutoEl && !aiAutoEl.dataset.bound) {
        aiAutoEl.dataset.bound = '1';
        aiAutoEl.addEventListener('change', function () {
          var c = document.getElementById('ai-consent-toggle');
          persistToggle({ aiAutoClassify: !!(c && c.checked && aiAutoEl.checked) });
        });
      }
      [['notif-toggle', 'notificationsEnabled'], ['outgoing-toggle', 'outgoingScanEnabled'], ['active-link-toggle', 'activeLinkProtectionEnabled'], ['nav-protect-toggle', 'navigationProtectionEnabled']].forEach(function (pair) {
        var el = document.getElementById(pair[0]);
        if (el && !el.dataset.bound) {
          el.dataset.bound = '1';
          el.addEventListener('change', function () { var o = {}; o[pair[1]] = el.checked; persistToggle(o); });
        }
      });
      var privacyBtn = document.getElementById('open-privacy-btn');
      if (privacyBtn && !privacyBtn.dataset.bound) {
        privacyBtn.dataset.bound = '1';
        privacyBtn.addEventListener('click', function () {
          chrome.tabs.create({ url: chrome.runtime.getURL('privacy.html') });
        });
      }

      // v5: Outgoing scan toggle
      var outToggle = document.getElementById('outgoing-toggle');
      if (outToggle) outToggle.checked = res ? (res.outgoingScanEnabled !== false) : true;

      // FEATURE NEW 3: Active Link Protection toggle
      var activeLinkToggle = document.getElementById('active-link-toggle');
      if (activeLinkToggle) activeLinkToggle.checked = res ? (res.activeLinkProtectionEnabled !== false) : true;
      var navToggle = document.getElementById('nav-protect-toggle');
      if (navToggle) navToggle.checked = res ? (res.navigationProtectionEnabled !== false) : true;

      // UPGRADE 4: Show VT quota usage
      var quota = await send({ type: 'GET_VT_QUOTA' });
      var quotaEl = document.getElementById('vt-quota-display');
      if (quotaEl && quota) {
        var remaining = Math.max(0, 490 - quota.used);
        var pct = Math.min(100, Math.round((quota.used / 490) * 100));
        var color = pct > 80 ? '#ef4444' : pct > 50 ? '#f59e0b' : '#22c55e';
        quotaEl.innerHTML = `
          <div class="quota-label">VirusTotal API Quota (today)</div>
          <div class="quota-bar-wrap"><div class="quota-bar" style="width:${pct}%;background:${color}"></div></div>
          <div class="quota-numbers"><span style="color:${color}">${quota.used}/490</span> used &nbsp;·&nbsp; ${remaining} remaining</div>
          <div class="quota-reset">Resets at midnight UTC &nbsp;·&nbsp; <button id="vt-quota-reset-btn" class="quota-reset-link" title="Resets PhishAlert's local usage counter only — does not affect your actual VirusTotal account quota">Reset local counter</button></div>`;
        var resetBtn = document.getElementById('vt-quota-reset-btn');
        if (resetBtn) {
          resetBtn.addEventListener('click', async function () {
            resetBtn.disabled = true;
            resetBtn.textContent = 'Resetting…';
            await send({ type: 'RESET_VT_QUOTA' });
            await loadSettings();
          });
        }
      }
    } catch (e) {
      errEl.className = 'error-msg';
      errEl.textContent = '⚠️ Could not load settings: ' + e.message;
      errEl.style.display = 'block';
    }
    await refreshLinkScanPermissionUI();
  }

  // ── Link redirect-chain scanning: optional broad host permission ────────
  // This is requested/removed here, directly in the popup's own click
  // handler, rather than relayed through a background message — Chrome
  // only shows the grant prompt for chrome.permissions.request() when it's
  // called synchronously from a real user gesture in an extension page, and
  // a message round-trip to the service worker doesn't reliably count.
  async function refreshLinkScanPermissionUI() {
    var btn = document.getElementById('link-scan-permission-btn');
    var statusEl = document.getElementById('link-scan-status');
    if (!btn || !statusEl) return;
    var granted = false;
    try { granted = await chrome.permissions.contains({ origins: ['https://*/*'] }); } catch {}
    btn.textContent = granted ? 'Disable' : 'Enable';
    statusEl.textContent = granted
      ? 'Enabled — links are followed hop-by-hop to their real destination.'
      : 'Disabled — links are checked by domain and threat feeds only.';
  }

  var linkScanBtn = document.getElementById('link-scan-permission-btn');
  if (linkScanBtn) {
    linkScanBtn.addEventListener('click', async function () {
      linkScanBtn.disabled = true;
      try {
        var granted = await chrome.permissions.contains({ origins: ['https://*/*'] });
        if (granted) {
          await chrome.permissions.remove({ origins: ['https://*/*'] });
        } else {
          await chrome.permissions.request({ origins: ['https://*/*'] });
        }
      } catch {}
      linkScanBtn.disabled = false;
      await refreshLinkScanPermissionUI();
    });
  }

  // ── Active Defense: origin permission helper ─────────────────────────────
  // FIX: the canary worker is a user-supplied, arbitrary domain — it's never
  // in host_permissions (those only cover PhishAlert's own fixed API
  // domains). Without a granted permission for that origin, background.js's
  // fetch() to it fails with a generic "Failed to fetch", which looks like
  // the worker is down even when the URL/key are both correct. This
  // requests just that one origin out of the "https://*/*" optional
  // permission already declared in the manifest. Must run synchronously
  // from the click handler (same reason refreshLinkScanPermissionUI below
  // does its own chrome.permissions call here instead of round-tripping
  // through the service worker) — otherwise Chrome silently denies it
  // instead of prompting.
  async function ensureCanaryOriginPermission(workerUrl) {
    // Built-in canary server is declared in manifest host_permissions — nothing to ask for.
    if (!workerUrl) return { granted: true };
    var origin;
    try { origin = new URL(workerUrl).origin + '/*'; }
    catch (e) { return { granted: false, error: 'That worker URL doesn\'t look valid.' }; }
    try {
      var already = await chrome.permissions.contains({ origins: [origin] });
      if (already) return { granted: true };
      var granted = await chrome.permissions.request({ origins: [origin] });
      return granted
        ? { granted: true }
        : { granted: false, error: 'Permission for ' + origin + ' was not granted — Test Connection and Deploy Bait need it to reach your worker.' };
    } catch (e) {
      return { granted: false, error: e.message };
    }
  }

  document.getElementById('save-btn').addEventListener('click', async function () {
      var key         = document.getElementById('vt-key').value.trim();
      var groqKey     = document.getElementById('groq-key').value.trim();
      var phishtankKey = document.getElementById('phishtank-key') ? document.getElementById('phishtank-key').value.trim() : '';
      var errEl = document.getElementById('settings-error');
      errEl.style.display = 'none';
      try {
        var notifEnabled     = document.getElementById('notif-toggle')       ? document.getElementById('notif-toggle').checked       : true;
        var outgoingEnabled  = document.getElementById('outgoing-toggle')    ? document.getElementById('outgoing-toggle').checked    : true;
        var activeLinkEnabled = document.getElementById('active-link-toggle') ? document.getElementById('active-link-toggle').checked : true;
        var aiConsentOn = document.getElementById('ai-consent-toggle') ? document.getElementById('ai-consent-toggle').checked : false;
        var aiAutoOn = aiConsentOn && document.getElementById('ai-auto-toggle') ? document.getElementById('ai-auto-toggle').checked : false;
        // UPGRADE 3: Save settings AND encrypt keys in one call
        var settingsToSave = { vtApiKey: key, groqApiKey: groqKey, phishtankApiKey: phishtankKey, notificationsEnabled: notifEnabled, outgoingScanEnabled: outgoingEnabled, activeLinkProtectionEnabled: activeLinkEnabled, aiConsent: aiConsentOn, aiAutoClassify: aiAutoOn };
        // Masked placeholders (shown for already-saved keys) are not real keys — never send them back.
        ['vtApiKey', 'groqApiKey', 'phishtankApiKey'].forEach(function (k) { if (String(settingsToSave[k]).indexOf('\u2022') !== -1) delete settingsToSave[k]; });
        var res = await send({ type: 'SAVE_SETTINGS', settings: settingsToSave });
      if (res && res.success !== false) {
        var msg = document.getElementById('saved-msg');
        msg.style.display = 'block';
        setTimeout(function () { msg.style.display = 'none'; }, 2500);
        // Refresh key status and quota display
        loadSettings();
      } else {
        throw new Error('Save returned failure');
      }
    } catch (e) {
      errEl.className = 'error-msg';
      errEl.textContent = '⚠️ Could not save: ' + e.message;
      errEl.style.display = 'block';
    }
  });

  document.getElementById('full-clear-btn').addEventListener('click', async function () {
    if (!confirm('EXTREME PRIVACY WIPE: This will permanently delete ALL scan history, sender trust data, whitelists, and your encrypted API keys.\n\nAre you absolutely sure?')) return;
    try {
      var res = await send({ type: 'CLEAR_ALL_DATA' });
      if (res && res.success) {
        alert('All local data has been wiped. The extension is now in its original state.');
        window.location.reload();
      } else {
        throw new Error('Wipe failed');
      }
    } catch (e) {
      alert('Error wiping data: ' + e.message);
    }
  });

  // ── Unified Tools Tab ──────────────────────────────────────────────────
  var utEmailContent = null;
  var utListenersAttached = false;
  var utLastDraft = '';

  async function loadTools() {
    utEmailContent = null;

    var emailRow = document.getElementById('ut-email-row');
    var analysisRow = document.getElementById('ut-analysis-row');
    var priReason = document.getElementById('ut-pri-reason');
    var secContent = document.getElementById('ut-sec-content');

    emailRow.innerHTML = '<div class="loading">Loading current email…</div>';
    analysisRow.style.display = 'none';
    priReason.style.display = 'none';
    secContent.innerHTML = '<div class="loading">Scanning…</div>';

    // FEATURE 3: Check for Groq key
    var keyStatus = await send({ type: 'GET_API_KEYS' });
    if (keyStatus && !keyStatus.hasGroq) {
       var notice = document.getElementById('groq-missing-notice').cloneNode(true);
       notice.style.display = 'block';
       secContent.innerHTML = '';
       secContent.appendChild(notice);
       return;
    }

    // Reset panes to default (security active)
    document.querySelectorAll('.ut-tab').forEach(function (t) { t.classList.remove('active'); });
    document.querySelectorAll('.ut-pane').forEach(function (p) { p.classList.remove('active'); });
    document.querySelector('[data-utab="security"]').classList.add('active');
    document.getElementById('ut-pane-security').classList.add('active');
    document.getElementById('ut-summary-output').style.display = 'none';
    document.getElementById('ut-draft-output').style.display = 'none';
    document.getElementById('ut-copy-btn').style.display = 'none';

    try {
      var emailContent = await send({ type: 'GET_EMAIL_CONTENT' });
      var analysis = await send({ type: 'GET_AI_ANALYSIS' });
      var phase4 = await send({ type: 'GET_PHASE4' });
      var scanData = await send({ type: 'GET_LAST_SCAN' });

      if (!emailContent) {
        emailRow.innerHTML = '<div class="empty"><span class="empty-icon">📧</span><strong>No email open</strong>Open an email in Gmail — tools will appear here.</div>';
        secContent.innerHTML = '';
        return;
      }

      utEmailContent = emailContent;

      // ── Email row ──────────────────────────────────────────────────────
      emailRow.innerHTML =
        '<div class="ut-email-from">📧 ' + invEsc(emailContent.sender || 'Unknown sender') + '</div>' +
        '<div class="ut-email-subject">' + (emailContent.contentWithheld
          ? '<em>Subject and body are not stored — AI features are off (Settings → AI &amp; Privacy)</em>'
          : invEsc(emailContent.subject || '(No subject)')) + '</div>';

      // ── AI classification row ─────────────────────────────────────────
      if (analysis && analysis.category) {
        var catColors = {
          Work: '#3b82f6', Personal: '#22c55e', Urgent: '#ef4444', Spam: '#64748b',
          Finance: '#f59e0b', Newsletter: '#8b5cf6', Promotional: '#ec4899', Social: '#0ea5e9'
        };
        var priIcons = { High: '🔴', Medium: '🟡', Low: '🟢' };
        var col = catColors[analysis.category] || '#64748b';
        analysisRow.style.display = 'flex';
        analysisRow.innerHTML =
          '<span class="ut-cat-badge" style="background:' + col + '22;color:' + col + ';border-color:' + col + '">' + invEsc(analysis.category || '?') + '</span>' +
          '<span class="ut-pri-badge">' + (priIcons[analysis.priority] || '') + ' ' + invEsc(analysis.priority || '?') + ' Priority</span>' +
          (analysis.deadline ? '<span class="ut-deadline">⏰ ' + invEsc(analysis.deadline) + '</span>' : '');
        if (analysis.priorityReason) {
          priReason.style.display = 'block';
          priReason.className = 'ut-pri-reason';
          priReason.textContent = 'ℹ️ ' + analysis.priorityReason;
        }
      }

      // ── Security pane ─────────────────────────────────────────────────
      renderSecurityPane(secContent, phase4, scanData);

      // ── Attach listeners once ─────────────────────────────────────────
      if (!utListenersAttached) {
        utListenersAttached = true;

        // Inner tab switching
        document.querySelectorAll('.ut-tab').forEach(function (tab) {
          tab.addEventListener('click', function () {
            document.querySelectorAll('.ut-tab').forEach(function (t) { t.classList.remove('active'); });
            document.querySelectorAll('.ut-pane').forEach(function (p) { p.classList.remove('active'); });
            tab.classList.add('active');
            document.getElementById('ut-pane-' + tab.dataset.utab).classList.add('active');
          });
        });

        // Tone buttons (for draft)
        document.querySelectorAll('.ut-tone-btn').forEach(function (btn) {
          btn.addEventListener('click', function () {
            document.querySelectorAll('.ut-tone-btn').forEach(function (b) { b.classList.remove('active'); });
            btn.classList.add('active');
          });
        });

        // Summarize
        document.getElementById('ut-summarize-btn').addEventListener('click', async function () {
          if (!utEmailContent) return;
          var out = document.getElementById('ut-summary-output');
          out.style.display = 'block';
          out.innerHTML = '<div class="loading">⏳ Summarizing…</div>';
          var a = await send({ type: 'CLASSIFY_EMAIL', subject: utEmailContent.subject, body: utEmailContent.body });
          if (!a || a.error) {
            out.innerHTML = '<div class="error-msg">⚠️ ' + invEsc(a && a.error ? a.error : 'Failed') + '</div>';
            return;
          }
          var pts = (a.keyPoints || []).map(function (p) { return '<li>' + invEsc(p) + '</li>'; }).join('');
          var acts = (a.actionItems || []).map(function (x) { return '<li>✅ ' + invEsc(x) + '</li>'; }).join('');
          out.innerHTML = '<div class="ut-result-box">' +
            '<p>' + invEsc(a.summary || 'No summary.') + '</p>' +
            (pts ? '<strong>Key Points</strong><ul>' + pts + '</ul>' : '') +
            (acts ? '<strong>Action Items</strong><ul>' + acts + '</ul>' : '') +
            (a.deadline ? '<div class="ut-deadline-row">⏰ Deadline: <strong>' + invEsc(a.deadline) + '</strong></div>' : '') +
            '</div>';
        });

        // ── FEATURE 1+2: Tone / Manipulation Analyzer + Phishing Explanation ──
        document.getElementById('ut-tone-btn').addEventListener('click', async function () {
          if (!utEmailContent) return;
          var out = document.getElementById('ut-tone-output');
          out.style.display = 'block';
          out.innerHTML = '<div class="loading">⏳ Analyzing psychological tactics…</div>';

          var a = await send({ type: 'ANALYZE_TONE', subject: utEmailContent.subject, body: utEmailContent.body });
          if (!a || a.error) {
            out.innerHTML = '<div class="error-msg">⚠️ ' + invEsc(a && a.error ? a.error : 'Failed') + '</div>';
            return;
          }

          var riskColors = { high: '#dc2626', medium: '#d97706', low: '#f59e0b', safe: '#16a34a' };
          var riskColor = riskColors[a.overallRisk] || '#374151';
          var sevColors = { high: 'ut-tone-sev-high', medium: 'ut-tone-sev-medium', low: 'ut-tone-sev-low' };

          var tacticsHtml = '';
          if (!a.tactics || a.tactics.length === 0) {
            tacticsHtml = '<div class="ut-tone-safe">✅ No manipulation tactics detected</div>';
          } else {
            tacticsHtml = (a.tactics || []).map(function (t) {
              return '<div class="ut-tone-tactic">' +
                '<div class="ut-tone-tactic-header">' +
                '<span class="ut-tone-label-badge">' + invEsc(t.label || t.type) + '</span>' +
                '<span class="ut-tone-sev ' + (Object.prototype.hasOwnProperty.call(sevColors, t.severity) ? sevColors[t.severity] : '') + '">' + invEsc(String(t.severity || '').toUpperCase()) + '</span>' +
                '</div>' +
                (t.evidence ? '<div class="ut-tone-evidence">💬 "' + invEsc(String(t.evidence).substring(0, 120)) + '"</div>' : '') +
                '<div class="ut-tone-why">' + invEsc(t.explanation || '') + '</div>' +
                '</div>';
            }).join('');
          }

          var scanData = await send({ type: 'GET_LAST_SCAN' });
          var explainBtn = (!a.tactics || a.tactics.length > 0 || (scanData && !scanData.isTrusted))
            ? '<button class="ut-explain-btn" id="ut-inline-explain-btn">🔍 Why is this email dangerous? (Plain English)</button><div id="ut-inline-explain-out"></div>'
            : '';

          out.innerHTML = '<div class="ut-tone-card">' +
            '<div class="ut-tone-risk" style="color:' + riskColor + '">Risk Level: <strong>' + invEsc(String(a.overallRisk || 'unknown').toUpperCase()) + '</strong></div>' +
            '<p class="ut-tone-summary-text">' + invEsc(a.summary || '') + '</p>' +
            '<div class="ut-tone-tactics">' + tacticsHtml + '</div>' +
            (a.recommendation ? '<div class="ut-tone-rec">💡 ' + invEsc(a.recommendation) + '</div>' : '') +
            '</div>' +
            explainBtn;

          // Phishing explanation sub-button
          if (document.getElementById('ut-inline-explain-btn')) {
            document.getElementById('ut-inline-explain-btn').addEventListener('click', async function () {
              var explainOut = document.getElementById('ut-inline-explain-out');
              explainOut.innerHTML = '<div class="loading" style="padding:8px">⏳ Generating plain-English explanation…</div>';
              var sd = await send({ type: 'GET_LAST_SCAN' });
              var ex = await send({ type: 'EXPLAIN_PHISHING', subject: utEmailContent.subject, body: utEmailContent.body, scanData: sd });
              if (!ex || ex.error) {
                explainOut.innerHTML = '<div class="error-msg">⚠️ ' + invEsc(ex && ex.error ? ex.error : 'Failed') + '</div>';
                return;
              }
              explainOut.innerHTML = '<div class="ut-explain-card">' +
                '<div class="ut-explain-header">🔍 Why This Email Is Dangerous</div>' +
                '<div class="ut-explain-text">' + invEsc(ex.explanation || '').replace(/\r?\n/g, '<br>') + '</div>' +
                '</div>';
            });
          }
        });

        // ── FEATURE 3: Thread-aware Draft Reply ────────────────────────────
        document.getElementById('ut-generate-btn').addEventListener('click', async function () {
          if (!utEmailContent) return;
          var tone = (document.querySelector('.ut-tone-btn.active') || { dataset: { tone: 'formal' } }).dataset.tone;
          var isThreadAware = document.getElementById('ut-thread-check') && document.getElementById('ut-thread-check').checked;
          var draftOut = document.getElementById('ut-draft-output');
          var copyBtn = document.getElementById('ut-copy-btn');
          draftOut.style.display = 'block';
          draftOut.innerHTML = '<div class="loading" style="padding:8px">⏳ Drafting' + (isThreadAware ? ' (reading full thread)' : '') + '…</div>';
          copyBtn.style.display = 'none';

          var res;
          if (isThreadAware) {
            var threadData = await send({ type: 'GET_THREAD_MESSAGES' });
            var threadMessages = threadData && threadData.messages && threadData.messages.length > 1
              ? threadData.messages
              : null;
            if (threadMessages) {
              res = await send({ type: 'DRAFT_THREAD_REPLY', subject: utEmailContent.subject, threadMessages: threadMessages, tone: tone });
            } else {
              res = await send({ type: 'DRAFT_REPLY', subject: utEmailContent.subject, body: utEmailContent.body, tone: tone });
            }
          } else {
            res = await send({ type: 'DRAFT_REPLY', subject: utEmailContent.subject, body: utEmailContent.body, tone: tone });
          }

          if (!res || res.error) {
            draftOut.innerHTML = '<div class="error-msg">⚠️ ' + invEsc(res && res.error ? res.error : 'Failed') + '</div>';
            return;
          }
          utLastDraft = res.draft || '';
          var threadNote = res.threadAware ? '<div style="font-size:11px;color:#2563eb;font-style:italic;margin-bottom:5px">🧵 Thread-aware draft — AI read the full conversation</div>' : '';
          draftOut.innerHTML = threadNote + '<div style="white-space:pre-wrap;font-size:12px;color:#cbd5e1;line-height:1.7">' + invEsc(utLastDraft) + '</div>';
          copyBtn.style.display = 'block';
        });

        // Copy draft
        document.getElementById('ut-copy-btn').addEventListener('click', function () {
          navigator.clipboard.writeText(utLastDraft);
          document.getElementById('ut-copy-btn').textContent = '✅ Copied!';
          setTimeout(function () { document.getElementById('ut-copy-btn').textContent = '📋 Copy Draft'; }, 2000);
        });

        // ── FEATURE 4: Email Coach ─────────────────────────────────────────
        document.getElementById('ut-coach-btn').addEventListener('click', async function () {
          var subject = (document.getElementById('ut-coach-subject').value || '').trim();
          var body = (document.getElementById('ut-coach-body').value || '').trim();
          if (!body) {
            document.getElementById('ut-coach-output').style.display = 'block';
            document.getElementById('ut-coach-output').innerHTML = '<div class="error-msg">⚠️ Please paste your email body first.</div>';
            return;
          }
          var out = document.getElementById('ut-coach-output');
          out.style.display = 'block';
          out.innerHTML = '<div class="loading">⏳ Reviewing your email…</div>';

          var a = await send({ type: 'COACH_EMAIL', subject: subject, body: body });
          if (!a || a.error) {
            out.innerHTML = '<div class="error-msg">⚠️ ' + invEsc(a && a.error ? a.error : 'Failed') + '</div>';
            return;
          }

          var gradeColors = { A: '#15803d', B: '#2563eb', C: '#d97706', D: '#dc2626', F: '#7f1d1d' };
          var gradeColor = gradeColors[a.grade] || '#374151';
          var scoreColor = (a.overallScore || 0) >= 80 ? '#15803d' : (a.overallScore || 0) >= 60 ? '#d97706' : '#dc2626';

          var strengthsHtml = (a.strengths || []).map(function (s) {
            return '<div class="ut-coach-strength">✅ ' + invEsc(s) + '</div>';
          }).join('');

          var improvementsHtml = (a.improvements || []).map(function (imp) {
            return '<div class="ut-coach-improvement">' +
              '<div class="ut-coach-imp-area">' + invEsc(imp.area || '') + '</div>' +
              '<div class="ut-coach-imp-issue">❗ ' + invEsc(imp.issue || '') + '</div>' +
              '<div class="ut-coach-imp-fix">💡 ' + invEsc(imp.suggestion || '') + '</div>' +
              '</div>';
          }).join('');

          var rewriteHtml = a.rewrittenSubject
            ? '<div class="ut-coach-rewrite"><div class="ut-coach-rewrite-label">✏️ Suggested Subject Line</div><div class="ut-coach-rewrite-val">' + invEsc(a.rewrittenSubject) + '</div></div>'
            : '';

          out.innerHTML =
            '<div class="ut-coach-result">' +
            '<div class="ut-coach-grade" style="color:' + gradeColor + '">' + invEsc(a.grade || '?') + '</div>' +
            '<div class="ut-coach-score-row">' +
            '<span class="ut-coach-score-badge" style="background:' + scoreColor + '22;color:' + scoreColor + ';border:1px solid ' + scoreColor + '">' + invEsc(a.overallScore || 0) + '/100</span>' +
            '</div>' +
            '<p class="ut-coach-summary">' + invEsc(a.summary || '') + '</p>' +
            (a.toneAssessment ? '<p style="font-size:11.5px;color:#94a3b8;margin-bottom:6px">🎭 ' + invEsc(a.toneAssessment) + '</p>' : '') +
            (a.readabilityNote ? '<p style="font-size:11.5px;color:#94a3b8;margin-bottom:10px">📖 ' + invEsc(a.readabilityNote) + '</p>' : '') +
            (strengthsHtml ? '<div class="ut-coach-section"><div class="ut-coach-section-title">Strengths</div>' + strengthsHtml + '</div>' : '') +
            (improvementsHtml ? '<div class="ut-coach-section"><div class="ut-coach-section-title">Improvements</div>' + improvementsHtml + '</div>' : '') +
            rewriteHtml +
            '</div>';
        });
      }

    } catch (e) {
      emailRow.innerHTML = '<div class="error-msg">⚠️ Error: ' + invEsc(e.message) + '</div>';
    }
  }

  function renderSecurityPane(container, phase4, scanData) {
    var items = [];

    // ── Score card at top ─────────────────────────────────────────────
    if (scanData && scanData.score !== undefined) {
      var sc = scanData.score;
      var scoreColor = sc >= 90 ? '#22c55e' : sc >= 60 ? '#f59e0b' : '#ef4444';
      var scoreLabel = sc >= 90 ? 'Trusted' : sc >= 60 ? 'Suspicious' : 'Dangerous';
      var scoreIcon = sc >= 90 ? '🟢' : sc >= 60 ? '⚠️' : '🚨';
      items.push({
        cls: sc >= 90 ? 'safe' : sc >= 60 ? 'warn' : 'danger', icon: scoreIcon,
        label: scoreIcon + ' ' + scoreLabel + ' — Trust Score: ' + sc + '/100',
        detail: 'Domain: ' + (scanData.domain || '')
      });
    }

    // ── SPF / DKIM / DMARC ────────────────────────────────────────────
    var checks = scanData && scanData.checks;
    if (checks) {
      var spf = checks.spf;
      var dkim = checks.dkim;
      var dmarc = checks.dmarc;
      if (spf) items.push({ cls: spf.pass ? 'safe' : 'danger', icon: '🔒', label: 'SPF: ' + (spf.pass ? 'Pass' : 'Fail'), detail: spf.detail || '' });
      if (dkim) items.push({ cls: dkim.pass ? 'safe' : 'warn', icon: '✍️', label: 'DKIM: ' + (dkim.pass ? 'Pass' : (dkim.inconclusive ? 'Unverified' : 'Fail')), detail: dkim.detail || '' });
      if (dmarc) items.push({ cls: dmarc.pass ? 'safe' : 'warn', icon: '📋', label: 'DMARC: ' + (dmarc.pass ? 'Pass (' + (dmarc.policy || '') + ')' : 'Fail'), detail: dmarc.detail || '' });

      // ── FEATURE 1: MX Record Validation ──────────────────────────────
      var mx = checks.mx;
      if (mx) {
        if (mx.suspicious) {
          items.push({ cls: 'danger', icon: '📮', label: 'No MX Records — send-only domain', detail: 'Phishing domains often have no MX. This domain cannot receive email.' });
        } else {
          items.push({ cls: 'safe', icon: '📮', label: 'MX Records valid — ' + (mx.count || 0) + ' record(s)', detail: mx.detail || '' });
        }
      }

      // ── Domain age ────────────────────────────────────────────────────
      var age = checks.age;
      if (age) {
        var ageClass = (age.isVeryNew || age.isNew) ? 'warn' : 'safe';
        items.push({ cls: ageClass, icon: '📅', label: 'Domain Age: ' + (age.detail || 'Unknown'), detail: age.isNew ? 'Domains under 6 months old are higher risk' : '' });
      }
    }

    // ── FEATURE 3: Punycode / IDN Detection ──────────────────────────
    var threats = scanData && scanData.threats;
    if (threats) {
      var puny = threats.punycode;
      if (puny && puny.hasPunycode) {
        items.push({ cls: 'danger', icon: '🔤', label: 'Punycode / IDN Domain Detected', detail: puny.detail || ('Decoded: ' + (puny.decoded || '')) });
      }

      // ── Display name spoofing ─────────────────────────────────────────
      var spoof = threats.displayNameSpoof;
      if (spoof && spoof.spoofing) {
        items.push({ cls: 'danger', icon: '🎭', label: 'Display Name Spoofing', detail: spoof.detail || '' });
      } else if (spoof) {
        items.push({ cls: 'safe', icon: '🎭', label: 'No display name spoofing', detail: '' });
      }

      // ── Homograph ─────────────────────────────────────────────────────
      var hom = threats.homograph;
      if (hom && hom.detected) {
        items.push({ cls: 'danger', icon: '🔤', label: 'IDN Homograph: mimics "' + hom.targetBrand + '"', detail: hom.detail || '' });
      }
    }

    // ── VirusTotal ────────────────────────────────────────────────────
    var vt = checks && checks.vt;
    if (vt && vt.available) {
      if (vt.isMalicious) {
        items.push({ cls: 'danger', icon: '🦠', label: 'VirusTotal: Malicious (' + vt.maliciousCount + ' engines)', detail: 'Flagged by ' + vt.maliciousCount + '/' + vt.totalEngines + ' security engines' });
      } else {
        items.push({ cls: 'safe', icon: '🦠', label: 'VirusTotal: Clean', detail: '0/' + vt.totalEngines + ' engines flagged this domain' });
      }
    } else if (vt && !vt.available) {
      items.push({ cls: 'info', icon: '🦠', label: 'VirusTotal: ' + (vt.error || 'No API key'), detail: 'Add a free VT key in Settings for deeper scanning' });
    }

    // ── FEATURE 2: Deep header analysis ──────────────────────────────
    var ha = phase4 && phase4.headerAnalysis;
    if (ha) {
      if (ha.issues && ha.issues.length > 0) {
        ha.issues.forEach(function (issue) {
          items.push({
            cls: issue.severity === 'high' ? 'danger' : issue.severity === 'medium' ? 'warn' : 'info',
            icon: '📨',
            label: formatHeaderIssueLabel(issue.type),
            detail: issue.detail
          });
        });
        // Show hop count if available
        if (ha.info && ha.info.hopCount !== undefined) {
          items.push({ cls: ha.info.hopCount > 10 ? 'warn' : 'safe', icon: '🔀', label: 'Mail Hops: ' + ha.info.hopCount, detail: ha.info.hopCount > 6 ? 'Unusual routing chain' : 'Normal routing' });
        }
        // Geo inconsistency
        if (ha.info && ha.info.routingCountries && ha.info.routingCountries.length > 0) {
          items.push({ cls: 'info', icon: '🌍', label: 'Routing via: ' + ha.info.routingCountries.join(', '), detail: 'Countries detected in mail header chain' });
        }
        // Auth-Results
        if (ha.info && ha.info.authResults) {
          var ar = ha.info.authResults;
          var arParts = [];
          if (ar.spf) arParts.push('SPF: ' + ar.spf);
          if (ar.dkim) arParts.push('DKIM: ' + ar.dkim);
          if (ar.dmarc) arParts.push('DMARC: ' + ar.dmarc);
          if (arParts.length) items.push({ cls: 'info', icon: '🔐', label: 'Auth-Results: ' + arParts.join(' · '), detail: 'As reported by receiving mail server' });
        }
        // X-Spam
        if (ha.info && ha.info.xSpamScore !== undefined) {
          items.push({ cls: ha.info.xSpamScore >= 5 ? 'warn' : 'safe', icon: '🚩', label: 'X-Spam-Score: ' + ha.info.xSpamScore, detail: ha.info.xSpamStatus || '' });
        }
      } else {
        items.push({ cls: 'safe', icon: '📨', label: 'Headers look normal', detail: ha.issueCount === 0 ? 'No anomalies in mail header chain' : '' });
      }
    }

    // ── Sender history ────────────────────────────────────────────────
    var sh = phase4 && phase4.senderHistory;
    if (sh) {
      if (sh.replyCount > 0) {
        items.push({ cls: 'safe', icon: '✉️', label: 'Known contact — ' + sh.replyCount + ' previous repl' + (sh.replyCount > 1 ? 'ies' : 'y'), detail: sh.label || '' });
      } else if (sh.seenCount > 0) {
        items.push({ cls: 'info', icon: '👤', label: 'Seen before — ' + sh.seenCount + ' time' + (sh.seenCount > 1 ? 's' : ''), detail: 'No replies on record' });
      } else {
        items.push({ cls: 'warn', icon: '👤', label: 'First contact — never seen this sender before', detail: '' });
      }
    }

    // ── Pixel trackers ────────────────────────────────────────────────
    var tr = phase4 && phase4.trackerResult;
    if (tr && tr.trackerCount > 0) {
      var domains = (tr.trackers || []).map(function (t) { return t.domain || ''; }).filter(Boolean).slice(0, 3).join(', ');
      items.push({ cls: 'warn', icon: '👁️', label: tr.trackerCount + ' tracking pixel' + (tr.trackerCount > 1 ? 's' : '') + ' detected', detail: domains || 'Invisible spy pixels found in email' });
    } else if (tr) {
      items.push({ cls: 'safe', icon: '👁️', label: 'No tracking pixels found', detail: '' });
    }

    // ── QR codes ──────────────────────────────────────────────────────
    var qr = phase4 && phase4.qrResult;
    if (qr && qr.qrCount > 0) {
      items.push({ cls: 'warn', icon: '📷', label: 'QR code detected — verify before scanning', detail: (qr.qrFindings && qr.qrFindings[0] && qr.qrFindings[0].detail) || '' });
    } else if (qr) {
      items.push({ cls: 'safe', icon: '📷', label: 'No QR codes found', detail: '' });
    }

    // ── Attachments ───────────────────────────────────────────────────
    var atts = phase4 && phase4.attachmentResults;
    if (atts && atts.length > 0) {
      var dangerous2 = atts.filter(function (a) { return a.riskLevel === 'dangerous'; });
      var suspicious2 = atts.filter(function (a) { return a.riskLevel === 'suspicious'; });
      if (dangerous2.length > 0) {
        items.push({ cls: 'danger', icon: '📎', label: 'Dangerous attachment: ' + dangerous2[0].fileName, detail: dangerous2[0].detail });
      } else if (suspicious2.length > 0) {
        items.push({ cls: 'warn', icon: '📎', label: 'Suspicious attachment: ' + suspicious2[0].fileName, detail: suspicious2[0].detail });
      } else {
        items.push({ cls: 'safe', icon: '📎', label: atts.length + ' attachment' + (atts.length > 1 ? 's' : '') + ' scanned — clean', detail: '' });
      }
    } else {
      items.push({ cls: 'safe', icon: '📎', label: 'No attachments found', detail: '' });
    }

    if (items.length === 0) {
      container.innerHTML = '<div class="loading" style="color:var(--text3)">Open an email in Gmail to see security findings.</div>';
      return;
    }

    container.innerHTML = items.map(function (item) {
      return '<div class="ut-sec-item ut-sec-' + item.cls + '">' +
        '<span class="ut-sec-icon">' + item.icon + '</span>' +
        '<span>' +
        '<span class="ut-sec-label">' + item.label + '</span>' +
        (item.detail ? '<span class="ut-sec-detail">' + item.detail + '</span>' : '') +
        '</span>' +
        '</div>';
    }).join('');
  }

  function formatHeaderIssueLabel(type) {
    var labels = {
      'reply_to_mismatch': 'Reply-To mismatch',
      'return_path_mismatch': 'Return-Path mismatch',
      'suspicious_mailer': 'Suspicious mail client',
      'excessive_hops': 'Excessive mail hops',
      'unusual_routing': 'Unusual mail routing',
      'geo_inconsistency': 'Geographic inconsistency',
      'auth_results_spf_fail': 'SPF fail (server-reported)',
      'auth_results_dkim_fail': 'DKIM fail (server-reported)',
      'auth_results_dmarc_fail': 'DMARC fail (server-reported)',
      'high_spam_score': 'High spam score',
      'medium_spam_score': 'Medium spam score',
      'spam_flagged': 'Spam-flagged by server',
      'private_originating_ip': 'Private originating IP'
    };
    return labels[type] || ('Header: ' + (type || '').replace(/_/g, ' '));
  }


  // ── Domain Checker ─────────────────────────────────────────────────────
  document.getElementById('checker-btn').addEventListener('click', runChecker);
  document.getElementById('checker-input').addEventListener('keydown', function (e) {
    if (e.key === 'Enter') runChecker();
  });

  async function runChecker() {
    var raw = document.getElementById('checker-input').value.trim();
    if (!raw) return;
    // Accept whatever people paste: "Name <a@b.com>", "a@b.com", "https://user@b.com:8080/x?y", "b.com."
    var domain = raw.toLowerCase()
      .replace(/^.*</, '').replace(/>.*$/, '')          // Name <addr>  ->  addr
      .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')            // scheme
      .split('/')[0].split('?')[0].split('#')[0]
      .replace(/^.*@/, '')                              // user@ / email local part
      .replace(/:\d+$/, '')                             // :port
      .replace(/\.+$/, '')                              // trailing dot
      .trim();
    var errBox = document.getElementById('checker-result');
    if (!/^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$/.test(domain)) {
      errBox.className = 'checker-result';
      errBox.innerHTML = '<div style="color:var(--yellow);font-size:12px;padding:4px 0">⚠️ "' + invEsc(raw.slice(0, 60)) + '" is not a valid domain or email address.</div>';
      errBox.style.display = 'block';
      return;
    }
    document.getElementById('checker-input').value = domain;   // show what was actually checked

    var btn = document.getElementById('checker-btn');
    var resultEl = document.getElementById('checker-result');
    btn.disabled = true;
    btn.textContent = '…';
    resultEl.className = 'checker-result';
    resultEl.innerHTML = '<div style="color:var(--text3);font-size:12px;padding:4px 0">🔍 Checking <strong style="color:var(--text);font-family:var(--mono)">' + invEsc(domain) + '</strong>…</div>';
    resultEl.style.display = 'block';

    try {
      // Bug fix #2/#3: check whitelist first — whitelisted domains score 100 immediately
      var wlCheck = await send({ type: 'WHITELIST_CHECK', domain: domain });
      if (wlCheck && wlCheck.whitelisted) {
        resultEl.className = 'checker-result trusted';
        resultEl.innerHTML =
          '<div class="checker-result-header">' +
          '<span class="checker-domain">✅ ' + invEsc(domain) + '</span>' +
          '<span class="score-badge green">100/100</span>' +
          '</div>' +
          '<div class="check-tags">' +
          '<span class="check-tag pass">✓ SPF</span>' +
          '<span class="check-tag pass">✓ DKIM</span>' +
          '<span class="check-tag pass">✓ DMARC</span>' +
          '<span class="check-tag pass">🛡️ Whitelisted by you</span>' +
          '</div>' +
          '<div style="font-size:11px;color:var(--green2);margin-top:6px">This domain is on your whitelist — all checks bypassed.</div>';
        btn.disabled = false;
        btn.textContent = 'Check';
        return;
      }

      // v5: Run all checks in parallel including URLhaus + OpenPhish
      var results = await Promise.all([
        send({ type: 'VERIFY_EMAIL_AUTH', domain: domain }),  // SPF+DKIM+DMARC+MX in one call
        send({ type: 'RDAP_AGE', domain: domain }),
        send({ type: 'VIRUSTOTAL_CHECK', domain: domain }),
        send({ type: 'CHECK_PUNYCODE', domain: domain }),
        send({ type: 'URLHAUS_CHECK', url: 'https://' + domain }),  // v5: free malware feed
        send({ type: 'CHECK_OPENPHISH', url: 'https://' + domain }) // live phishing feed, no key required
      ]);

      var auth = results[0] || {};
      var rdap = results[1] || {};
      var vt = results[2] || {};
      var puny = results[3] || {};
      var urlhaus = results[4] || {};
      var openphish = results[5] || {};

      var spf = auth.spf || {};
      var dkim = auth.dkim || {};
      var dmarc = auth.dmarc || {};
      var mx = auth.mx || {};

      // Score
      var score = 0;
      if (spf.pass) score += spf.strict ? 25 : 18;
      if (dkim.pass) score += 25;
      else if (dkim.inconclusive) score += 12;
      if (dmarc.pass) {
        score += dmarc.policy === 'reject' ? 20 : dmarc.policy === 'quarantine' ? 16 : 8;
      }

      var ageLabel = 'Unknown';
      var ageClass = '';
      if (rdap && !rdap.error && rdap.ageInDays !== null) {
        var yrs = Math.floor(rdap.ageInDays / 365);
        var mos = Math.floor((rdap.ageInDays % 365) / 30);
        ageLabel = yrs > 0 ? yrs + 'y ' + mos + 'm' : mos + 'mo old';
        if (rdap.ageInDays >= 365) { score += 15; ageClass = 'pass'; }
        else if (rdap.ageInDays >= 180) { score += 8; }
        else if (rdap.ageInDays >= 30) { score += 4; ageClass = 'fail'; }
        else { ageClass = 'fail'; ageLabel = '⚠️ ' + ageLabel; }
      } else { score += 8; }

      var vtMalicious = vt.available && vt.isMalicious;
      var vtLabel = vt.available ? (vt.isMalicious ? '🦠 VT: Flagged (' + vt.maliciousCount + ')' : '✓ VT: Clean') : '🔍 VT: No key';
      var vtClass = vt.available ? (vt.isMalicious ? 'fail' : 'pass') : '';
      if (vtMalicious) score = Math.max(0, score - 40);

      // MX penalty
      if (mx.suspicious) score = Math.max(0, score - 20);
      // Punycode penalty
      if (puny.suspicious) score = Math.max(0, score - 30);
      // v5: URLhaus malware penalty
      if (urlhaus.malicious) score = Math.max(0, score - 45);
      // OpenPhish live feed / dangerous-URI penalty
      if (openphish.isPhishing) score = Math.max(0, score - 45);

      var isTrusted = score >= 90 && !puny.suspicious;
      var isCritical = vtMalicious || score < 30 || puny.suspicious || openphish.isPhishing;
      var cls = isCritical ? 'critical' : isTrusted ? 'trusted' : 'suspicious';
      var scoreCls = isCritical ? 'red' : isTrusted ? 'green' : 'yellow';
      var icon = isCritical ? '🚨' : isTrusted ? '🟢' : '⚠️';

      // Build extra tags
      var extraTags = '';
      extraTags += '<span class="check-tag ' + (mx.suspicious ? 'fail' : 'pass') + '">' + (mx.suspicious ? '✗ No MX' : '✓ MX OK') + '</span>';
      if (urlhaus.malicious) {
        extraTags += '<span class="check-tag fail">🦠 URLhaus: ' + (urlhaus.threat || 'Malware').substring(0, 30) + '</span>';
      } else {
        extraTags += '<span class="check-tag pass">✓ URLhaus: Clean</span>';
      }
      if (openphish.isPhishing) {
        extraTags += '<span class="check-tag fail">🎣 OpenPhish: ' + (openphish.reason || 'On live feed').substring(0, 30) + '</span>';
      } else {
        extraTags += '<span class="check-tag pass">✓ OpenPhish: Clean</span>';
      }
      if (puny.hasPunycode) {
        extraTags += '<span class="check-tag fail">⚠️ Punycode</span>';
      }
      if (dmarc.pass && dmarc.policy) {
        extraTags += '<span class="check-tag ' + (dmarc.policy === 'reject' ? 'pass' : '') + '" title="' + (dmarc.policy === 'none' ? 'Policy none = monitor only: receivers are not told to block spoofed mail' : 'Published DMARC policy') + '">DMARC: ' + invEsc(dmarc.policy) + (dmarc.policy === 'none' ? ' (monitor only)' : '') + '</span>';
      }

      resultEl.className = 'checker-result ' + cls;
      resultEl.innerHTML =
        '<div class="checker-result-header">' +
        '<span class="checker-domain">' + icon + ' ' + invEsc(domain) + '</span>' +
        '<span class="score-badge ' + scoreCls + '">' + score + '/100</span>' +
        '</div>' +
        '<div class="check-tags">' +
        '<span class="check-tag ' + (spf.pass ? 'pass' : 'fail') + '">' + (spf.pass ? '✓' : '✗') + ' SPF</span>' +
        '<span class="check-tag ' + (dkim.pass ? 'pass' : (dkim.inconclusive ? '' : 'fail')) + '">' + (dkim.pass ? '✓' : (dkim.inconclusive ? '?' : '✗')) + ' DKIM' + (dkim.inconclusive ? ' (unverified)' : '') + '</span>' +
        '<span class="check-tag ' + (dmarc.pass ? 'pass' : 'fail') + '">' + (dmarc.pass ? '✓' : '✗') + ' DMARC</span>' +
        '<span class="check-tag ' + ageClass + '">📅 ' + ageLabel + '</span>' +
        '<span class="check-tag ' + vtClass + '">' + vtLabel + '</span>' +
        extraTags +
        '</div>' +
        (puny.suspicious ? '<div class="checker-puny-warn">⚠️ ' + invEsc(puny.detail || 'Punycode domain detected') + '</div>' : '') +
        (spf.record ? '<div class="checker-record">SPF: <code>' + invEsc(spf.record.substring(0, 80)) + '</code></div>' : '') +
        (dmarc.record ? '<div class="checker-record">DMARC: <code>' + invEsc(dmarc.record.substring(0, 80)) + '</code></div>' : '');

    } catch (e) {
      resultEl.className = 'checker-result critical';
      resultEl.innerHTML = '<div class="checker-domain">⚠️ Error</div><div style="font-size:11px;color:var(--red2);margin-top:5px">' + invEsc(e.message) + '</div>';
    }

    btn.disabled = false;
    btn.textContent = 'Check';
  }

  // ── Verify a message from its raw headers ──────────────────────────────
  // Neither webmail DOM exposes Authentication-Results, so the user pastes the headers
  // ("Show original" in Gmail, "View message source" elsewhere). The background worker
  // reads the receiving server's own SPF/DKIM/DMARC verdict (authres.js).
  var hdrBtn = document.getElementById('hdr-verify-btn');
  if (hdrBtn) hdrBtn.addEventListener('click', runHeaderVerify);

  async function runHeaderVerify() {
    var input = document.getElementById('hdr-input');
    var out = document.getElementById('hdr-result');
    var raw = (input.value || '').trim();
    if (!raw) return;
    hdrBtn.disabled = true; hdrBtn.textContent = '…';
    out.style.display = '';
    out.className = 'checker-result';
    out.innerHTML = '<div style="color:var(--text3);font-size:12px">Reading headers…</div>';
    try {
      var r = await send({ type: 'VERIFY_MESSAGE_HEADERS', rawHeaders: raw });
      if (!r || r.error) {
        out.className = 'checker-result critical';
        out.innerHTML = '<div class="checker-domain">⚠️ ' + invEsc((r && r.error) || 'No response from the extension') + '</div>';
      } else {
        var fromMsg = r.authSource === 'message';
        var tag = function (name, v) {
          if (!v) return '<span class="check-tag">' + name + ': not reported</span>';
          return '<span class="check-tag ' + (v.pass ? 'pass' : 'fail') + '">' + (v.pass ? '✓' : '✗') + ' ' + name + '</span>';
        };
        var verdict = fromMsg
          ? (r.messageAuth && r.messageAuth.verified ? 'trusted' : 'critical')
          : 'suspicious';
        out.className = 'checker-result ' + verdict;
        out.innerHTML =
          '<div class="checker-result-header"><span class="checker-domain">' + invEsc(r.domain) + '</span></div>' +
          '<div class="check-tags">' +
            (fromMsg ? tag('SPF', r.spf) + tag('DKIM', r.dkim) + tag('DMARC', r.dmarc) : '') +
          '</div>' +
          '<div style="font-size:11px;color:var(--text2);margin-top:6px">' +
            invEsc(fromMsg
              ? r.messageAuth.reason + ' (receiver: ' + r.messageAuth.receiver + ')'
              : 'Could not verify this message from its headers. ' + (r.authNote || '') +
                ' The result below is DNS-only: it shows what the domain publishes, not whether this message was authorised.') +
          '</div>';
      }
    } catch (e) {
      out.className = 'checker-result critical';
      out.innerHTML = '<div class="checker-domain">⚠️ Error</div><div style="font-size:11px;margin-top:5px">' + invEsc(e.message) + '</div>';
    }
    hdrBtn.disabled = false; hdrBtn.textContent = 'Verify message';
  }

  // ── AI Chat ────────────────────────────────────────────────────────────
  var aiHistory = [];
  var aiCurrentDomain = null;
  var aiCurrentMsgId = null;
  var aiCurrentTimestamp = 0;
  var aiCurrentScanContext = null;
  var aiListenersAttached = false;
  var aiPollInterval = null;

  async function initAiChat() {
    // Always fetch the latest scan — reflects whichever email is open right now
    var scanContext = await send({ type: 'GET_LAST_SCAN' });

    // Use msgId (unique per Gmail message) + timestamp to detect any email switch,
    // including switching between two emails from the same domain.
    var newDomain = scanContext ? (scanContext.domain || null) : null;
    var newMsgId = scanContext ? (scanContext.msgId || null) : null;
    var newTimestamp = scanContext ? (scanContext.timestamp || 0) : 0;

    // Reset chat whenever the active email changes
    var emailChanged = newDomain !== aiCurrentDomain ||
      newMsgId !== aiCurrentMsgId ||
      newTimestamp !== aiCurrentTimestamp;

    if (emailChanged) {
      aiCurrentDomain = newDomain;
      aiCurrentMsgId = newMsgId;
      aiCurrentTimestamp = newTimestamp;
      aiCurrentScanContext = scanContext;
      aiHistory = [];

      // FEATURE 3: Check for Groq key
      var keyStatus = await send({ type: 'GET_API_KEYS' });
      var msgBox = document.getElementById('ai-messages');
      var notice = document.getElementById('groq-missing-notice');
      
      if (keyStatus && !keyStatus.hasGroq) {
        msgBox.innerHTML = '';
        msgBox.appendChild(notice.cloneNode(true)).style.display = 'block';
        return;
      }

      // Clear previous messages
      msgBox.innerHTML = '';

      if (scanContext) {
        appendAiMsg('ai', '🛡️ I\'ve loaded the scan for <strong>' + invEsc(scanContext.domain || 'this email') + '</strong> (Score: ' + invEsc(scanContext.score !== undefined ? scanContext.score + '/100' : '?') + '). Ask me anything about it!', true);
      } else {
        appendAiMsg('ai', '👋 Hi! Open an email in Gmail and I\'ll analyze it for you. Or ask me a general phishing question.', true);
      }
    }

    // Poll every 2 seconds while the AI tab is open so that switching emails
    // in Gmail is detected automatically without needing to reopen the popup.
    if (!aiPollInterval) {
      aiPollInterval = setInterval(async function () {
        // Only poll if the AI tab is still visible
        if (!document.getElementById('tab-ai').classList.contains('active')) {
          clearInterval(aiPollInterval);
          aiPollInterval = null;
          return;
        }
        var latest = await send({ type: 'GET_LAST_SCAN' });
        var latestDomain = latest ? (latest.domain || null) : null;
        var latestMsgId = latest ? (latest.msgId || null) : null;
        var latestTimestamp = latest ? (latest.timestamp || 0) : 0;

        var changed = latestDomain !== aiCurrentDomain ||
          latestMsgId !== aiCurrentMsgId ||
          latestTimestamp !== aiCurrentTimestamp;

        if (changed) {
          // New email detected — reset chat with fresh context
          aiCurrentDomain = latestDomain;
          aiCurrentMsgId = latestMsgId;
          aiCurrentTimestamp = latestTimestamp;
          aiCurrentScanContext = latest;
          aiHistory = [];

          var msgBox = document.getElementById('ai-messages');
          msgBox.innerHTML = '';

          if (latest) {
            appendAiMsg('ai', '🛡️ Switched to scan for <strong>' + invEsc(latest.domain || 'this email') + '</strong> (Score: ' + invEsc(latest.score !== undefined ? latest.score + '/100' : '?') + '). Ask me anything about it!', true);
          }
        }
      }, 2000);
    }

    // Attach listeners only once — but always reference aiCurrentScanContext
    // dynamically so quick-reply buttons always use the latest email's context.
    if (!aiListenersAttached) {
      aiListenersAttached = true;

      document.querySelectorAll('.pa-quick-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
          // Use aiCurrentScanContext (not a captured closure value) so this
          // always reflects whichever email is currently open.
          sendAiMessage(btn.textContent, aiCurrentScanContext);
        });
      });

      document.getElementById('ai-send-btn').addEventListener('click', function () {
        var val = document.getElementById('ai-input').value.trim();
        if (val) sendAiMessage(val, aiCurrentScanContext);
      });

      document.getElementById('ai-input').addEventListener('keydown', function (e) {
        if (e.key === 'Enter') {
          var val = document.getElementById('ai-input').value.trim();
          if (val) sendAiMessage(val, aiCurrentScanContext);
        }
      });
    }
  }

  async function sendAiMessage(text, scanContext) {
    document.getElementById('ai-input').value = '';
    appendAiMsg('user', text);
    aiHistory.push({ role: 'user', content: text });

    var typingEl = document.createElement('div');
    typingEl.className = 'pa-msg pa-msg-typing';
    typingEl.textContent = '…thinking';
    document.getElementById('ai-messages').appendChild(typingEl);
    scrollAiToBottom();

    // Always use the most up-to-date context
    var sc = scanContext || aiCurrentScanContext;
    var context = sc ? (function () {
      // threats may be a structured object {displayNameSpoof, homograph}
      // or a flat array (old log entries) — handle both gracefully
      var threatList = [];
      if (sc.threats && !Array.isArray(sc.threats)) {
        if (sc.threats.displayNameSpoof && sc.threats.displayNameSpoof.spoofing) threatList.push('Display name spoofing');
        if (sc.threats.homograph && sc.threats.homograph.detected) threatList.push('Homograph attack');
      } else if (sc.threatList && Array.isArray(sc.threatList)) {
        threatList = sc.threatList;
      } else if (Array.isArray(sc.threats)) {
        threatList = sc.threats;
      }
      return {
        domain: sc.domain,
        score: sc.score,
        spf: sc.checks && sc.checks.spf ? sc.checks.spf.detail : 'Unknown',
        dkim: sc.checks && sc.checks.dkim ? sc.checks.dkim.detail : 'Unknown',
        dmarc: sc.checks && sc.checks.dmarc ? (sc.checks.dmarc.detail + (sc.checks.dmarc.policy ? ' (policy: ' + sc.checks.dmarc.policy + ')' : '')) : 'Unknown',
        domainAge: sc.checks && sc.checks.age ? sc.checks.age.detail : 'Unknown',
        vtResult: sc.checks && sc.checks.vt && sc.checks.vt.available
          ? (sc.checks.vt.isMalicious ? 'Malicious (' + sc.checks.vt.maliciousCount + ' engines)' : 'Clean')
          : 'Not checked',
        threats: threatList,
        isTrusted: sc.isTrusted
      };
    })() : null;

    var res = await send({ type: 'CLAUDE_CHAT', messages: aiHistory, context: context });
    typingEl.remove();

    if (res && res.reply) {
      aiHistory.push({ role: 'assistant', content: res.reply });
      appendAiMsg('ai', res.reply, false);
    } else {
      appendAiMsg('error', paPopupIcon('warning', '#dc2626') + ' ' + invEsc(res && res.error ? res.error : 'No response.'), true);
    }
  }

  // ── Inline icon set for popup UI (mirrors content-shared.js's paIcon) ────
  // FIX: AI panel error messages used a raw ⚠️ emoji, inconsistent with the
  // SVG icon system used for trust-tier badges elsewhere in the popup.
  function paPopupIcon(name, color, size) {
    color = color || 'currentColor';
    size = size || 14;
    var body = {
      warning: '<path d="M12 4l9 16H3L12 4z"/><path d="M12 10v4"/><path d="M12 17h.01"/>'
    }[name] || '';
    return '<svg width="' + size + '" height="' + size + '" viewBox="0 0 24 24" fill="none" stroke="' + color +
      '" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;vertical-align:middle">' +
      body + '</svg>';
  }

  // `content` is plain text unless `isTrustedHtml` is true (only for markup this file
  // built itself, with every dynamic part already escaped). AI replies and the user's
  // own text are never treated as HTML.
  function appendAiMsg(type, content, isTrustedHtml) {
    var el = document.createElement('div');
    el.className = 'pa-msg ' + (type === 'user' ? 'pa-msg-user' : type === 'error' ? 'pa-msg-error' : 'pa-msg-ai');
    if (isTrustedHtml) el.innerHTML = content;
    else el.innerHTML = invEsc(content).replace(/\r?\n/g, '<br>');
    document.getElementById('ai-messages').appendChild(el);
    scrollAiToBottom();
  }

  function scrollAiToBottom() {
    var box = document.getElementById('ai-messages');
    box.scrollTop = box.scrollHeight;
  }

  // ── Productivity Tab ───────────────────────────────────────────────────
  var prodEmailContent = null;
  var prodListenersAttached = false;

  async function loadProductivity() {
    prodEmailContent = await send({ type: 'GET_EMAIL_CONTENT' });

    var noEmailMsg = prodEmailContent
      ? '📧 ' + (prodEmailContent.sender || '') + ' — ' + (prodEmailContent.subject || '(No subject)')
      : null;

    ['cal', 'act', 'lbl'].forEach(function (key) {
      var el = document.getElementById('prod-' + key + '-email-info');
      if (el) el.textContent = noEmailMsg || 'No email open — open an email in Gmail first.';
    });

    // Restore everything generated in this tab if it's still the same open email
    // (closing the popup must not throw results away; closing/reopening the email does).
    await restoreProdOutputs();

    if (!prodListenersAttached) {
      prodListenersAttached = true;

      // Inner tab switching
      document.querySelectorAll('.inner-tab').forEach(function (tab) {
        tab.addEventListener('click', function () {
          document.querySelectorAll('.inner-tab').forEach(function (t) { t.classList.remove('active'); });
          document.querySelectorAll('.inner-pane').forEach(function (p) { p.classList.remove('active'); });
          tab.classList.add('active');
          document.getElementById('prod-pane-' + tab.dataset.ptab).classList.add('active');
        });
      });

      // ── Calendar Extraction ─────────────────────────────────────────────
      document.getElementById('prod-cal-btn').addEventListener('click', async function () {
        if (!prodEmailContent) {
          showProdOutput('prod-cal-output', '<div class="error-msg">⚠️ Open an email in Gmail first.</div>');
          return;
        }
        var btn = document.getElementById('prod-cal-btn');
        btn.disabled = true; btn.textContent = '⏳ Extracting…';
        showProdOutput('prod-cal-output', '<div class="loading">⏳ Scanning for meeting times…</div>');

        var res = await send({ type: 'EXTRACT_CALENDAR', subject: prodEmailContent.subject, body: prodEmailContent.body });
        btn.disabled = false; btn.innerHTML = '📅 Extract Meeting Times';

        if (!res || res.error) {
          showProdOutput('prod-cal-output', '<div class="error-msg">⚠️ ' + invEsc(res && res.error ? res.error : 'Failed') + '</div>');
          return;
        }

        if (!res.hasEvents || !res.events || res.events.length === 0) {
          showProdOutput('prod-cal-output', '<div class="prod-no-results">📅 No meeting times or events found in this email.</div>', true);
          return;
        }

        var html = '';
        res.events.forEach(function (ev) {
          var meta = invEsc([ev.date, ev.time, ev.duration ? ev.duration + ' min' : null, ev.location].filter(Boolean).join(' · '));
          // Only ever link to Google Calendar's own event-template URL
          var calLink = (ev.googleCalendarUrl && /^https:\/\/(www\.)?(calendar\.google\.com|google\.com\/calendar)\//i.test(ev.googleCalendarUrl))
            ? '<a class="prod-event-btn" href="' + invEsc(ev.googleCalendarUrl) + '" target="_blank" rel="noopener noreferrer">📅 Add to Google Calendar</a>'
            : '';
          html += '<div class="prod-event">' +
            '<div class="prod-event-title">' + invEsc(ev.title) + '</div>' +
            '<div class="prod-event-meta">' + meta + '</div>' +
            (ev.description ? '<div style="font-size:11px;color:var(--text3);margin-bottom:5px">' + invEsc(ev.description) + '</div>' : '') +
            calLink +
            '</div>';
        });

        showProdOutput('prod-cal-output',
          '<div style="font-size:11px;color:var(--text3);margin-bottom:8px">Found ' + res.events.length + ' event(s) — ' + invEsc(res.summary || '') + '</div>' + html,
          true
        );
      });

      // ── Action Item Extractor ───────────────────────────────────────────
      document.getElementById('prod-act-btn').addEventListener('click', async function () {
        if (!prodEmailContent) {
          showProdOutput('prod-act-output', '<div class="error-msg">⚠️ Open an email in Gmail first.</div>');
          return;
        }
        var btn = document.getElementById('prod-act-btn');
        btn.disabled = true; btn.textContent = '⏳ Extracting…';
        showProdOutput('prod-act-output', '<div class="loading">⏳ Finding action items…</div>');

        var res = await send({ type: 'EXTRACT_ACTIONS', subject: prodEmailContent.subject, body: prodEmailContent.body });
        btn.disabled = false; btn.innerHTML = '✅ Extract Action Items';

        if (!res || res.error) {
          showProdOutput('prod-act-output', '<div class="error-msg">⚠️ ' + invEsc(res && res.error ? res.error : 'Failed') + '</div>');
          return;
        }

        renderActionResult(res, true);
      });

      // ── Notion hand-off ────────────────────────────────────────────────
      // Notion can't be pre-filled from a URL (the old ?title= link just opened an
      // empty page). So: build a Markdown note from the email, put it on the
      // clipboard, and open a fresh Notion page — Notion turns pasted Markdown
      // into real headings, to-dos and quotes, ready for the user to edit.
      document.getElementById('prod-act-output').addEventListener('click', function (e) {
        var b = e.target.closest ? e.target.closest('[data-notion-task]') : null;
        if (b) sendToNotion(b.getAttribute('data-notion-task'));
      });

      // ── Smart Gmail Labels ──────────────────────────────────────────────
      document.getElementById('prod-lbl-btn').addEventListener('click', async function () {
        if (!prodEmailContent) {
          showProdOutput('prod-lbl-output', '<div class="error-msg">⚠️ Open an email in Gmail first.</div>');
          return;
        }
        var btn = document.getElementById('prod-lbl-btn');
        btn.disabled = true; btn.textContent = '⏳ Analyzing…';
        showProdOutput('prod-lbl-output', '<div class="loading">⏳ Suggesting labels…</div>');

        var res = await send({ type: 'SUGGEST_LABELS', subject: prodEmailContent.subject, body: prodEmailContent.body, sender: prodEmailContent.sender });
        btn.disabled = false; btn.innerHTML = '🏷️ Suggest Gmail Labels';

        if (!res || res.error) {
          showProdOutput('prod-lbl-output', '<div class="error-msg">⚠️ ' + invEsc(res && res.error ? res.error : 'Failed') + '</div>');
          return;
        }

        var addLabels = (res.additionalLabels || []).map(function (l) {
          return '<span class="prod-label-chip">🏷️ ' + invEsc(l) + '</span>';
        }).join('');

        var extraActions = '';
        if (res.shouldUnsubscribe) {
          extraActions += '<div class="prod-label-action prod-label-unsubscribe">🚫 Consider unsubscribing — ' + invEsc(res.unsubscribeReason || '') + '</div>';
        }
        if (res.isImportant) {
          extraActions += '<div class="prod-label-action prod-label-important">⭐ Mark as important — ' + invEsc(res.importanceReason || '') + '</div>';
        }

        var folderMap = { INBOX: '📥 Keep in Inbox', archive: '📦 Archive', starred: '⭐ Star it' };
        var html =
          '<div class="prod-label-primary">🏷️ ' + invEsc(res.primaryLabel || 'Unlabeled') + '</div>' +
          (addLabels ? '<div style="margin-bottom:7px">' + addLabels + '</div>' : '') +
          '<div class="prod-label-meta">' +
          (Object.prototype.hasOwnProperty.call(folderMap, res.suggestedFolder) ? folderMap[res.suggestedFolder] : '') + '<br>' +
          invEsc(res.reasoning || '') +
          '</div>' +
          extraActions +
          '<div style="font-size:11px;color:var(--text3);margin-top:9px;padding:7px;background:var(--bg3);border-radius:6px;border:1px solid var(--border)">💡 <strong>How to apply:</strong> In Gmail, click the label icon (🏷️) in the toolbar while this email is open, then type the label name to create or apply it.</div>';

        showProdOutput('prod-lbl-output', html, true);
      });

      // ── Daily Inbox Digest ──────────────────────────────────────────────
      document.getElementById('prod-digest-btn').addEventListener('click', async function () {
        var btn = document.getElementById('prod-digest-btn');
        btn.disabled = true; btn.textContent = '⏳ Generating…';
        showProdOutput('prod-digest-output', '<div class="loading">⏳ Summarizing your inbox…</div>');

        var res = await send({ type: 'GENERATE_DIGEST' });
        btn.disabled = false; btn.innerHTML = '📊 Generate Inbox Digest';

        if (!res || res.error) {
          showProdOutput('prod-digest-output', '<div class="error-msg">⚠️ ' + invEsc(res && res.error ? res.error : 'Failed') + '</div>');
          return;
        }

        var healthClass = {
          healthy: 'prod-health-healthy', busy: 'prod-health-busy',
          cluttered: 'prod-health-cluttered', under_attack: 'prod-health-under_attack'
        };
        var healthLabel = {
          healthy: '✅ Healthy Inbox', busy: '📬 Busy Inbox',
          cluttered: '📦 Cluttered Inbox', under_attack: '🚨 Under Attack'
        };
        var health = res.overallInboxHealth || 'healthy';

        var themesHtml = (res.keyThemes || []).map(function (t) {
          return '<span class="prod-digest-theme">' + invEsc(t) + '</span>';
        }).join('');

        var actionsHtml = (res.recommendedActions || []).map(function (a) {
          return '<div class="prod-digest-action">→ ' + invEsc(a) + '</div>';
        }).join('');

        var html =
          '<span class="prod-health-badge ' + (Object.prototype.hasOwnProperty.call(healthClass, health) ? healthClass[health] : '') + '">' + (Object.prototype.hasOwnProperty.call(healthLabel, health) ? healthLabel[health] : invEsc(health)) + '</span>' +
          '<div class="prod-digest-stats">' +
          '<div class="prod-digest-stat"><div class="prod-digest-stat-num" style="color:var(--red2)">' + invEsc(res.urgentCount || 0) + '</div><div class="prod-digest-stat-label">Urgent</div></div>' +
          '<div class="prod-digest-stat"><div class="prod-digest-stat-num" style="color:var(--yellow)">' + invEsc(res.suspiciousCount || 0) + '</div><div class="prod-digest-stat-label">Suspicious</div></div>' +
          '</div>' +
          '<div class="prod-digest-text">' + invEsc(res.digest || '') + '</div>' +
          (themesHtml ? '<div class="prod-digest-themes">' + themesHtml + '</div>' : '') +
          (actionsHtml ? '<div style="margin-bottom:4px">' + actionsHtml + '</div>' : '');

        showProdOutput('prod-digest-output', html, true);
      });
    }
  }

  var _prodLastTasks = null;

  // ── Productivity output cache (per opened email) ────────────────────────
  // content.js re-saves the email (new timestamp) every time an email is opened,
  // so timestamp+sender+subject identifies "this open instance" of the email.
  // Every finished result in the Productivity tab (calendar, actions, labels,
  // digest) is stored under that key and restored when the popup reopens.
  var PROD_CACHE_KEY = 'phishalert_prod_cache';
  var PROD_OUTPUT_IDS = ['prod-cal-output', 'prod-act-output', 'prod-lbl-output', 'prod-digest-output'];
  var _prodCache = null; // { key, outputs: { id: html }, actions: res|null }

  function currentEmailKey() {
    if (!prodEmailContent) return null;
    return [prodEmailContent.timestamp || '', prodEmailContent.sender || '', prodEmailContent.subject || ''].join('|');
  }

  function persistProdCache() {
    if (!_prodCache) return;
    try {
      var obj = {}; obj[PROD_CACHE_KEY] = _prodCache;
      // Memory-only: results are derived from email text, so never persist them to disk.
      if (chrome.storage.session) chrome.storage.session.set(obj);
    } catch (err) {}
  }

  function cacheProdOutput(id, html) {
    var key = currentEmailKey();
    if (!key) return;
    if (!_prodCache || _prodCache.key !== key) _prodCache = { key: key, outputs: {}, actions: null };
    _prodCache.outputs[id] = html;
    persistProdCache();
  }

  async function restoreProdOutputs() {
    _prodLastTasks = null;
    var key = currentEmailKey();
    var cached = null;
    try {
      var data = chrome.storage.session ? await chrome.storage.session.get(PROD_CACHE_KEY) : {};
      cached = data && data[PROD_CACHE_KEY];
    } catch (err) {}

    // Different email (or none open) → drop the old results and start clean
    if (!key || !cached || cached.key !== key) {
      if (cached) { try { chrome.storage.session.remove(PROD_CACHE_KEY); } catch (err) {} }
      _prodCache = null;
      PROD_OUTPUT_IDS.forEach(function (id) {
        var el = document.getElementById(id);
        if (el) { el.style.display = 'none'; el.innerHTML = ''; }
      });
      return;
    }

    _prodCache = cached;
    Object.keys(cached.outputs || {}).forEach(function (id) {
      if (id === 'prod-act-output') return; // re-rendered from data below so Notion buttons keep working
      showProdOutput(id, cached.outputs[id]);
    });
    if (cached.actions) renderActionResult(cached.actions, false);
    else if (cached.outputs && cached.outputs['prod-act-output']) showProdOutput('prod-act-output', cached.outputs['prod-act-output']);
  }

  function renderActionResult(res, persist) {
    if (!res.hasTasks || !res.tasks || res.tasks.length === 0) {
      showProdOutput('prod-act-output', '<div class="prod-no-results">✅ No specific action items found in this email.</div>', persist);
      return;
    }

    var priClass = { high: 'prod-task-pri-high', medium: 'prod-task-pri-medium', low: 'prod-task-pri-low' };
    var html = '';
    _prodLastTasks = res;
    res.tasks.forEach(function (task, taskIdx) {
      var meta = invEsc([task.deadline ? '⏰ ' + task.deadline : null, task.assignedTo ? '👤 ' + task.assignedTo : null].filter(Boolean).join(' · '));
      var btns = '<div class="prod-task-btns">';
      btns += '<button class="prod-task-btn" data-notion-task="' + taskIdx + '" title="Copy a ready-made note to your clipboard and open Notion">📝 Notion</button>';
      btns += '</div>';

      html += '<div class="prod-task">' +
        '<div class="prod-task-header">' +
        '<span class="prod-task-title">' + invEsc(task.title) + '</span>' +
        '<span class="prod-task-pri ' + (Object.prototype.hasOwnProperty.call(priClass, task.priority) ? priClass[task.priority] : 'prod-task-pri-medium') + '">' + invEsc(String(task.priority || 'medium').toUpperCase()) + '</span>' +
        '</div>' +
        (meta ? '<div class="prod-task-meta">' + meta + '</div>' : '') +
        (task.context ? '<div style="font-size:11px;color:var(--text3);margin-bottom:5px">' + invEsc(task.context) + '</div>' : '') +
        btns +
        '</div>';
    });

    showProdOutput('prod-act-output',
      '<div style="font-size:11px;color:var(--text3);margin-bottom:8px">' + res.tasks.length + ' task(s) — ' + invEsc(res.summary || '') + '</div>' +
      '<div class="prod-task-btns" style="margin-bottom:8px"><button class="prod-task-btn" data-notion-task="all" title="Copy one note with every action item and open Notion">📝 Send all to Notion</button></div>' +
      '<div id="prod-notion-msg" style="display:none;font-size:11px;font-weight:600;color:var(--green2);margin-bottom:8px"></div>' +
      html,
      persist
    );
    if (persist) {
      var key = currentEmailKey();
      if (key) {
        if (!_prodCache || _prodCache.key !== key) _prodCache = { key: key, outputs: {}, actions: null };
        _prodCache.actions = res;
        persistProdCache();
      }
    }
  }


  async function sendToNotion(which) {
    var msgEl = document.getElementById('prod-notion-msg');
    function say(text, ok) {
      if (!msgEl) return;
      msgEl.style.display = 'block';
      msgEl.style.color = ok ? 'var(--green2)' : 'var(--red2)';
      msgEl.textContent = text;
    }
    if (!prodEmailContent || !_prodLastTasks || !_prodLastTasks.tasks) { say('Extract action items first.', false); return; }

    var tasks = which === 'all' ? _prodLastTasks.tasks : [_prodLastTasks.tasks[Number(which)]].filter(Boolean);
    if (!tasks.length) { say('Nothing to send.', false); return; }

    // Link back to the email (Gmail/Outlook/Yahoo/Proton tab the popup was opened on)
    var emailUrl = '';
    try {
      var tabs = await new Promise(function (r) { chrome.tabs.query({ active: true, currentWindow: true }, r); });
      var u = tabs && tabs[0] && tabs[0].url || '';
      if (/^https:\/\/(mail\.google\.com|outlook\.(live|office|office365)\.com|mail\.yahoo\.com|mail\.proton\.me|app\.protonmail\.ch)\//.test(u)) emailUrl = u;
    } catch (err) {}

    var md = buildNotionNote(prodEmailContent, _prodLastTasks.summary, tasks, emailUrl);

    try {
      await navigator.clipboard.writeText(md);
    } catch (err) {
      // Fallback for restricted clipboard contexts
      var ta = document.createElement('textarea');
      ta.value = md; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      var ok = false; try { ok = document.execCommand('copy'); } catch (e2) {}
      document.body.removeChild(ta);
      if (!ok) { say('Couldn\u2019t copy the note. Please allow clipboard access and try again.', false); return; }
    }

    var isMac = /Mac|iPhone|iPad/.test(navigator.platform || '');
    say('\u2713 Note copied \u2014 opening Notion. Press ' + (isMac ? '\u2318V' : 'Ctrl+V') + ' on the new page.', true);
    // Brief pause so the message is readable before the popup closes with the new tab.
    setTimeout(function () {
      try { chrome.tabs.create({ url: 'https://www.notion.so/new' }); }
      catch (err) { window.open('https://www.notion.so/new', '_blank'); }
    }, 1300);
  }

  function buildNotionNote(email, summary, tasks, emailUrl) {
    var clean = function (v) { return String(v == null ? '' : v).replace(/\s+/g, ' ').trim(); };
    var lines = [];
    lines.push('# ' + (clean(email.subject) || '(No subject)'));
    lines.push('');
    if (email.sender) lines.push('**From:** ' + clean(email.sender));
    lines.push('**Saved:** ' + new Date().toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }));
    if (emailUrl) lines.push('**Email:** ' + emailUrl);
    lines.push('');
    if (summary) { lines.push('> ' + clean(summary)); lines.push(''); }
    lines.push('## Action items');
    lines.push('');
    tasks.forEach(function (t) {
      var bits = [];
      if (t.priority) bits.push(clean(t.priority).toUpperCase() + ' priority');
      if (t.deadline) bits.push('due ' + clean(t.deadline));
      if (t.assignedTo) bits.push(clean(t.assignedTo));
      lines.push('- [ ] ' + clean(t.title) + (bits.length ? ' (' + bits.join(' \u00b7 ') + ')' : ''));
      if (t.context) lines.push('    ' + clean(t.context));
    });
    lines.push('');
    lines.push('## Notes');
    lines.push('');
    return lines.join('\n');
  }

  // persist=true marks a finished result (not a loading/error state) to be kept
  // for the current email and restored when the popup is reopened.
  function showProdOutput(id, html, persist) {
    var el = document.getElementById(id);
    if (!el) return;
    el.style.display = 'block';
    el.innerHTML = html;
    if (persist) cacheProdOutput(id, html);
  }


  // ══════════════════════════════════════════════════════════════════════════
  // FEATURE 1: Weekly Threat Intelligence Report
  // ══════════════════════════════════════════════════════════════════════════
  async function loadWeeklyReport() {
    var output = document.getElementById('weekly-report-output');
    var genBtn = document.getElementById('weekly-gen-btn');
    if (!output) return;

    output.innerHTML = '<div class="loading">Loading last report…</div>';

    // Try loading existing report first
    var report = await send({ type: 'GET_WEEKLY_REPORT' });
    if (report && report.hasData) {
      renderWeeklyReport(report);
    } else {
      output.innerHTML = '<div class="empty"><span class="empty-icon">📊</span><strong>No report yet</strong><span style="display:block;margin-top:5px;font-size:11px">Click Generate to build your first weekly security digest.</span></div>';
    }

    if (!genBtn._weeklyListenerAttached) {
      genBtn._weeklyListenerAttached = true;
      genBtn.addEventListener('click', async function () {
        genBtn.disabled = true;
        genBtn.textContent = '⏳ Generating…';
        output.innerHTML = '<div class="loading">⏳ Analyzing last 7 days…</div>';
        var r = await send({ type: 'GENERATE_WEEKLY_REPORT' });
        genBtn.disabled = false;
        genBtn.textContent = '📊 Generate Weekly Report';
        if (!r || !r.hasData) {
          output.innerHTML = '<div class="empty"><span class="empty-icon">📭</span><strong>' + (r && r.message ? r.message : 'Not enough data yet.') + '</strong><span style="display:block;margin-top:5px;font-size:11px">Scan more emails in Gmail and try again.</span></div>';
          return;
        }
        renderWeeklyReport(r);
      });
    }
  }

  function renderWeeklyReport(r) {
    var output = document.getElementById('weekly-report-output');
    if (!output) return;

    var threatColor = r.personalThreatScore >= 60 ? 'var(--red2)' : r.personalThreatScore >= 30 ? 'var(--yellow)' : 'var(--green2)';
    var avgColor = (r.avgTrustScore || 0) >= 80 ? 'var(--green2)' : (r.avgTrustScore || 0) >= 55 ? 'var(--yellow)' : 'var(--red2)';

    var html = '<div class="weekly-period">📅 ' + (r.period ? r.period.from + ' — ' + r.period.to : 'Last 7 days') + '</div>';

    // Stats grid
    html += '<div class="weekly-card"><div class="weekly-card-title">📊 Activity Summary</div>';
    html += '<div class="weekly-stat-grid">';
    html += '<div class="weekly-stat"><div class="weekly-stat-num" style="color:var(--blue2)">' + (r.totalScanned || 0) + '</div><div class="weekly-stat-lbl">Scanned</div></div>';
    html += '<div class="weekly-stat"><div class="weekly-stat-num" style="color:var(--red2)">' + (r.threatsCount || 0) + '</div><div class="weekly-stat-lbl">Threats</div></div>';
    html += '<div class="weekly-stat"><div class="weekly-stat-num" style="color:var(--green2)">' + (r.safeCount || 0) + '</div><div class="weekly-stat-lbl">Safe</div></div>';
    html += '<div class="weekly-stat"><div class="weekly-stat-num" style="color:var(--yellow)">' + (r.suspiciousCount || 0) + '</div><div class="weekly-stat-lbl">Suspicious</div></div>';
    html += '</div>';

    // Personal threat score
    html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">';
    html += '<span style="font-size:11px;color:var(--text2)">Your threat exposure score:</span>';
    html += '<span style="font-size:15px;font-weight:800;font-family:var(--mono);color:' + threatColor + '">' + (r.personalThreatScore || 0) + '/100</span>';
    html += '</div>';
    html += '<div style="font-size:11px;color:var(--text2)">Avg sender trust: <span style="color:' + avgColor + ';font-weight:700">' + (r.avgTrustScore || '--') + '/100</span></div>';
    html += '</div>';

    // Top risky domains
    if (r.topRiskyDomains && r.topRiskyDomains.length > 0) {
      html += '<div class="weekly-card"><div class="weekly-card-title">⚠️ Top Risky Domains</div>';
      r.topRiskyDomains.forEach(function (d) {
        html += '<div class="weekly-domain-row"><span style="color:var(--red2)">' + d.domain + '</span><span style="font-size:10px;color:var(--text3)">' + d.count + ' flag' + (d.count !== 1 ? 's' : '') + '</span></div>';
      });
      html += '</div>';
    }

    // Top attack types
    if (r.topAttacks && r.topAttacks.length > 0) {
      html += '<div class="weekly-card"><div class="weekly-card-title">🎯 Most Common Attack Types</div>';
      html += '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:3px">';
      r.topAttacks.forEach(function (a) {
        html += '<span class="weekly-attack-tag">' + a.type.substring(0, 35) + ' ×' + a.count + '</span>';
      });
      html += '</div></div>';
    }

    output.innerHTML = html;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // FEATURE 2: Adaptive Sender Learning + FEATURE 4: One-Click Phishing Report
  // (injected into Reports tab)
  // ══════════════════════════════════════════════════════════════════════════
  var _adaptiveListenersAttached = false;
  var _oneclickListenersAttached = false;

  // Override loadReports to inject adaptive + oneclick sections
  var _originalLoadReports = loadReports;
  loadReports = async function () {
    // Load adaptive sender and oneclick for current email
    var scanData = await send({ type: 'GET_LAST_SCAN' });
    var emailContent = await send({ type: 'GET_EMAIL_CONTENT' });

    var adaptiveWrap = document.getElementById('adaptive-wrap');
    var oneclickSection = document.getElementById('oneclick-report-section');
    var noEmailDiv = document.getElementById('reports-no-email');

    if (scanData && emailContent) {
      if (noEmailDiv) noEmailDiv.style.display = 'none';

      // ── Adaptive Sender Learning ──
      if (adaptiveWrap) {
        adaptiveWrap.style.display = 'block';
        var senderInfo = document.getElementById('adaptive-sender-info');
        if (senderInfo) {
          senderInfo.textContent = 'Sender: ' + (emailContent.sender || scanData.domain || 'Unknown');
        }

        // Load current adaptive trust
        if (emailContent.sender) {
          var trust = await send({ type: 'GET_ADAPTIVE_TRUST', email: emailContent.sender });
          updateAdaptiveBadge(trust);
        }

        if (!_adaptiveListenersAttached) {
          _adaptiveListenersAttached = true;

          document.getElementById('adaptive-safe-btn').addEventListener('click', async function () {
            if (!emailContent || !emailContent.sender) return;
            await send({ type: 'ADAPTIVE_SENDER_ACTION', email: emailContent.sender, domain: emailContent.domain || '', action: 'mark_safe' });
            // Bug fix #3: also add domain to whitelist so future scans score it as 100
            var domainToWhitelist = emailContent.domain ||
              (emailContent.sender || '').toLowerCase().replace(/^[^@]+@/, '').replace(/^www\./, '').split('/')[0].trim();
            if (domainToWhitelist && domainToWhitelist.includes('.')) {
              await send({ type: 'WHITELIST_ADD', domain: domainToWhitelist });
              // also undo any community report on this domain
              await send({ type: 'CLEAR_COMMUNITY_REPORT', domain: domainToWhitelist, whitelist: false });
              if (typeof loadReports === 'function') loadReports();
            }
            var t = await send({ type: 'GET_ADAPTIVE_TRUST', email: emailContent.sender });
            updateAdaptiveBadge(t);
            showAdaptiveFeedback('✅ Marked as safe — domain whitelisted & trust score boosted.', 'var(--green2)');
          });

          document.getElementById('adaptive-phish-btn').addEventListener('click', async function () {
            if (!emailContent || !emailContent.sender) return;
            await send({ type: 'ADAPTIVE_SENDER_ACTION', email: emailContent.sender, domain: emailContent.domain || '', action: 'mark_phishing' });
            var t = await send({ type: 'GET_ADAPTIVE_TRUST', email: emailContent.sender });
            updateAdaptiveBadge(t);
            showAdaptiveFeedback('🚩 Marked as phishing — trust reduced for this sender.', 'var(--red2)');
          });

          document.getElementById('adaptive-block-btn').addEventListener('click', async function () {
            if (!emailContent || !emailContent.sender) return;
            if (!confirm('Block sender ' + emailContent.sender + '?')) return;
            await send({ type: 'BLOCK_SENDER', email: emailContent.sender, domain: emailContent.domain || '', reason: 'User blocked via Reports tab' });
            await send({ type: 'ADAPTIVE_SENDER_ACTION', email: emailContent.sender, domain: emailContent.domain || '', action: 'block' });
            showAdaptiveFeedback('🚫 Sender blocked and marked as threat.', '#fca5a5');
          });
        }
      }

      // ── One-Click Phishing Report ──
      if (oneclickSection) {
        oneclickSection.style.display = 'block';
        var targetContainer = document.getElementById('oneclick-report-targets');

        if (!_oneclickListenersAttached) {
          _oneclickListenersAttached = true;
          document.getElementById('oneclick-report-btn').addEventListener('click', async function () {
            var btn = document.getElementById('oneclick-report-btn');
            btn.disabled = true;
            btn.textContent = '⏳ Generating report links…';
            if (targetContainer) targetContainer.style.display = 'none';

            var domain = emailContent.domain || scanData.domain || '';
            var sender = emailContent.sender || '';
            var subject = emailContent.subject || '';

            var result = await send({ type: 'REPORT_PHISHING_ONECLICK', domain: domain, sender: sender, subject: subject, note: 'User reported via PhishAlert' });

            btn.disabled = false;
            btn.textContent = '🚨 Report This Email as Phishing';

            if (!result || result.error) {
              showOneclickBanner('⚠️ Error: ' + (result && result.error ? result.error : 'Failed'), false);
              return;
            }

            showOneclickBanner('✅ Report saved! Use the links below to file with external services.', true);

            if (targetContainer) {
              targetContainer.style.display = 'block';
              var thtml = '';
              (result.reports || []).forEach(function (rep) {
                if (rep.status === 'success') {
                  thtml += '<div class="report-target"><span class="report-target-name">' + rep.target + '</span><span class="report-target-ok">✅ Saved</span></div>';
                } else if (rep.status === 'link' && rep.url) {
                  thtml += '<div class="report-target"><span class="report-target-name">' + rep.target + '</span><a class="report-target-link" href="' + rep.url + '" target="_blank">Open →</a></div>';
                }
              });
              targetContainer.innerHTML = thtml;
            }
          });
        }
      }
    } else {
      if (adaptiveWrap) adaptiveWrap.style.display = 'none';
      if (oneclickSection) oneclickSection.style.display = 'none';
      if (noEmailDiv) noEmailDiv.style.display = 'block';
    }

    // Call original loadReports for blocked senders and community reports
    await _originalLoadReports();
  };

  function updateAdaptiveBadge(trust) {
    var fb = document.getElementById('adaptive-feedback');
    if (!fb || !trust) return;
    var net = trust.netEffect || (trust.bonus || 0) - (trust.penalty || 0);
    var netStr = net > 0 ? '+' + net : String(net);
    var color = net > 0 ? 'var(--green2)' : net < 0 ? 'var(--red2)' : 'var(--text3)';
    fb.innerHTML = '<span class="adaptive-trust-badge" style="color:' + color + '">🧠 ' + (trust.label || 'First contact') + ' · Score effect: ' + netStr + '</span>';
  }

  function showAdaptiveFeedback(msg, color) {
    var fb = document.getElementById('adaptive-feedback');
    if (!fb) return;
    fb.innerHTML = '<span style="color:' + (color || 'var(--text2)') + '">' + msg + '</span>';
    setTimeout(function () {
      var t = send({ type: 'GET_ADAPTIVE_TRUST', email: '' });
    }, 2000);
  }

  function showOneclickBanner(msg, isSuccess) {
    var banner = document.getElementById('oneclick-report-banner');
    if (!banner) return;
    banner.textContent = msg;
    banner.style.display = 'block';
    banner.style.borderColor = isSuccess ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)';
    banner.style.background = isSuccess ? 'rgba(34,197,94,0.1)' : 'rgba(239,68,68,0.1)';
    banner.style.color = isSuccess ? 'var(--green2)' : 'var(--red2)';
  }

  // ── Init ───────────────────────────────────────────────────────────────
  // Load overview stats on open
  loadStats();
  // Pre-load settings silently
  loadSettings();



  /* ═══════════════════════════════════════════════════════════════════════
     PhishAlert — Popup JS Feature Additions
     APPEND THIS ENTIRE FILE to the bottom of popup.js,
     just before the final closing `})();`
     ═══════════════════════════════════════════════════════════════════════ */

  // ═══════════════════════════════════════════════════════════════════════
  // FEATURE 1 — First-Run Onboarding Wizard
  // ═══════════════════════════════════════════════════════════════════════

  // ── Onboarding storage helpers ─────────────────────────────────────────
  // Progress lives in storage.local (survives the popup closing when the user
  // opens a "Get key" tab). Unsaved key drafts live in storage.session —
  // memory only, never written to disk, cleared on browser restart.
  var OB_STATE_KEY = 'pa_onboarding_state';
  var OB_DRAFT_KEY = 'pa_onboarding_draft';
  var OB_TOTAL = 5;
  var obApi = null;

  function obArea(name) {
    try { return (chrome.storage && chrome.storage[name]) || null; } catch (e) { return null; }
  }
  function obGet(areaName, key) {
    return new Promise(function (resolve) {
      var a = obArea(areaName);
      if (!a) { resolve(null); return; }
      try { a.get(key, function (r) { resolve((r && r[key]) || null); }); } catch (e) { resolve(null); }
    });
  }
  function obSet(areaName, key, val) {
    return new Promise(function (resolve) {
      var a = obArea(areaName);
      if (!a) { resolve(); return; }
      var o = {}; o[key] = val;
      try { a.set(o, function () { resolve(); }); } catch (e) { resolve(); }
    });
  }
  function obRemove(areaName, key) {
    return new Promise(function (resolve) {
      var a = obArea(areaName);
      if (!a) { resolve(); return; }
      try { a.remove(key, function () { resolve(); }); } catch (e) { resolve(); }
    });
  }

  // ── Key verification (best-effort; offline/blocked never blocks saving) ──
  async function obStatus(url, headers) {
    var t;
    try {
      var ctl = new AbortController();
      t = setTimeout(function () { ctl.abort(); }, 7000);
      var r = await fetch(url, { headers: headers, signal: ctl.signal });
      return r.status;
    } catch (e) {
      return 0;
    } finally {
      clearTimeout(t);
    }
  }
  async function obVerifyVT(key) {
    var st = await obStatus('https://www.virustotal.com/api/v3/domains/google.com', { 'x-apikey': key });
    if (st === 200 || st === 429) return 'ok';
    if (st === 401 || st === 403) return 'invalid';
    return 'unverified';
  }
  async function obVerifyGroq(key) {
    var st = await obStatus('https://api.groq.com/openai/v1/models', { 'Authorization': 'Bearer ' + key });
    if (st === 200 || st === 429) return 'ok';
    if (st === 401) return 'invalid';
    return 'unverified';
  }

  async function checkFirstRun() {
    var data = await send({ type: 'GET_SETTINGS' });
    if ((!data || data.onboarded !== true) && obApi) await obApi.open();
  }

  function initOnboarding() {
    var overlay = document.getElementById('pa-onboarding');
    if (!overlay) return;

    function $(id) { return overlay.querySelector('#' + id); }
    var steps = overlay.querySelectorAll('.pa-ob-step');
    var segs = overlay.querySelectorAll('.pa-ob-seg');
    var current = 1;
    var saved = { vt: false, groq: false };
    var prefs = { activeLinkProtectionEnabled: true, outgoingScanEnabled: true, notificationsEnabled: true };

    var KEYS = {
      vt:   { field: 'vtApiKey',   input: 'ob-vt-input',   save: 'ob-vt-save',   replace: 'ob-vt-replace',   card: 'ob-vt-card',   msg: 'ob-vt-msg',   verify: obVerifyVT },
      groq: { field: 'groqApiKey', input: 'ob-groq-input', save: 'ob-groq-save', replace: 'ob-groq-replace', card: 'ob-groq-card', msg: 'ob-groq-msg', verify: obVerifyGroq }
    };
    var PREF_INPUTS = {
      'ob-pref-link':  'activeLinkProtectionEnabled',
      'ob-pref-out':   'outgoingScanEnabled',
      'ob-pref-notif': 'notificationsEnabled'
    };

    function setMsg(which, text, kind) {
      var el = $(KEYS[which].msg);
      el.textContent = text || '';
      el.className = 'pa-ob-msg' + (kind ? ' ' + kind : '');
    }

    function markSaved(which, verdict) {
      var card = $(KEYS[which].card);
      card.classList.add('is-saved');
      var label = card.querySelector('.pa-ob-saved-text');
      label.textContent = verdict === 'ok' ? 'Verified & encrypted'
                        : verdict === 'unverified' ? 'Saved & encrypted (couldn\u2019t verify right now)'
                        : 'Key on file \u00b7 encrypted';
      setMsg(which, '', '');
    }

    function updateNextLabel() {
      var btn = $('ob-next');
      if (current === 1) btn.textContent = 'Get started \u2192';
      else if (current === 2) btn.textContent = 'Continue \u2192';
      else if (current === 3) btn.textContent = (saved.vt || saved.groq) ? 'Continue \u2192' : 'Skip for now \u2192';
      else if (current === 4) btn.textContent = 'Continue \u2192';
      else btn.textContent = 'Start using PhishAlert';
    }

    function pill(id, on, onText, offText) {
      var el = $(id);
      el.className = 'pa-ob-pill ' + (on ? 'on' : 'off');
      el.textContent = on ? onText : offText;
    }
    function renderSummary() {
      pill('ob-sum-auth', true, 'Always on', 'Always on');
      pill('ob-sum-link', prefs.activeLinkProtectionEnabled, 'On', 'Off');
      pill('ob-sum-out', prefs.outgoingScanEnabled, 'On', 'Off');
      pill('ob-sum-vt', saved.vt, 'Connected', 'Not added');
      pill('ob-sum-ai', saved.groq, 'Connected', 'Not added');
    }

    function showStep(n, persist) {
      current = Math.max(1, Math.min(OB_TOTAL, n));
      steps.forEach(function (s) {
        s.classList.toggle('active', Number(s.getAttribute('data-step')) === current);
      });
      segs.forEach(function (s, i) { s.classList.toggle('done', i < current); });
      $('ob-step-label').textContent = 'Step ' + current + ' of ' + OB_TOTAL;
      $('ob-back').style.visibility = current > 1 ? 'visible' : 'hidden';
      $('ob-skip').style.display = current === OB_TOTAL ? 'none' : '';
      updateNextLabel();
      if (current === OB_TOTAL) renderSummary();
      overlay.querySelector('.pa-ob-body').scrollTop = 0;
      if (persist !== false) obSet('local', OB_STATE_KEY, { step: current });
    }

    // ── Save a single key (each key is independent) ───────────────────
    async function saveKey(which) {
      var cfg = KEYS[which];
      var input = $(cfg.input);
      var btn = $(cfg.save);
      var val = (input.value || '').trim();
      if (!val) { setMsg(which, 'Paste your key first.', 'err'); return false; }

      btn.disabled = true;
      btn.textContent = 'Checking\u2026';
      setMsg(which, '', '');
      var verdict = await cfg.verify(val);
      if (verdict === 'invalid') {
        btn.disabled = false; btn.textContent = 'Save';
        setMsg(which, 'That key was rejected. Make sure you copied the whole key.', 'err');
        return false;
      }
      var payload = { type: 'SAVE_API_KEYS' };
      payload[cfg.field] = val;
      var res = await send(payload);
      btn.disabled = false; btn.textContent = 'Save';
      if (!res || res.success === false) {
        setMsg(which, 'Couldn\u2019t save the key. Please try again.', 'err');
        return false;
      }
      input.value = '';
      saved[which] = true;
      markSaved(which, verdict);
      persistDraft();
      updateNextLabel();
      return true;
    }

    function persistDraft() {
      obSet('session', OB_DRAFT_KEY, {
        vt: $(KEYS.vt.input).value,
        groq: $(KEYS.groq.input).value
      });
    }

    Object.keys(KEYS).forEach(function (which) {
      var cfg = KEYS[which];
      $(cfg.save).addEventListener('click', function () { saveKey(which); });
      $(cfg.input).addEventListener('input', function () { setMsg(which, '', ''); persistDraft(); });
      $(cfg.input).addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); saveKey(which); }
      });
      $(cfg.replace).addEventListener('click', function () {
        $(cfg.card).classList.remove('is-saved');
        $(cfg.input).focus();
      });
    });

    // ── Preference toggles save instantly (partial merge in background) ─
    Object.keys(PREF_INPUTS).forEach(function (id) {
      $(id).addEventListener('change', function () {
        var name = PREF_INPUTS[id];
        prefs[name] = $(id).checked;
        var settings = {};
        settings[name] = prefs[name];
        send({ type: 'SAVE_SETTINGS', settings: settings });
      });
    });

    // ── Finish / skip ───────────────────────────────────────────────────
    async function finish(animate) {
      await send({ type: 'SAVE_SETTINGS', settings: { onboarded: true } });
      await obRemove('local', OB_STATE_KEY);
      await obRemove('session', OB_DRAFT_KEY);
      if (animate) {
        overlay.style.transition = 'opacity 0.3s';
        overlay.style.opacity = '0';
        setTimeout(function () {
          overlay.classList.remove('open');
          overlay.style.opacity = '';
          overlay.style.transition = '';
        }, 300);
      } else {
        overlay.classList.remove('open');
      }
      if (typeof loadStats === 'function') loadStats();
    }

    // ── Navigation ──────────────────────────────────────────────────────
    $('ob-back').addEventListener('click', function () { showStep(current - 1); });
    $('ob-skip').addEventListener('click', function () { finish(false); });
    $('ob-next').addEventListener('click', async function () {
      var btn = $('ob-next');
      if (current === 3) {
        // Anything typed but not yet saved gets saved now, so nothing is lost.
        btn.disabled = true;
        for (var w in KEYS) {
          if (Object.prototype.hasOwnProperty.call(KEYS, w) && ($(KEYS[w].input).value || '').trim()) {
            var ok = await saveKey(w);
            if (!ok) { btn.disabled = false; return; }
          }
        }
        btn.disabled = false;
      }
      if (current === OB_TOTAL) { finish(true); return; }
      showStep(current + 1);
    });

    // ── Open: restore progress, saved keys, prefs and unsaved drafts ────
    obApi = {
      open: async function () {
        var st = await obGet('local', OB_STATE_KEY);
        var ks = await send({ type: 'GET_API_KEYS' });
        var s = (await send({ type: 'GET_SETTINGS' })) || {};
        var draft = await obGet('session', OB_DRAFT_KEY);

        saved.vt = !!(ks && ks.hasVT);
        saved.groq = !!(ks && ks.hasGroq);
        if (saved.vt) markSaved('vt', 'existing');
        if (saved.groq) markSaved('groq', 'existing');

        Object.keys(PREF_INPUTS).forEach(function (id) {
          var name = PREF_INPUTS[id];
          prefs[name] = s[name] !== false;
          $(id).checked = prefs[name];
        });

        if (draft) {
          if (draft.vt && !saved.vt) $(KEYS.vt.input).value = draft.vt;
          if (draft.groq && !saved.groq) $(KEYS.groq.input).value = draft.groq;
        }

        // Show the one-time canary server setup steps only while the built-in
        // server address is still the placeholder (hidden automatically once deployed).
        var setupBox = $('ob-canary-setup');
        if (setupBox) {
          var hostPerms = (chrome.runtime.getManifest().host_permissions || []).join(' ');
          setupBox.style.display = hostPerms.indexOf('YOUR-SUBDOMAIN') !== -1 ? '' : 'none';
        }

        overlay.classList.add('open');
        showStep(st && st.step ? Number(st.step) : 1, false);
      }
    };
  }


  // ═══════════════════════════════════════════════════════════════════════
  // FEATURE 4 — Light Mode + Theme Toggle
  // ═══════════════════════════════════════════════════════════════════════

  async function initTheme() {
    var data = await send({ type: 'GET_SETTINGS' });
    var theme = (data && data.theme) ? data.theme : 'dark';
    applyTheme(theme);
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    var btn = document.getElementById('theme-toggle-btn');
    if (btn) {
      btn.textContent = theme === 'light' ? '🌙' : '☀️';
      btn.title = theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode';
    }
  }

  async function toggleTheme() {
    var current = document.documentElement.getAttribute('data-theme') || 'dark';
    var next = current === 'light' ? 'dark' : 'light';
    applyTheme(next);
    var s = await send({ type: 'GET_SETTINGS' }) || {};
    s.theme = next;
    await send({ type: 'SAVE_SETTINGS', settings: s });
  }


  // ═══════════════════════════════════════════════════════════════════════
  // FEATURE 5 — Custom Whitelist Management (Settings Tab)
  // ═══════════════════════════════════════════════════════════════════════

  var _whitelistListenersAttached = false;

  async function loadWhitelist() {
    var container = document.getElementById('whitelist-entries');
    if (!container) return;

    var whitelist = await send({ type: 'WHITELIST_GET' }) || [];

    // Bug fix: always update the count badge
    var badge = document.getElementById('whitelist-count-badge');
    if (badge) badge.textContent = whitelist.length;

    if (!whitelist.length) {
      container.innerHTML = '<div style="font-size:11px;color:var(--text3);text-align:center;padding:10px 0">No whitelisted domains yet.<br>Add a domain above to skip scanning.</div>';
      return;
    }

    container.innerHTML = whitelist.map(function (domain) {
      return '<div class="whitelist-entry">' +
        '<span class="whitelist-domain">' + domain + '</span>' +
        '<button class="whitelist-remove-btn" data-domain="' + domain + '" title="Remove from whitelist">✕</button>' +
        '</div>';
    }).join('');

    container.querySelectorAll('.whitelist-remove-btn').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        btn.disabled = true;
        await send({ type: 'WHITELIST_REMOVE', domain: btn.dataset.domain });
        loadWhitelist();
      });
    });
  }

  function initWhitelistUI() {
    if (_whitelistListenersAttached) { loadWhitelist(); return; }
    _whitelistListenersAttached = true;

    var addBtn = document.getElementById('whitelist-add-btn');
    var input = document.getElementById('whitelist-input');
    if (!addBtn || !input) return;

    var _isAdding = false;

    async function doAdd() {
      if (_isAdding) return; // prevent double-click duplicates
      var raw = input.value.trim().toLowerCase()
        .replace(/^https?:\/\//, '')
        .replace(/^www\./, '')
        .replace(/\/.*/, '')
        .replace(/\?.*/, '')
        .replace(/^[^@]+@/, '');  // Bug fix: strip email user part (e.g. user@gmail.com → gmail.com)

      if (!raw || !raw.includes('.')) {
        input.style.borderColor = '#ef4444';
        input.placeholder = 'Enter a valid domain (e.g. mybank.com)';
        setTimeout(function () {
          input.style.borderColor = '';
          input.placeholder = 'e.g. mycompany.com';
        }, 1800);
        return;
      }

      _isAdding = true;
      addBtn.disabled = true;
      addBtn.textContent = '⏳';
      await send({ type: 'WHITELIST_ADD', domain: raw });
      input.value = '';
      addBtn.disabled = false;
      addBtn.textContent = '+ Add';
      _isAdding = false;
      loadWhitelist();
    }

    addBtn.addEventListener('click', doAdd);
    input.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') doAdd();
    });

    loadWhitelist();
  }

  // Hook whitelist loader into Settings tab navigation
  var _origLoadSettings = typeof loadSettings === 'function' ? loadSettings : null;
  if (_origLoadSettings) {
    loadSettings = async function () {
      await _origLoadSettings();
      initWhitelistUI();
    };
  }


  // ═══════════════════════════════════════════════════════════════════════
  // FEATURE 3 — Export Full Scan Report as PDF
  // ═══════════════════════════════════════════════════════════════════════

  async function exportReportPDF() {
    var btn = document.getElementById('pdf-export-btn');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Building report…'; }

    var scanData = await send({ type: 'GET_LAST_SCAN' });
    var phase4 = await send({ type: 'GET_PHASE4' });
    var emailContent = await send({ type: 'GET_EMAIL_CONTENT' });
    var vtQuota = await send({ type: 'GET_VT_QUOTA' });

    if (!scanData) {
      if (btn) { btn.disabled = false; btn.textContent = '📄 Export PDF'; }
      alert('No scan data yet — open an email in Gmail first.');
      return;
    }

    var now = new Date().toLocaleString();
    var score = scanData.score !== undefined ? scanData.score : '—';
    var domain = scanData.domain || 'Unknown';
    var scoreNum = typeof score === 'number' ? score : 50;
    // FIX: was a hardcoded 60/90 three-tier scale that had drifted out of
    // sync with the Threats tab's 45/70/90 five-tier scale (see
    // PA_SCORE_TIERS) — a score of 75 used to show "Likely safe" in the
    // popup but "SUSPICIOUS" in this exported report. Now both read from
    // the same source, so the label here always matches the Threats tab.
    var reportTier = paGetScoreTier(scoreNum, !!scanData.whitelisted);
    var scoreColor = reportTier.color;
    var statusLabel = reportTier.label;

    // Auth checks rows
    var checks = scanData.checks || {};
    var checkRows = ['spf', 'dkim', 'dmarc'].map(function (k) {
      var c = checks[k];
      if (!c) return '';
      var icons = { spf: '🔒', dkim: '✍️', dmarc: '📋' };
      var color = c.pass ? '#16a34a' : '#dc2626';
      return '<tr><td>' + icons[k] + ' ' + k.toUpperCase() + '</td>' +
        '<td style="color:' + color + ';font-weight:700">' + (c.pass ? 'PASS' : 'FAIL') + '</td>' +
        '<td style="color:#6b7280;font-size:11px">' + (c.detail || '') + '</td></tr>';
    }).join('');

    // MX row
    var mx = checks.mx || {};
    checkRows += '<tr><td>📮 MX Record</td>' +
      '<td style="color:' + (mx.hasMX ? '#16a34a' : '#dc2626') + ';font-weight:700">' + (mx.hasMX ? 'PASS' : 'FAIL') + '</td>' +
      '<td style="color:#6b7280;font-size:11px">' + (mx.detail || '') + '</td></tr>';

    // Threats list
    var threats = scanData.threats || {};
    var threatItems = [];
    if (threats.displayNameSpoof && threats.displayNameSpoof.spoofing)
      threatItems.push({ icon: '🎭', title: 'Display Name Spoofing', detail: threats.displayNameSpoof.detail || '', severity: 'CRITICAL' });
    if (threats.homograph && threats.homograph.detected)
      threatItems.push({ icon: '🔤', title: 'IDN Homograph Attack', detail: threats.homograph.detail || '', severity: 'CRITICAL' });
    if (threats.punycode && threats.punycode.suspicious)
      threatItems.push({ icon: '🔤', title: 'Punycode / IDN Attack', detail: threats.punycode.detail || '', severity: 'CRITICAL' });
    if (checks.vt && checks.vt.isMalicious)
      threatItems.push({ icon: '🦠', title: 'VirusTotal: Domain Flagged', detail: checks.vt.maliciousCount + ' of ' + checks.vt.totalEngines + ' engines flagged this domain', severity: 'CRITICAL' });

    var headerIssues = (phase4 && phase4.headerAnalysis && phase4.headerAnalysis.issues) || [];
    headerIssues.forEach(function (issue) {
      threatItems.push({
        icon: '📨',
        title: issue.type.replace(/_/g, ' ').replace(/\b\w/g, function (l) { return l.toUpperCase(); }),
        detail: issue.detail || '',
        severity: issue.severity.toUpperCase()
      });
    });

    var threatsHtml = threatItems.length ? threatItems.map(function (t) {
      var sevColor = t.severity === 'CRITICAL' || t.severity === 'HIGH' ? '#991b1b' : '#92400e';
      var sevBg = t.severity === 'CRITICAL' || t.severity === 'HIGH' ? '#fef2f2' : '#fffbeb';
      var sevBorder = t.severity === 'CRITICAL' || t.severity === 'HIGH' ? '#dc2626' : '#f59e0b';
      return '<div style="padding:9px 12px;margin-bottom:7px;border-radius:7px;background:' + sevBg + ';border-left:3px solid ' + sevBorder + '">' +
        '<div style="display:flex;align-items:center;gap:7px;margin-bottom:4px">' +
        '<strong style="color:' + sevColor + '">' + t.icon + ' ' + t.title + '</strong>' +
        '<span style="font-size:10px;background:' + sevBorder + '22;color:' + sevColor + ';padding:1px 7px;border-radius:10px;font-weight:700">' + t.severity + '</span>' +
        '</div>' +
        '<div style="font-size:12px;color:#6b7280">' + t.detail + '</div>' +
        '</div>';
    }).join('') : '<p style="color:#16a34a;font-weight:600">✅ No active threats detected</p>';

    // Trackers & QR
    var trackerSection = '';
    if (phase4 && phase4.trackerResult && phase4.trackerResult.trackerCount > 0) {
      var tc = phase4.trackerResult;
      trackerSection = '<div class="section"><div class="section-title">👁️ Tracking Pixels</div>' +
        '<p>' + tc.trackerCount + ' tracking pixel(s) detected. Trackers reveal your IP and open time.</p>' +
        (tc.trackers || []).slice(0, 3).map(function (t) { return '<div style="font-size:11px;color:#6b7280;padding:3px 0">' + (t.domain || t.src || '') + ' — ' + t.reason + '</div>'; }).join('') +
        '</div>';
    }
    var qrSection = '';
    if (phase4 && phase4.qrResult && phase4.qrResult.qrCount > 0) {
      qrSection = '<div class="section"><div class="section-title">📷 QR Codes</div>' +
        '<p>' + phase4.qrResult.qrCount + ' QR code(s) detected — destinations cannot be previewed without scanning.</p></div>';
    }

    // Recommended actions
    var recs = [];
    if (scoreNum < 45) recs.push('⛔ Do NOT reply, click links, or download attachments from this email');
    if (scoreNum < 90) recs.push('🔍 Verify sender identity through an alternative channel before taking action');
    if (!checks.spf?.pass) recs.push('⚠️ SPF failure — the sending server may not be authorized');
    if (!checks.dmarc?.pass) recs.push('⚠️ No DMARC policy — domain can be freely spoofed');
    if (threats.displayNameSpoof?.spoofing) recs.push('🚩 Display name impersonation detected — this is likely a phishing attempt');
    if (scoreNum >= 90) recs.push('✅ No action required — sender appears legitimate');
    var recsHtml = recs.length ? recs.map(function (r) { return '<li style="margin-bottom:6px">' + r + '</li>'; }).join('') : '<li>No specific action required.</li>';

    var vtQuotaHtml = vtQuota ? vtQuota.used + ' / ' + (vtQuota.date || '') : '—';

    // Build the full HTML report
    var html = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">' +
      '<title>PhishAlert Security Report — ' + domain + '</title>' +
      '<style>' +
      'body{font-family:-apple-system,"Segoe UI",sans-serif;color:#0f172a;background:#f1f5f9;padding:36px 28px;max-width:860px;margin:0 auto;font-size:13px;line-height:1.6}' +
      'h1{font-size:22px;font-weight:900;margin:0}' +
      '.section{background:#fff;border-radius:12px;padding:18px 20px;margin-bottom:16px;border:1px solid #e2e8f0;box-shadow:0 1px 4px rgba(0,0,0,.06)}' +
      '.section-title{font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.6px;color:#64748b;margin-bottom:12px}' +
      'table{width:100%;border-collapse:collapse}' +
      'td{padding:7px 10px;border-bottom:1px solid #e5e7eb;vertical-align:top}' +
      'tr:last-child td{border-bottom:none}' +
      'td:first-child{color:#64748b;width:120px;font-weight:600}' +
      'ul{padding-left:18px;margin:0}' +
      '.footer{text-align:center;margin-top:28px;color:#94a3b8;font-size:11px}' +
      '@media print{body{background:#fff;padding:20px}@page{margin:2cm}}' +
      '</style></head><body>' +

      // Header
      '<div style="display:flex;align-items:center;gap:16px;margin-bottom:22px">' +
      '<div style="width:52px;height:52px;background:linear-gradient(135deg,#1d4ed8,#2563eb);border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:28px;flex-shrink:0">🛡️</div>' +
      '<div><h1>PhishAlert Security Report</h1><div style="color:#64748b;font-size:13px">Generated: ' + now + '</div></div>' +
      '' +
      '</div>' +

      // Email overview
      '<div class="section"><div class="section-title">📧 Email Overview</div>' +
      '<table><tbody>' +
      '<tr><td>Sender Domain</td><td style="font-weight:700;font-family:monospace">' + domain + '</td></tr>' +
      '<tr><td>Subject</td><td>' + (emailContent && emailContent.subject ? emailContent.subject : '—') + '</td></tr>' +
      '<tr><td>Sender</td><td>' + (emailContent && emailContent.sender ? emailContent.sender : '—') + '</td></tr>' +
      '<tr><td>Scan Time</td><td>' + now + '</td></tr>' +
      '</tbody></table>' +
      '</div>' +

      // Trust Score
      '<div class="section"><div class="section-title">🎯 Trust Score</div>' +
      '<div style="display:flex;align-items:center;gap:20px">' +
      '<div style="font-size:56px;font-weight:900;color:' + scoreColor + ';font-family:monospace;line-height:1">' +
      score + '<span style="font-size:22px">/100</span>' +
      '</div>' +
      '<div>' +
      '<span style="display:inline-block;padding:4px 14px;border-radius:20px;background:' + scoreColor + '22;color:' + scoreColor + ';border:1px solid ' + scoreColor + '55;font-weight:800;font-size:13px">' + statusLabel + '</span>' +
      '<div style="font-size:12px;color:#64748b;margin-top:6px">' +
      (scanData.whitelisted ? 'You manually whitelisted this domain — all automated checks were skipped.' :
        scoreNum >= 90 ? 'All major authentication checks passed.' :
        scoreNum >= 70 ? 'Mostly clean, but not every check passed. Low risk.' :
        scoreNum >= 45 ? 'Moderate risk — some checks failed. Exercise caution.' :
          'Significant failures detected. High risk of phishing.') +
      '</div>' +
      '</div>' +
      '</div>' +
      '</div>' +

      // Authentication
      '<div class="section"><div class="section-title">🔒 Authentication Checks</div>' +
      '<table><tbody>' + checkRows + '</tbody></table>' +
      '</div>' +

      // Threats
      '<div class="section"><div class="section-title">🚨 Detected Threats (' + threatItems.length + ')</div>' +
      threatsHtml +
      '</div>' +

      // Trackers & QR
      trackerSection +
      qrSection +

      // Recommendations
      '<div class="section"><div class="section-title">💡 Recommended Actions</div>' +
      '<ul>' + recsHtml + '</ul>' +
      '</div>' +

      // Meta
      '<div class="section"><div class="section-title">ℹ️ Scan Metadata</div>' +
      '<table><tbody>' +
      '<tr><td>VT Usage Today</td><td>' + vtQuotaHtml + ' API calls</td></tr>' +
      '<tr><td>Domain Age</td><td>' + (checks.domainAge && checks.domainAge.detail ? checks.domainAge.detail : '—') + '</td></tr>' +
      '<tr><td>Phishing Extension</td><td>PhishAlert</td></tr>' +
      '</tbody></table>' +
      '</div>' +

      '<div class="footer">Generated by PhishAlert · ' + now + ' · For security documentation purposes only<br>This report is based on automated checks and should be reviewed by a security professional.</div>' +

      '<script>window.onload=function(){window.print();}<\/script>' +
      '</body></html>';

    // Open report in new tab
    var blob = new Blob([html], { type: 'text/html' });
    var url = URL.createObjectURL(blob);
    chrome.tabs.create({ url: url });

    if (btn) {
      setTimeout(function () { btn.disabled = false; btn.textContent = '📄 Export PDF'; }, 2000);
    }
  }

  // Hook PDF export button on Threats tab load
  var _origLoadThreats = typeof loadThreats === 'function' ? loadThreats : null;
  if (_origLoadThreats) {
    loadThreats = async function () {
      await _origLoadThreats();
      // Attach PDF export button handler each time threats tab loads
      var pdfBtn = document.getElementById('pdf-export-btn');
      if (pdfBtn && !pdfBtn._pdfAttached) {
        pdfBtn._pdfAttached = true;
        pdfBtn.addEventListener('click', exportReportPDF);
      }
    };
  }

  // ═══════════════════════════════════════════════════════════════════════
  // REPORTS V2 — Case/Report Management (Report Dashboard, Repository,
  // Status lifecycle, Report Builder, Case Detail view, PDF export)
  // ═══════════════════════════════════════════════════════════════════════
  var _rpCases = [];
  var _rpFilter = 'all';
  var _rpSearch = '';
  var _rpOpenCaseId = null;
  var _rpBuilderType = 'incident';

  function rpStatusClass(status) {
    switch (status) {
      case 'INVESTIGATING': return 'rp-status-investigating';
      case 'CONTAINED': return 'rp-status-contained';
      case 'RESOLVED': return 'rp-status-resolved';
      default: return 'rp-status-open';
    }
  }

  function rpSeverityIcon(record) {
    if (record.reportType === 'threat_intel') return '📈';
    var tier = record.tier;
    if (tier === 'CRITICAL' || tier === 'HIGH RISK') return '🔴';
    if (tier === 'SUSPICIOUS') return '🟠';
    return '🟢';
  }

  function rpTypeLabel(type) {
    return { incident: 'Incident Report', executive: 'Executive Summary', forensic: 'Forensic Report', threat_intel: 'Threat Intelligence' }[type] || 'Report';
  }

  function rpMatchesFilter(record, filter) {
    if (filter === 'all') return true;
    if (filter === 'resolved') return record.status === 'RESOLVED';
    if (filter === 'phishing') return record.tier === 'CRITICAL' || record.tier === 'HIGH RISK';
    if (filter === 'suspicious') return record.tier === 'SUSPICIOUS';
    return true;
  }

  function rpMatchesSearch(record, q) {
    if (!q) return true;
    q = q.toLowerCase();
    return (record.id || '').toLowerCase().includes(q) ||
      (record.domain || '').toLowerCase().includes(q) ||
      (record.sender || '').toLowerCase().includes(q) ||
      (record.attackType || '').toLowerCase().includes(q);
  }

  function rpCaseCardHtml(r) {
    var evCount = r.checks ? Object.keys(r.checks).filter(function (k) { return r.checks[k]; }).length : 0;
    var iocCount = r.iocs ? ((r.iocs.domains || []).length + (r.iocs.urls || []).length + (r.iocs.ipAddresses || []).length + (r.iocs.emailAddresses || []).length) : 0;
    return '<div class="rp-case-card" data-case-id="' + r.id + '">' +
      '<div class="rp-case-top">' +
      '<span class="rp-case-id">' + rpSeverityIcon(r) + ' ' + r.id + '</span>' +
      '<span class="rp-status-badge ' + rpStatusClass(r.status) + '">' + r.status + '</span>' +
      '</div>' +
      '<div class="rp-case-title">' + invEsc(r.attackType || rpTypeLabel(r.reportType)) + '</div>' +
      (r.domain ? '<div class="rp-case-domain">' + invEsc(r.domain) + (r.score != null ? ' · Score: ' + r.score + '/100' : '') + '</div>' : '') +
      '<div class="rp-case-meta-row">' +
      '<span>📄 ' + rpTypeLabel(r.reportType) + '</span>' +
      (evCount ? '<span>🧪 Evidence: ' + evCount + '</span>' : '') +
      (iocCount ? '<span>🔎 IOCs: ' + iocCount + '</span>' : '') +
      (r.campaign ? '<span>🧬 Campaign: ' + r.campaign.confidence + '%</span>' : '') +
      '</div>' +
      '<div class="rp-case-actions">' +
      '<button class="rp-view-btn" data-case-id="' + r.id + '">👁️ View Case</button>' +
      '<button class="rp-pdf-btn" data-case-id="' + r.id + '">📄 Export PDF</button>' +
      '<button class="rp-delete-btn" data-case-id="' + r.id + '">🗑️</button>' +
      '</div>' +
      '</div>';
  }

  function rpRenderCaseList() {
    var container = document.getElementById('rp-case-list');
    if (!container) return;
    var filtered = _rpCases.filter(function (r) { return rpMatchesFilter(r, _rpFilter) && rpMatchesSearch(r, _rpSearch); });
    if (!filtered.length) {
      container.innerHTML = '<div class="empty"><span class="empty-icon">🗂️</span><strong>No reports yet</strong>Generate a report from a scanned email to start building your case history.</div>';
      return;
    }
    container.innerHTML = filtered.map(rpCaseCardHtml).join('');

    container.querySelectorAll('.rp-case-card').forEach(function (card) {
      card.addEventListener('click', function (e) {
        if (e.target.closest('button')) return;
        rpOpenCaseModal(card.dataset.caseId);
      });
    });
    container.querySelectorAll('.rp-view-btn').forEach(function (btn) {
      btn.addEventListener('click', function (e) { e.stopPropagation(); rpOpenCaseModal(btn.dataset.caseId); });
    });
    container.querySelectorAll('.rp-pdf-btn').forEach(function (btn) {
      btn.addEventListener('click', function (e) {
        e.stopPropagation();
        var r = _rpCases.find(function (c) { return c.id === btn.dataset.caseId; });
        if (r) rpExportCasePdf(r);
      });
    });
    container.querySelectorAll('.rp-delete-btn').forEach(function (btn) {
      btn.addEventListener('click', async function (e) {
        e.stopPropagation();
        if (!confirm('Delete case ' + btn.dataset.caseId + '? This cannot be undone.')) return;
        await send({ type: 'DELETE_CASE_REPORT', id: btn.dataset.caseId });
        await rpLoadCaseList();
      });
    });
  }

  function rpRenderDashboard() {
    var total = _rpCases.length;
    var phishing = _rpCases.filter(function (r) { return r.tier === 'CRITICAL' || r.tier === 'HIGH RISK'; }).length;
    var suspicious = _rpCases.filter(function (r) { return r.tier === 'SUSPICIOUS'; }).length;
    var resolved = _rpCases.filter(function (r) { return r.status === 'RESOLVED'; }).length;
    var elT = document.getElementById('rp-stat-total'); if (elT) elT.textContent = total;
    var elP = document.getElementById('rp-stat-phishing'); if (elP) elP.textContent = phishing;
    var elS = document.getElementById('rp-stat-suspicious'); if (elS) elS.textContent = suspicious;
    var elR = document.getElementById('rp-stat-resolved'); if (elR) elR.textContent = resolved;
  }

  async function rpLoadCaseList() {
    var container = document.getElementById('rp-case-list');
    if (container) container.innerHTML = '<div class="loading">Loading reports…</div>';
    try {
      _rpCases = await send({ type: 'GET_CASE_REPORTS' }) || [];
    } catch (e) {
      _rpCases = [];
    }
    rpRenderDashboard();
    rpRenderCaseList();
  }

  // ── Case Detail Modal ──────────────────────────────────────────────────
  function rpCaseOverviewHtml(r) {
    var verdictClass = (r.tier === 'CRITICAL' || r.tier === 'HIGH RISK') ? 'critical' : r.tier === 'SUSPICIOUS' ? 'warn' : 'safe';
    var html = '<div class="tf-verdict ' + verdictClass + '">' +
      '<div>' +
      '<div style="font-weight:800;font-size:13px">' + rpSeverityIcon(r) + ' ' + invEsc(r.tier || '') + '</div>' +
      '<div style="font-size:12px;margin-top:3px;color:var(--text2)">' + invEsc(r.attackType || '') + (r.targetBrand ? ' · targets ' + invEsc(r.targetBrand) : '') + '</div>' +
      '</div>' +
      (r.score != null ? '<div class="tf-verdict-meta"><div><div class="tf-verdict-meta-num">' + r.score + '</div><div class="tf-verdict-meta-label">Score</div></div></div>' : '') +
      '</div>';

    html += '<div class="tf-section"><div class="tf-section-title">🚨 Threat Findings</div>';
    if (r.findings && r.findings.length) {
      html += r.findings.map(function (f) {
        return '<div class="tf-timeline-item"><div class="tf-timeline-dot' + (f.level === 'critical' ? ' flag' : '') + '"></div>' +
          '<div><div class="tf-timeline-text">' + (f.icon || '⚠️') + ' ' + invEsc(f.title) + '</div></div></div>';
      }).join('');
    } else {
      html += '<div class="inv-empty">No specific issues detected</div>';
    }
    html += '</div>';

    var related = _rpCases.filter(function (o) {
      return o.id !== r.id && ((o.domain && o.domain === r.domain) || (o.campaign && r.campaign && o.campaign.brand && o.campaign.brand === r.campaign.brand));
    }).slice(0, 5);
    if (related.length) {
      html += '<div class="tf-section"><div class="tf-section-title">🔗 Related Cases</div><div class="inv-chip-row">' +
        related.map(function (o) { return '<span class="inv-chip rp-related-chip" data-case-id="' + o.id + '" style="cursor:pointer">' + o.id + '</span>'; }).join('') +
        '</div></div>';
    }

    html += '<div class="tf-section"><div class="tf-section-title">📄 Report Text</div>' +
      '<div class="inv-report-output">' + invEsc(r.reportText || '') + '</div>' +
      '<button class="inv-copy-btn" id="rp-case-copy-btn">📋 Copy Report</button>' +
      '</div>';

    return html;
  }

  function rpCaseEvidenceHtml(r) {
    var c = r.checks || {};
    if (!c || !Object.keys(c).length) return '<div class="tf-section"><div class="inv-empty">No raw evidence stored for this report type.</div></div>';
    var rows = '';
    rows += tfEvidenceRow('SPF', c.spf && c.spf.pass, c.spf && c.spf.detail, !c.spf);
    rows += tfEvidenceRow('DKIM', c.dkim && c.dkim.pass, c.dkim && c.dkim.detail, !c.dkim ? true : (c.dkim.inconclusive ? 'unverified' : false));
    rows += tfEvidenceRow('DMARC', c.dmarc && c.dmarc.pass, c.dmarc && c.dmarc.detail, !c.dmarc);
    rows += tfEvidenceRow('MX', !(c.mx && c.mx.suspicious), c.mx && c.mx.detail, !c.mx);
    rows += tfEvidenceRow('BIMI', !!(c.bimi && c.bimi.hasBIMI && c.bimi.hasVMC), c.bimi && (c.bimi.isImpersonatingBrand ? 'No record — likely impersonating ' + c.bimi.claimedBrand : c.bimi.detail), !c.bimi);
    rows += tfEvidenceRow('URLhaus', !(c.urlhaus && c.urlhaus.malicious), c.urlhaus && c.urlhaus.threat, !c.urlhaus);
    rows += tfEvidenceRow('VirusTotal', c.vt && c.vt.available ? !c.vt.isMalicious : null, c.vt && c.vt.available ? (c.vt.maliciousCount + ' / ' + c.vt.totalEngines + ' engines') : '', !(c.vt && c.vt.available));
    rows += tfEvidenceRow('DNS Blacklist', !(c.dnsbl && c.dnsbl.listed), c.dnsbl && (c.dnsbl.listings || []).map(function (l) { return l.source; }).join(', '), !c.dnsbl);
    return '<div class="tf-section"><div class="tf-section-title">🧪 Evidence</div><table class="tf-evidence-table"><tbody>' + rows + '</tbody></table></div>';
  }

  function rpCaseIOCsHtml(r) {
    var iocs = r.iocs;
    if (!iocs) return '<div class="tf-section"><div class="inv-empty">No IOC data stored for this report type.</div></div>';
    var html = '<div class="tf-section"><div class="tf-section-title">🔎 Indicators of Compromise</div>';
    html += '<div class="inv-section"><div class="inv-section-title">🌐 Domains (' + (iocs.domains || []).length + ')</div>' + invChipRow(iocs.domains) + '</div>';
    html += '<div class="inv-section"><div class="inv-section-title">🔗 URLs (' + (iocs.urls || []).length + ')</div>' + invChipRow(iocs.urls) + '</div>';
    if (iocs.ipAddresses && iocs.ipAddresses.length) html += '<div class="inv-section"><div class="inv-section-title">🖥️ IP Addresses</div>' + invChipRow(iocs.ipAddresses) + '</div>';
    html += '<div class="inv-section"><div class="inv-section-title">📧 Email Addresses</div>' + invChipRow(iocs.emailAddresses) + '</div>';
    if (r.hash) html += '<div class="inv-section"><div class="inv-section-title">🔐 Evidence Integrity (SHA-256)</div><div style="font-family:var(--mono);font-size:10.5px;color:var(--text3);word-break:break-all">' + r.hash + '</div></div>';
    html += '</div>';
    return html;
  }

  function rpCaseTimelineHtml(r) {
    var entries = [];
    entries.push({ t: r.timestamp || r.createdAt, text: 'Email received &amp; scanned by PhishAlert', flagged: false });
    if (r.iocsExtractedAt) entries.push({ t: r.iocsExtractedAt, text: 'Indicators of compromise extracted', flagged: false });
    if (r.replyToMismatch) entries.push({ t: r.timestamp, text: 'Reply-To mismatch detected', flagged: true });
    if (r.campaign) entries.push({ t: r.createdAt, text: 'Correlated to existing campaign (' + r.campaign.emailCount + ' related emails)', flagged: true });
    entries.push({ t: r.createdAt, text: 'Report generated (' + rpTypeLabel(r.reportType) + ')', flagged: false });
    entries.sort(function (a, b) { return (a.t || 0) - (b.t || 0); });
    return '<div class="tf-section"><div class="tf-section-title">🕒 Evidence Timeline</div><div class="tf-timeline">' +
      entries.map(function (e) { return tfTimelineItem(e.text, e.t, e.flagged); }).join('') +
      '</div></div>';
  }

  var _rpCaseGroupBuilders = { overview: rpCaseOverviewHtml, evidence: rpCaseEvidenceHtml, iocs: rpCaseIOCsHtml, timeline: rpCaseTimelineHtml };

  function rpShowCaseGroup(name, r) {
    var body = document.getElementById('rp-case-modal-body');
    if (!body) return;
    body.innerHTML = (_rpCaseGroupBuilders[name] || rpCaseOverviewHtml)(r);
    document.querySelectorAll('#rp-case-subnav .tf-subnav-btn').forEach(function (b) {
      b.classList.toggle('active', b.getAttribute('data-rpgroup') === name);
    });
    var copyBtn = document.getElementById('rp-case-copy-btn');
    if (copyBtn) copyBtn.addEventListener('click', function () {
      navigator.clipboard.writeText(r.reportText || '').then(function () {
        copyBtn.textContent = '✅ Copied!';
        setTimeout(function () { copyBtn.textContent = '📋 Copy Report'; }, 2000);
      });
    });
    body.querySelectorAll('.rp-related-chip').forEach(function (chip) {
      chip.addEventListener('click', function () { rpOpenCaseModal(chip.dataset.caseId); });
    });
  }

  function rpOpenCaseModal(id) {
    var r = _rpCases.find(function (c) { return c.id === id; });
    if (!r) return;
    _rpOpenCaseId = id;
    var modal = document.getElementById('rp-case-modal');
    var title = document.getElementById('rp-case-modal-title');
    var statusSel = document.getElementById('rp-case-status-select');
    if (title) title.textContent = r.id + ' — ' + rpTypeLabel(r.reportType);
    if (statusSel) statusSel.value = r.status;
    if (modal) modal.style.display = 'flex';
    rpShowCaseGroup('overview', r);
  }

  function rpCloseCaseModal() {
    var modal = document.getElementById('rp-case-modal');
    if (modal) modal.style.display = 'none';
    _rpOpenCaseId = null;
  }

  // ── PDF export for a stored case (reuses the same print-tab pattern as
  //    the Threats & Forensics export, so it works within the extension
  //    CSP without any external library). ────────────────────────────────
  function rpExportCasePdf(r) {
    var now = new Date(r.createdAt).toLocaleString();
    var tierColor = (r.tier === 'CRITICAL' || r.tier === 'HIGH RISK') ? '#dc2626' : r.tier === 'SUSPICIOUS' ? '#d97706' : '#16a34a';
    var findingsHtml = (r.findings || []).length
      ? '<ul>' + r.findings.map(function (f) { return '<li>' + (f.icon || '') + ' ' + invEsc(f.title || '') + '</li>'; }).join('') + '</ul>'
      : '<p style="color:#16a34a">No specific issues detected.</p>';
    var html = '<!DOCTYPE html><html><head><meta charset="UTF-8"><title>' + r.id + ' — PhishAlert Report</title>' +
      '<style>body{font-family:-apple-system,"Segoe UI",sans-serif;color:#0f172a;background:#f1f5f9;padding:32px 26px;max-width:820px;margin:0 auto;font-size:13px;line-height:1.6}' +
      '.section{background:#fff;border-radius:12px;padding:16px 18px;margin-bottom:14px;border:1px solid #e2e8f0}' +
      '.section-title{font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.5px;color:#64748b;margin-bottom:10px}' +
      'pre{white-space:pre-wrap;font-family:inherit;font-size:12.5px}' +
      '@media print{body{background:#fff}@page{margin:2cm}}</style></head><body>' +
      '<div style="display:flex;align-items:center;gap:14px;margin-bottom:18px">' +
      '<div style="width:46px;height:46px;background:linear-gradient(135deg,#1d4ed8,#2563eb);border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:24px">🛡️</div>' +
      '<div><h1 style="margin:0;font-size:20px">' + rpTypeLabel(r.reportType) + '</h1><div style="color:#64748b">Case ' + r.id + ' · Generated ' + now + '</div></div></div>' +
      '<div class="section"><div class="section-title">Verdict</div>' +
      '<div style="font-size:34px;font-weight:900;color:' + tierColor + '">' + (r.score != null ? r.score + '/100' : (r.tier || '')) + '</div>' +
      '<div style="color:' + tierColor + ';font-weight:700">' + (r.tier || '') + ' — ' + (r.attackType || '') + '</div></div>' +
      '<div class="section"><div class="section-title">Threat Findings</div>' + findingsHtml + '</div>' +
      '<div class="section"><div class="section-title">Full Report</div><pre>' + invEsc(r.reportText || '') + '</pre></div>' +
      '<div style="text-align:center;color:#94a3b8;font-size:11px;margin-top:20px">Generated by PhishAlert · For security documentation purposes only</div>' +
      '<script>window.onload=function(){window.print();}<\/script></body></html>';
    var blob = new Blob([html], { type: 'text/html' });
    var url = URL.createObjectURL(blob);
    chrome.tabs.create({ url: url });
  }

  // ── Report Builder ─────────────────────────────────────────────────────
  function rpOpenBuilder() {
    var modal = document.getElementById('rp-builder-modal');
    var out = document.getElementById('rp-builder-output');
    if (out) out.innerHTML = '';
    if (modal) modal.style.display = 'flex';
  }

  function rpCloseBuilder() {
    var modal = document.getElementById('rp-builder-modal');
    if (modal) modal.style.display = 'none';
  }

  async function rpGenerateFromBuilder() {
    var btn = document.getElementById('rp-builder-generate-btn');
    var out = document.getElementById('rp-builder-output');
    if (btn) { btn.disabled = true; btn.textContent = '⏳ Generating…'; }
    if (out) out.innerHTML = '';

    var res;
    if (_rpBuilderType !== 'threat_intel') {
      var scan = await send({ type: 'GET_LAST_SCAN' });
      if (!scan) {
        if (btn) { btn.disabled = false; btn.textContent = 'Generate Report'; }
        if (out) out.innerHTML = '<div class="error-msg">⚠️ No scan data yet — open an email in Gmail first.</div>';
        return;
      }
      res = await send({ type: 'GENERATE_CASE_REPORT', reportType: _rpBuilderType, scanEntry: scan });
    } else {
      res = await send({ type: 'GENERATE_CASE_REPORT', reportType: 'threat_intel' });
    }

    if (btn) { btn.disabled = false; btn.textContent = 'Generate Report'; }
    if (!res || !res.success) {
      if (out) out.innerHTML = '<div class="error-msg">⚠️ ' + ((res && res.error) || 'Could not generate report') + '</div>';
      return;
    }
    if (out) {
      out.innerHTML = '<div class="report-success-banner" style="display:block">✅ Saved as case ' + res.case.id + '</div>' +
        '<div class="inv-report-output">' + invEsc(res.case.reportText) + '</div>';
    }
    await rpLoadCaseList();
  }

  function rpAttachStaticListeners() {
    var genBtn = document.getElementById('rp-generate-btn');
    if (genBtn && !genBtn._rpAttached) { genBtn._rpAttached = true; genBtn.addEventListener('click', rpOpenBuilder); }

    var builderClose = document.getElementById('rp-builder-close');
    if (builderClose && !builderClose._rpAttached) { builderClose._rpAttached = true; builderClose.addEventListener('click', rpCloseBuilder); }

    var builderGen = document.getElementById('rp-builder-generate-btn');
    if (builderGen && !builderGen._rpAttached) { builderGen._rpAttached = true; builderGen.addEventListener('click', rpGenerateFromBuilder); }

    document.querySelectorAll('#rp-builder-types .rp-type-btn').forEach(function (b) {
      if (b._rpAttached) return;
      b._rpAttached = true;
      b.addEventListener('click', function () {
        document.querySelectorAll('#rp-builder-types .rp-type-btn').forEach(function (o) { o.classList.remove('active'); });
        b.classList.add('active');
        _rpBuilderType = b.dataset.type;
        var hint = document.getElementById('rp-builder-hint');
        if (hint) {
          hint.textContent = _rpBuilderType === 'threat_intel'
            ? "Uses this week's scan history — no email needs to be open."
            : 'Generates from the email currently open in Gmail.';
        }
      });
    });

    var caseModalClose = document.getElementById('rp-case-modal-close');
    if (caseModalClose && !caseModalClose._rpAttached) { caseModalClose._rpAttached = true; caseModalClose.addEventListener('click', rpCloseCaseModal); }

    var pdfBtn = document.getElementById('rp-case-pdf-btn');
    if (pdfBtn && !pdfBtn._rpAttached) {
      pdfBtn._rpAttached = true;
      pdfBtn.addEventListener('click', function () {
        var r = _rpCases.find(function (c) { return c.id === _rpOpenCaseId; });
        if (r) rpExportCasePdf(r);
      });
    }

    document.querySelectorAll('#rp-case-subnav .tf-subnav-btn').forEach(function (b) {
      if (b._rpAttached) return;
      b._rpAttached = true;
      b.addEventListener('click', function () {
        var r = _rpCases.find(function (c) { return c.id === _rpOpenCaseId; });
        if (r) rpShowCaseGroup(b.getAttribute('data-rpgroup'), r);
      });
    });

    var statusSel = document.getElementById('rp-case-status-select');
    if (statusSel && !statusSel._rpAttached) {
      statusSel._rpAttached = true;
      statusSel.addEventListener('change', async function () {
        if (!_rpOpenCaseId) return;
        await send({ type: 'UPDATE_CASE_STATUS', id: _rpOpenCaseId, status: statusSel.value });
        await rpLoadCaseList();
      });
    }

    document.querySelectorAll('.rp-filter-chip').forEach(function (chip) {
      if (chip._rpAttached) return;
      chip._rpAttached = true;
      chip.addEventListener('click', function () {
        document.querySelectorAll('.rp-filter-chip').forEach(function (c) { c.classList.remove('active'); });
        chip.classList.add('active');
        _rpFilter = chip.dataset.filter;
        rpRenderCaseList();
      });
    });

    var searchInput = document.getElementById('rp-search');
    if (searchInput && !searchInput._rpAttached) {
      searchInput._rpAttached = true;
      searchInput.addEventListener('input', function () {
        _rpSearch = searchInput.value.trim();
        rpRenderCaseList();
      });
    }
  }

  // Wrap loadReports once more: load the case dashboard/repository first,
  // then fall through to the already-patched community/adaptive rendering
  // (adaptive learning, one-click report, blocked senders, community
  // reports, CSV export — all unchanged, just moved down the page).
  var _rpOriginalLoadReports = loadReports;
  loadReports = async function () {
    rpAttachStaticListeners();
    await rpLoadCaseList();
    await _rpOriginalLoadReports();
  };

  // ─── Bootstrap all new features on popup open ────────────────────────────
  (async function initNewFeatures() {
    // Theme (must be first — before any rendering)
    await initTheme();

    // Theme toggle button
    var themeBtn = document.getElementById('theme-toggle-btn');
    if (themeBtn) themeBtn.addEventListener('click', toggleTheme);

    // Onboarding
    initOnboarding();
    await checkFirstRun();

    // PDF export (attach if threats tab is already rendered)
    var pdfBtn = document.getElementById('pdf-export-btn');
    if (pdfBtn && !pdfBtn._pdfAttached) {
      pdfBtn._pdfAttached = true;
      pdfBtn.addEventListener('click', exportReportPDF);
    }

    // Whitelist (only if settings panel is the default open tab)
    var settingsPanel = document.getElementById('tab-settings');
    if (settingsPanel && settingsPanel.classList.contains('active')) {
      initWhitelistUI();
    }
  })();

})();