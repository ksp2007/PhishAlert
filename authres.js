// PhishAlert — authres.js
// Parses the Authentication-Results headers (RFC 8601) of an actual delivered message
// and answers: did THIS message pass SPF / DKIM / DMARC for the domain in its From line?
//
// Why this exists: the DNS check ("does paypal.com publish an SPF/DKIM/DMARC record?")
// says nothing about whether a given message was authorised by that domain. A forged
// "From: x@paypal.com" sent from anywhere sees the same published records and looked like
// a pass. The only trustworthy evidence is what the *receiving* server recorded.
//
// Trust model — two things make an Authentication-Results header worth believing:
//  1. It was added by the receiving provider: its authserv-id matches a known receiver
//     pattern. Anyone can put a fake "Authentication-Results: mx.google.com; spf=pass" line
//     in a message they send, so headers from other hosts are ignored.
//  2. Position. Receivers prepend, so the genuine one is above anything the sender injected.
//     Only the first trusted header is used.
// A result also only counts for the From domain when it is *aligned* with it: "spf=pass" for
// smtp.mailfrom=evil.com says nothing about paypal.com.
//
// Loaded via importScripts() in the background service worker (after psl.js).
(function (g) {
  'use strict';

  // authserv-id patterns of receivers whose headers we trust. Add a provider here once you
  // have confirmed what its servers actually stamp.
  var TRUSTED_RECEIVERS = [
    /(^|\.)mx\.google\.com$/i,                 // Gmail
    /(^|\.)google\.com$/i,
    /\.protection\.outlook\.com$/i,            // Outlook / Microsoft 365
    /(^|\.)outlook\.com$/i,
    /(^|\.)mail\.yahoo\.com$/i,                // Yahoo
    /(^|\.)yahoo\.com$/i,
    /(^|\.)protonmail\.ch$/i,                  // Proton
    /(^|\.)proton\.me$/i
  ];

  function unfold(raw) { return String(raw || '').replace(/\r?\n[ \t]+/g, ' '); }

  // Split a header blob into [{name, value}], unfolding continuation lines. Stops at the
  // blank line separating headers from body.
  function splitHeaders(raw) {
    var text = unfold(String(raw || '').split(/\r?\n\r?\n/)[0]);
    var out = [];
    text.split(/\r?\n/).forEach(function (line) {
      var m = line.match(/^([!-9;-~]+):\s*(.*)$/);
      if (m) out.push({ name: m[1].toLowerCase(), value: m[2] });
    });
    return out;
  }

  function stripComments(s) {          // RFC 5322 comments: (like this)
    var prev;
    do { prev = s; s = s.replace(/\([^()]*\)/g, ''); } while (s !== prev);
    return s;
  }

  // "mx.google.com; spf=pass smtp.mailfrom=a.com; dkim=pass header.d=a.com ..."
  // Exchange Online omits the authserv-id and starts straight with "spf=pass ...", so when the
  // first segment is itself a method=result pair we treat the id as empty (anonymous).
  function parseOne(value) {
    var rawParts = String(value || '').split(';').map(function (p) { return p.trim(); }).filter(Boolean);
    if (!rawParts.length) return null;
    var parts = rawParts.map(stripComments).map(function (p) { return p.trim(); });
    var anonymous = /^[a-z0-9-]+\s*=\s*[a-z0-9_-]+/i.test(parts[0]);
    var id = anonymous ? '' : parts[0].split(/\s+/)[0].toLowerCase();
    var res = { authservId: id, anonymous: anonymous, results: [] };
    (anonymous ? parts : parts.slice(1)).forEach(function (p, i) {
      var m = p.match(/^([a-z0-9-]+)\s*=\s*([a-z0-9_-]+)\s*(.*)$/i);
      if (!m) return;
      var r = { method: m[1].toLowerCase(), result: m[2].toLowerCase(), props: {} };
      var re = /([a-z0-9-]+\.[a-z0-9-]+)\s*=\s*("[^"]*"|[^\s;]+)/gi, pm;
      while ((pm = re.exec(m[3]))) r.props[pm[1].toLowerCase()] = pm[2].replace(/^"|"$/g, '').toLowerCase();
      // Gmail puts the DMARC policy in a comment: dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=x
      // Exchange uses action=none. stripComments() would throw both away, so read them first.
      if (r.method === 'dmarc') {
        var raw = rawParts[anonymous ? i : i + 1] || '';
        var pol = raw.match(/\bp\s*=\s*(none|quarantine|reject)/i) || m[3].match(/\bp\s*=\s*(none|quarantine|reject)/i);
        var act = m[3].match(/\baction\s*=\s*([a-z]+)/i) || raw.match(/\bdis\s*=\s*(none|quarantine|reject)/i);
        if (pol) r.props['policy.p'] = pol[1].toLowerCase();
        if (act) r.props['policy.action'] = act[1].toLowerCase();
      }
      res.results.push(r);
    });
    return res;
  }

  function domainOf(addr) {
    var s = String(addr || '').toLowerCase();
    var m = s.match(/@([a-z0-9.-]+)/);
    return (m ? m[1] : s.replace(/^.*[\s<]/, '').replace(/>.*$/, '')).replace(/\.+$/, '');
  }
  function root(h) { return (typeof g.paRootDomain === 'function') ? g.paRootDomain(h) : h; }
  function aligned(a, b) { return !!a && !!b && root(a) === root(b); }   // DMARC "relaxed"

  // pass | unaligned (passed, but for a different domain than From) | fail | none | error
  function status(result, isAligned) {
    if (result === 'pass') return isAligned ? 'pass' : 'unaligned';
    if (result === 'none') return 'none';
    if (result === 'temperror' || result === 'permerror') return 'error';
    return 'fail';   // fail, softfail, neutral, policy, hardfail
  }

  function trusted(authservId) { return TRUSTED_RECEIVERS.some(function (re) { return re.test(authservId); }); }
  // An id-less header (Exchange Online) is believed only when the message also carries Exchange's
  // own stamp. Position still protects us: only the first trusted header is ever used.
  function exchangeStamped(hdrs) {
    return hdrs.some(function (h) { return /^x-ms-exchange-(organization-authsource|crosstenant-id|organization-authas)$/.test(h.name); });
  }

  // Main entry. `rawHeaders`: the message's header block. `fromDomain`: domain from the
  // From address (taken from the same headers if omitted).
  // Returns { source:'message'|'none', verified:boolean, reason, spf, dkim, dmarc, receiver }
  // where spf/dkim/dmarc are { result, aligned, pass } and `pass` is true only for a
  // trusted, aligned pass. Never throws.
  function evaluate(rawHeaders, fromDomain) {
    var out = { source: 'none', verified: false, reason: null, receiver: null,
                spf: null, dkim: null, dmarc: null, untrustedIgnored: 0 };
    try {
      var hdrs = splitHeaders(rawHeaders);
      var from = fromDomain || domainOf((hdrs.filter(function (h) { return h.name === 'from'; })[0] || {}).value);
      var all = hdrs.filter(function (h) { return h.name === 'authentication-results'; })
                    .map(function (h) { return parseOne(h.value); }).filter(Boolean);
      if (!all.length) { out.reason = 'No Authentication-Results header in this message'; return out; }

      var firstTrusted = null;
      all.forEach(function (a) { if (a.anonymous ? exchangeStamped(hdrs) : trusted(a.authservId)) { if (!firstTrusted) firstTrusted = a; } else out.untrustedIgnored++; });
      if (!firstTrusted) {
        out.reason = 'Authentication-Results present but not from a recognised receiving server (' +
                     all.map(function (a) { return a.authservId || '(no authserv-id)'; }).join(', ') + ') — ignored, it could be forged';
        return out;
      }
      out.source = 'message';
      out.receiver = firstTrusted.authservId || 'Exchange Online';

      function pick(method) { return firstTrusted.results.filter(function (r) { return r.method === method; }); }

      // SPF: counts only if the authenticated envelope domain aligns with From
      var spf = pick('spf')[0];
      if (spf) {
        var mf = domainOf(spf.props['smtp.mailfrom'] || spf.props['smtp.helo']);
        out.spf = { result: spf.result, domain: mf, aligned: aligned(mf, from) };
        out.spf.pass = spf.result === 'pass' && out.spf.aligned;
        out.spf.status = status(spf.result, out.spf.aligned);
      }
      // DKIM: any signature that passed AND is aligned with From
      var dk = pick('dkim');
      if (dk.length) {
        var best = dk.filter(function (r) { return r.result === 'pass' && aligned(domainOf(r.props['header.d'] || r.props['header.i']), from); })[0];
        var first = best || dk[0];
        var d = domainOf(first.props['header.d'] || first.props['header.i']);
        out.dkim = { result: first.result, domain: d, aligned: aligned(d, from), pass: !!best };
        out.dkim.status = status(first.result, out.dkim.aligned);
        // Google Workspace signs with <from-domain-with-dashes>.<selector>.gappssmtp.com until the
        // domain's admin enables its own DKIM key. The tenant name embeds the From domain, so a
        // valid signature there is Google vouching for that tenant. Not strict DMARC alignment, so
        // flagged separately instead of being called a plain pass.
        if (!best) {
          var want = String(from).replace(/\./g, '-');
          var gd = dk.filter(function (r) {
            var sd = domainOf(r.props['header.d'] || r.props['header.i']);
            return r.result === 'pass' && sd.slice(-14) === '.gappssmtp.com' && sd.split('.')[0] === want;
          })[0];
          if (gd) {
            out.dkim = { result: 'pass', domain: domainOf(gd.props['header.d'] || gd.props['header.i']),
                         aligned: false, pass: false, status: 'google-default' };
          }
        }
        if (out.dkim) out.dkim.signers = dk.map(function (r) { var sd = domainOf(r.props['header.d'] || r.props['header.i']); return (sd || 'no signature') + ': ' + r.result; });
      }
      // DMARC: authoritative for the From domain when the receiver evaluated it
      var dm = pick('dmarc')[0];
      if (dm) {
        var hf = domainOf(dm.props['header.from']);
        out.dmarc = { result: dm.result, domain: hf, aligned: aligned(hf, from),
                      policy: dm.props['policy.p'] || dm.props['policy.published-domain-policy'] || dm.props['policy.applied-disposition'] || null,
                      action: dm.props['policy.action'] || null };
        out.dmarc.pass = dm.result === 'pass' && out.dmarc.aligned;
        out.dmarc.status = status(dm.result, out.dmarc.aligned);
      }
      out.verified = !!(out.dmarc ? out.dmarc.pass : (out.spf && out.spf.pass) || (out.dkim && out.dkim.pass));
      out.reason = out.verified ? 'Receiving server authenticated this message for ' + from
                                : 'Receiving server did NOT authenticate this message for ' + from;
    } catch (e) {
      out.source = 'none'; out.reason = 'Could not parse headers';
    }
    return out;
  }

  g.paAuthRes = { evaluate: evaluate, splitHeaders: splitHeaders, parseOne: parseOne };
})(typeof self !== 'undefined' ? self : globalThis);
