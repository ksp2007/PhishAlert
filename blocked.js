// PhishAlert — blocked.js (interstitial shown by the navigation guard in background.js)
// All values come from the query string, which a web page could in theory craft, so everything is
// rendered with textContent and the target URL is re-validated before it is ever navigated to.
(function () {
  'use strict';
  var q = new URLSearchParams(location.search);
  var url = q.get('u') || '';
  var kind = q.get('k') === 'warn' ? 'warn' : 'block';
  var reasons = [];
  try { reasons = JSON.parse(q.get('r') || '[]'); } catch (e) { reasons = []; }
  if (!Array.isArray(reasons)) reasons = [];

  var safeUrl = /^https?:\/\//i.test(url) ? url : '';
  var $ = function (id) { return document.getElementById(id); };

  $('card').className = 'card ' + kind;
  $('icon').textContent = kind === 'block' ? '🚫' : '⚠️';
  $('title').textContent = kind === 'block' ? 'Phishing page blocked' : 'This page has been reported as phishing';
  $('lead').textContent = kind === 'block'
    ? 'PhishAlert stopped this page from loading because threat intelligence confirms it is a phishing or malicious site. Do not enter passwords, card numbers or any personal details.'
    : 'This address is listed in PhishTank, but the community has not finished verifying it yet. Treat it as dangerous unless you know it is safe.';
  $('url').textContent = safeUrl || '(invalid address)';

  var ul = $('reasons');
  reasons.slice(0, 5).forEach(function (r) {
    var li = document.createElement('li');
    li.textContent = String(r).slice(0, 220);
    ul.appendChild(li);
  });
  $('fine').textContent = 'Wrongly flagged? "Continue anyway" allows this exact address for 10 minutes. You can also add the site to your whitelist in PhishAlert.';

  $('back').addEventListener('click', function () {
    chrome.tabs.update({ url: 'chrome://newtab/' }, function () { if (chrome.runtime.lastError) window.close(); });
  });

  $('proceed').addEventListener('click', function () {
    if (!safeUrl) return;
    chrome.runtime.sendMessage({ type: 'NAV_ALLOW_ONCE', url: safeUrl }, function (res) {
      if (res && res.success) location.replace(safeUrl);
    });
  });
})();
