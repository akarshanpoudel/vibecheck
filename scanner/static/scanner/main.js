/* scanner/static/scanner/main.js
 *
 * Two responsibilities — each activates only if its anchor element
 * exists in the DOM, so this file is safe to load on every page.
 *
 *   1. Poll the status endpoint while a scan is pending.
 *   2. Copy-to-clipboard on the share button.
 */

(function () {
  'use strict';

  // ---- 1. Pending-scan poller -----------------------------------------------

  var pending = document.getElementById('vc-pending');

  if (pending) {
    var statusUrl = pending.dataset.statusUrl;
    var delay     = 2500;

    function poll() {
      fetch(statusUrl)
        .then(function (r) { return r.json(); })
        .then(function (d) {
          if (d.status !== 'pending') {
            window.location.reload();
          } else {
            setTimeout(poll, delay);
          }
        })
        .catch(function () {
          // Back off on network errors — don't hammer a struggling server.
          setTimeout(poll, delay * 2);
        });
    }

    setTimeout(poll, delay);
  }

  // ---- 2. Copy-link button --------------------------------------------------

  var copyBtn = document.getElementById('vc-copy-link');

  if (copyBtn) {
    var original = copyBtn.textContent;

    function flash(label) {
      copyBtn.textContent = label;
      setTimeout(function () { copyBtn.textContent = original; }, 2000);
    }

    // textarea fallback for browsers without the Clipboard API
    function legacyCopy(text) {
      var ta          = document.createElement('textarea');
      ta.value        = text;
      ta.style.cssText = 'position:fixed;top:0;left:0;opacity:0;pointer-events:none';
      document.body.appendChild(ta);
      ta.focus();
      ta.select();
      try   { document.execCommand('copy'); flash('Copied!'); }
      catch (e) { flash('Failed'); }
      document.body.removeChild(ta);
    }

    copyBtn.addEventListener('click', function () {
      var url = window.location.href;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(url)
          .then(function ()  { flash('Copied!'); })
          .catch(function () { legacyCopy(url); });
      } else {
        legacyCopy(url);
      }
    });
  }

})();