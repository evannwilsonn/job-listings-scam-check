/* LureCheck review pages: keyboard shortcuts for the queue and "Copy for email" on the trends report.
   Served from this site only (CSP script-src 'self'). The pages work fully without it. Keyboard actions never
   animate: reviewers press these keys all day. */
(function () {
  "use strict";
  var KEYS = { s: "scam", r: "real", a: "aggregator", n: "unclear" };

  function cards() { return Array.prototype.slice.call(document.querySelectorAll("main article.card")).filter(function (c) {
    return c.querySelector("form.decide") && !c.classList.contains("leaving"); }); }
  function current() { return document.querySelector("main article.card.kb-focus"); }
  function focusCard(c) {
    var old = current(); if (old) old.classList.remove("kb-focus");
    if (!c) return;
    c.classList.add("kb-focus");
    c.scrollIntoView({ block: "start", behavior: "auto" });
    c.setAttribute("tabindex", "-1"); c.focus({ preventScroll: true });
  }
  function move(step) {
    var list = cards(); if (!list.length) return;
    var i = list.indexOf(current());
    focusCard(list[i < 0 ? 0 : Math.max(0, Math.min(list.length - 1, i + step))]);
  }
  function typing(el) { return el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName)); }
  function help(show) {
    var h = document.getElementById("kb-help"); if (!h) return;
    h.hidden = show === undefined ? !h.hidden : !show;
  }

  document.addEventListener("keydown", function (ev) {
    if (ev.defaultPrevented || ev.metaKey || ev.ctrlKey || ev.altKey || typing(ev.target)) {
      if (ev.key === "Escape" && typing(ev.target)) ev.target.blur();
      return;
    }
    var k = ev.key.toLowerCase();
    if (k === "?" || (k === "/" && ev.shiftKey)) { help(); ev.preventDefault(); return; }
    if (k === "escape") { help(false); return; }
    if (!document.querySelector("main article.card form.decide") && k !== "u") return;
    if (k === "j") { move(1); ev.preventDefault(); return; }
    if (k === "k") { move(-1); ev.preventDefault(); return; }
    if (k === "u") { var undo = document.querySelector(".stub button"); if (undo) { undo.click(); ev.preventDefault(); } return; }
    if (k === "e") { var c0 = current() || cards()[0]; if (c0) { focusCard(c0); var note = c0.querySelector("input[name=note]"); if (note) note.focus(); ev.preventDefault(); } return; }
    if (KEYS[k]) {
      var c = current() || cards()[0]; if (!c) return;
      var b = c.querySelector('button[name=action][value="' + KEYS[k] + '"]');
      if (b) { focusCard(c); b.click(); ev.preventDefault(); }
    }
  });

  // After a decision the page comes back at the confirmation; put the keyboard on the next report.
  function afterLoad() {
    if (location.hash === "#decided") {
      var stub = document.getElementById("decided"), next = stub && stub.nextElementSibling;
      while (next && !(next.matches && next.matches("article.card"))) next = next.nextElementSibling;
      if (next) { next.classList.add("kb-focus"); next.setAttribute("tabindex", "-1"); next.focus({ preventScroll: true }); }
    }
    var hint = document.getElementById("kb-hint"); if (hint && document.querySelector("main article.card form.decide")) hint.hidden = false;
    Array.prototype.forEach.call(document.querySelectorAll("[data-copy]"), function (btn) {
      btn.hidden = false;
      btn.addEventListener("click", function () {
        var src = document.getElementById(btn.getAttribute("data-copy")); if (!src) return;
        var html = "<div style=\"font-family:Arial,sans-serif;font-size:14px;line-height:1.5\">" + src.innerHTML + "</div>";
        var text = src.innerText;
        var done = function (ok) { var t = btn.textContent; btn.textContent = ok ? "Copied" : "Select and copy the report"; setTimeout(function () { btn.textContent = t; }, 1600); };
        try {
          if (window.ClipboardItem && navigator.clipboard && navigator.clipboard.write) {
            navigator.clipboard.write([new ClipboardItem({ "text/html": new Blob([html], { type: "text/html" }),
              "text/plain": new Blob([text], { type: "text/plain" }) })]).then(function () { done(true); }, function () {
              navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); }); });
          } else if (navigator.clipboard) {
            navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); });
          } else { done(false); }
        } catch (e) { done(false); }
      });
    });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", afterLoad); else afterLoad();
})();
