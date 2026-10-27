// The extension's checker: the same rules and engine as the LureCheck page, run locally. Everything is rendered
// with textContent, so nothing from a checked message is ever treated as HTML.
"use strict";
(function () {
  const $ = id => document.getElementById(id);
  const COLORS = ["#2e7d32", "#b26a00", "#c62828", "#8e0000"];
  const STEPS = [
    ["Look the company up yourself and confirm the job is on its own careers page.", "Never pay for training, equipment or a background check."],
    ["Don't click links or open attachments yet.", "Find the organization's contact details yourself and ask whether the message is real.", "Don't share your SSN, ID or bank details."],
    ["Don't reply with personal information, and don't click the links.", "Block the sender and report it to the site it came from."],
    ["Stop replying. Don't send money, gift cards, crypto or bank details, and don't deposit any check they send.", "If you already shared bank details or deposited a check, call your bank now.", "Report it at reportfraud.ftc.gov."],
  ];
  const el = (tag, text, cls) => { const n = document.createElement(tag); if (text) n.textContent = text; if (cls) n.className = cls; return n; };

  function run() {
    const text = $("text").value.trim();
    if (!text) return;
    const r = window.LureCheck.check(text, $("sender").value);
    const box = el("div", "", "tier");
    box.style.borderColor = COLORS[r.level] || COLORS[1];
    box.append(el("h2", r.title), el("p", r.advice));
    for (const f of r.findings.slice(0, 8)) {
      const d = el("div", "", "f");
      d.append(el("b", f.title), el("span", f.why, "why"));
      box.append(d);
    }
    const ol = el("ol");
    for (const s of STEPS[r.level] || STEPS[1]) ol.append(el("li", s));
    box.append(el("b", "What to do"), ol);
    $("result").replaceChildren(box);
  }

  $("go").addEventListener("click", run);
  $("ver").textContent = "Rules " + window.LureCheck.ruleset + ".";
  chrome.storage.session.get("pending").then(({pending}) => {
    if (!pending) return;
    chrome.storage.session.remove("pending");
    $("text").value = pending;
    run();
  });
})();
