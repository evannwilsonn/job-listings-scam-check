/*
 * LureCheck embeddable checker for a career center's own website (plan items 31, 32).
 *
 *   <div id="lurecheck"></div>
 *   <script src="https://lurecheck.com/web/embed.js" data-api="https://api.lurecheck.com" data-school="fsu"
 *           data-target="lurecheck" defer></script>
 *
 * A student pastes a message; the result is tiered by the engine's own bands:
 *   clear    -> "No known scam signs" and how to verify anyway
 *   caution  -> the specific things to check, before any link or contact
 *   review   -> "Likely a scam" plus "Already replied?" and "Report it"
 *   block    -> "Stop" plus the same two, first
 * A student can also attach a screenshot (read on the server, never stored: /analyze-image) or an offer letter PDF
 * (/analyze-offer); the result then shows the text that was read so they can check it.
 * "Already replied?" asks what happened and shows the ordered recovery steps (/recovery). "Report it" sends an
 * anonymous, masked report (/report) and shows the FTC summary to paste.
 *
 * Everything renders with textContent inside a shadow root: nothing from a message or the API is ever treated as
 * HTML, and the host page's styles can't leak in. No cookies, no storage, no tracking. The API must list this site
 * in ALLOWED_ORIGINS.
 */
(function () {
  "use strict";
  const me = document.currentScript;
  const API = ((me && me.dataset.api) || "").replace(/\/+$/, "");
  const SCHOOL = (me && me.dataset.school) || "";
  const host = document.getElementById((me && me.dataset.target) || "lurecheck");
  if (!API || !host) return;

  const TIERS = {
    clear: ["No known scam signs", "Nothing here matches a known scam pattern. That isn't a guarantee: look the employer up yourself and apply through its own website.", "#2e7d32"],
    caution: ["Be careful", "A few things are off. Check each one below with the employer, using contact details you find yourself, before you reply or click anything.", "#b26a00"],
    review: ["Likely a scam", "Several strong scam signs. Don't reply with personal information, don't click links, and don't send or accept money.", "#c62828"],
    block: ["Stop: this is a scam", "This matches patterns that only scams use. Don't respond, don't click links, and never send money, gift cards or bank details.", "#8e0000"],
  };
  const HAPPENED = [
    ["replied", "I replied or talked to them"], ["shared_personal_info", "I gave them my SSN, ID or address"],
    ["shared_bank_details", "I gave them bank or card details"], ["shared_login", "I gave them a password or code"],
    ["deposited_check", "I deposited a check they sent"], ["sent_money", "I sent them money"],
    ["gift_cards", "I bought gift cards"], ["crypto", "I sent crypto"], ["shipped_packages", "I reshipped packages"],
    ["installed_software", "I installed an app they sent"],
  ];

  const root = host.attachShadow ? host.attachShadow({mode: "open"}) : host;
  const el = (tag, props, ...kids) => {
    const n = document.createElement(tag);
    Object.assign(n, props || {});
    for (const k of kids) if (k != null) n.append(k);
    return n;
  };
  const style = el("style", {textContent: `
    :host{all:initial} .w{font:15px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#1b1b1b;max-width:640px}
    textarea,input{width:100%;box-sizing:border-box;font:inherit;padding:10px;border:1px solid #c9c9c9;border-radius:8px}
    textarea{min-height:140px} label{display:block;margin:10px 0 4px;font-weight:600}
    button{font:inherit;padding:9px 14px;border:0;border-radius:8px;background:#1f3a5f;color:#fff;cursor:pointer;margin:10px 8px 0 0}
    button.alt{background:#e9edf2;color:#1b1b1b} .tier{margin-top:16px;padding:14px;border-radius:10px;border:1.5px solid}
    h3{margin:0 0 6px;font-size:17px} ul,ol{padding-left:20px} li{margin:6px 0} .why{color:#444}
    .small{font-size:13px;color:#555} pre{white-space:pre-wrap;background:#f6f6f6;padding:10px;border-radius:8px}`});
  const text = el("textarea", {placeholder: "Paste the job posting, email or text message"});
  const sender = el("input", {placeholder: "Sender's email address (optional)"});
  const go = el("button", {textContent: "Check it"});
  const file = el("input", {type: "file", accept: "image/png,image/jpeg,image/webp,application/pdf"});
  const out = el("div");
  out.setAttribute("role", "status");
  out.setAttribute("aria-live", "polite");
  root.append(style, el("div", {className: "w"}, el("label", {textContent: "Is this job real?"}), text,
    el("label", {textContent: "Who sent it"}), sender,
    el("label", {textContent: "Or attach a screenshot or an offer letter (PDF)"}), file, go, out));

  async function post(path, body) {
    const r = await fetch(API + path, {method: "POST", headers: {"Content-Type": "application/json"},
                                        body: JSON.stringify(body)});
    if (!r.ok) {
      let say = "";
      try { say = (await r.json()).detail; } catch (_) { /* not JSON */ }
      throw Object.assign(new Error(String(r.status)), {say: typeof say === "string" && r.status < 500 || r.status === 503 ? say : ""});
    }
    return r.json();
  }

  function showFindings(findings) {
    const shown = findings.filter(f => f.weight > 0 || f.rule_id === "model_second_look").slice(0, 8);
    if (!shown.length) return null;
    return el("ul", {}, ...shown.map(f =>
      el("li", {}, el("strong", {textContent: f.title}), el("div", {className: "why", textContent: f.why}))));
  }

  function recoveryForm(box) {
    const checks = HAPPENED.map(([k, label]) =>
      el("label", {style: "font-weight:400"}, el("input", {type: "checkbox", value: k, style: "width:auto;margin-right:8px"}), label));
    const show = el("button", {textContent: "Show me what to do"});
    const steps = el("div");
    show.onclick = async () => {
      const happened = checks.map(l => l.firstChild).filter(c => c.checked).map(c => c.value);
      steps.replaceChildren(el("p", {className: "small", textContent: "Loading..."}));
      try {
        const plan = await post("/recovery", {happened});
        steps.replaceChildren(el("ol", {}, ...plan.steps.map(s =>
          el("li", {}, el("strong", {textContent: s.title}), el("div", {textContent: s.do}),
             el("div", {className: "why", textContent: s.why})))), el("p", {className: "small", textContent: plan.note}));
      } catch (e) { steps.replaceChildren(el("p", {textContent: "Couldn't load the steps. Call your bank's fraud line first."})); }
    };
    box.replaceChildren(el("h3", {textContent: "What happened so far?"}), ...checks, show, steps);
  }

  async function report(box) {
    box.replaceChildren(el("p", {className: "small", textContent: "Sending..."}));
    try {
      const r = await post("/report", {text: text.value.slice(0, 20000), sender: sender.value, school: SCHOOL});
      box.replaceChildren(
        el("h3", {textContent: r.queued ? "Thanks, a reviewer will look at it" : "Not saved, but you can still report it"}),
        el("p", {textContent: "Contact details are hidden before it's stored, and nothing about you is kept. Please also report it to the FTC; paste this:"}),
        el("pre", {textContent: r.ftc_summary}),
        el("a", {href: r.ftc_url, target: "_blank", rel: "noopener noreferrer", textContent: "Open reportfraud.ftc.gov"}));
    } catch (e) { box.replaceChildren(el("p", {textContent: "Couldn't send the report. You can still report it at reportfraud.ftc.gov."})); }
  }

  const readFile = f => new Promise((ok, bad) => {
    const rd = new FileReader();
    rd.onload = () => ok(String(rd.result).split(",", 2)[1] || "");
    rd.onerror = () => bad(rd.error);
    rd.readAsDataURL(f);
  });

  async function request() {
    const f = file.files && file.files[0];
    if (f) {
      if (f.size > 5 * 1024 * 1024) throw Object.assign(new Error("big"), {say: "That file is over 5 MB. Crop it or paste the text instead."});
      const b64 = await readFile(f);
      return f.type === "application/pdf"
        ? post("/analyze-offer", {pdf_base64: b64, sender: sender.value, school: SCHOOL})
        : post("/analyze-image", {image_base64: b64, sender: sender.value, school: SCHOOL});
    }
    if (/offer (?:letter|of employment)|pleased to offer/i.test(text.value))
      return post("/analyze-offer", {text: text.value.slice(0, 20000), sender: sender.value, school: SCHOOL});
    return post("/analyze", {description: text.value.slice(0, 20000), sender: sender.value, school: SCHOOL});
  }

  go.onclick = async () => {
    if (!text.value.trim() && !(file.files && file.files[0])) return;
    go.disabled = true;
    out.replaceChildren(el("p", {className: "small", textContent: "Checking..."}));
    try {
      const r = await request();
      const [title, advice, color] = TIERS[r.band] || TIERS.caution;
      const extra = el("div");
      const tier = el("div", {className: "tier"}, el("h3", {textContent: title}), el("p", {textContent: advice}),
        showFindings(r.findings || []));
      tier.style.borderColor = color;
      tier.firstChild.style.color = color;
      if (r.band === "review" || r.band === "block") {
        const replied = el("button", {textContent: "I already replied", className: r.band === "block" ? "" : "alt"});
        const rep = el("button", {textContent: "Report it", className: "alt"});
        replied.onclick = () => recoveryForm(extra);
        rep.onclick = () => report(extra);
        tier.append(replied, rep);
      }
      if (r.text_read) {
        if (!text.value.trim()) text.value = r.text_read;
        tier.append(el("p", {className: "small", textContent: "We read this text from your file. If it's wrong, fix it above and check again."}),
                    el("pre", {textContent: r.text_read.slice(0, 1500)}));
        file.value = "";
      }
      out.replaceChildren(tier, extra);
    } catch (e) {
      if (e.say) { out.replaceChildren(el("p", {textContent: e.say})); return; }
      out.replaceChildren(el("p", {textContent: "The checker isn't reachable right now. Until it is: never pay to get a job, never deposit a check from an employer you haven't verified, and look the company up yourself."}));
    } finally { go.disabled = false; }
  };
})();
