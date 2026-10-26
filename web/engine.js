/*
 * Job-scam detector: browser port of the Python engine (scam_detector/rules.py, scorer.py, leadgen.py,
 * enrichment/compensation.py, enrichment/url_flow.py).
 *
 * This file is the single JS implementation. It is inlined into index.html by tools/build_web.py and
 * loaded in Node by web/parity_runner.js, so the same code that runs in the browser is what the
 * parity gate (tools/parity.py) checks against the Python engine. Never edit the copy in index.html.
 *
 * The rules are data: createEngine(rulepack) takes the parsed scam_detector/rulepack/core.json.
 * Message-mode checks (senderFindings, linkFindings) have no Python twin yet and are browser-only.
 */
function createEngine(RULEPACK) {
  "use strict";

  // ---------------- helpers ----------------
  const reEsc = s => s.replace(/[.*+?^${}()|[\]\\\/\-#&~]/g, "\\$&");
  function allMatches(rx, text) {
    const out = []; rx.lastIndex = 0; let m;
    while ((m = rx.exec(text)) !== null) { out.push(m); if (m[0] === "") rx.lastIndex++; }
    return out;
  }
  const fmt0 = n => Math.round(n).toLocaleString("en-US");
  const fmtG = n => String(Number(n.toPrecision(6)));
  const title = s => s.replace(/\b[a-z]/g, c => c.toUpperCase());

  // ---------------- normalization (rules.py) ----------------
  const ZERO_WIDTH = /[​‌‍⁠﻿­]/g;
  const HOMO = {"а":"a","е":"e","о":"o","р":"p","с":"c","у":"y","х":"x","і":"i","ѕ":"s","ο":"o","α":"a","ρ":"p","’":"'","‘":"'","“":'"',"”":'"'};
  const HOMO_RX = new RegExp("[" + Object.keys(HOMO).join("") + "]", "g");
  const SPACED = /(?<![a-z0-9])(?:[a-z][ .\-_*]){4,}[a-z](?![a-z0-9])/gi;
  const LEET = /(?<=[a-z])[@$0134](?=[a-z])/gi;
  const LEET_MAP = {"@":"a","$":"s","0":"o","1":"i","3":"e","4":"a"};
  const MAX_TEXT = 20000;
  // Scammer respellings folded to the plain word before any rule runs (mirror of rules._ALIASES).
  const ALIASES = [
    [/\bcheques?\b/gi, "check"],
    [/\b(?:payment|funds?)\s+(?:document|instrument)s?\b/gi, "check"],
    [/\bwhats[\s\-]+app\b|\bthe\s+green\s+(?:chat\s+)?app\b/gi, "whatsapp"],
    [/\btele[\s\-]+gram\b|\bt-gram\b|\bthe\s+blue\s+(?:chat\s+)?app\b/gi, "telegram"],
    [/\bz-?pay\b|\bbank\s+app\s+transfer\b/gi, "zelle"],
    [/\b(?:reward|e-?gift)\s+cards?\b|\bstore\s+vouchers?\b/gi, "gift card"],
    [/\bmobile-load\b|\bcash\s+in\b(?=\s+(?:the|this|it|your|a)\b)/gi, "deposit"],
    [/\bdigital\s+coins?\b/gi, "bitcoin"],
  ];
  function normalize(text) {
    text = (text || "").normalize("NFKC").replace(ZERO_WIDTH, "").replace(HOMO_RX, c => HOMO[c]);
    text = text.replace(SPACED, m => m.replace(/[ .\-_*]/g, ""));
    text = text.replace(LEET, m => LEET_MAP[m]);
    for (const [rx, plain] of ALIASES) text = text.replace(rx, plain);
    return text.slice(0, MAX_TEXT);
  }

  // ---------------- guards ----------------
  const NEGATORS = /\b(?:no|never|not|without|zero|nor|neither|free of|isn't|aren't|doesn't|won't|don't|do not|does not|will not|cannot|can't)\b/gi;
  const REQUIRE = /\b(?:must|need to|needs to|have to|required to|you will pay|you pay)\b/i;
  const AFTER = /\b(?:at no (?:cost|charge)|no cost|free of charge|for free|is free|are free|free to you|covered by|paid for by|paid by|we (?:pay|cover)|is waived|are waived)\b/i;
  const POST_HIRE = /\b(?:upon\s+(?:hire|being hired|acceptance|offer)|after\s+(?:you(?:'re| are)\s+|being\s+|an?\s+|your\s+|the\s+)?(?:hired|hire|offer|accepted|acceptance|background check|first)|once\s+(?:you(?:'re| are)\s+)?(?:hired|accepted)|once\s+your\s+background|for\s+(?:payroll|i-?9|tax|w-?4)|i-?9|w-?4|new hires?)\b/i;
  const SENT_BREAK = /[.;:!?\n]/;
  function sentenceBefore(text, start) {
    const parts = text.slice(Math.max(0, start - 160), start).split(SENT_BREAK);
    return parts[parts.length - 1];
  }
  function sentenceAfter(text, end) {
    const seg = text.slice(end, end + 120); const m = SENT_BREAK.exec(seg);
    return m ? seg.slice(0, m.index) : seg;
  }
  // Each guard returns the words that rule a match out ("never", "upon hire"), or "" when nothing does.
  function negated(text, m) {
    const before = sentenceBefore(text, m.index).split(/\s+/).filter(Boolean).slice(-14).join(" ");
    let neg = null; for (const n of allMatches(NEGATORS, before)) neg = n;
    if (neg && !REQUIRE.test(before.slice(neg.index + neg[0].length))) return neg[0];
    const a = AFTER.exec(sentenceAfter(text, m.index + m[0].length));
    return a ? a[0] : "";
  }
  function postHire(text, m) {
    const h = POST_HIRE.exec(text.slice(Math.max(0, m.index - 120), m.index + m[0].length + 120));
    return h ? h[0] : "";
  }
  const DISCLAIMER = /\b(?:at\s+no\s+time|will\s+never|would\s+never|we\s+never|never\s+(?:ask|request|contact|move)|will\s+not\s+ever|won't\s+ever)\b/i;
  const disclaimer = (text, m) => { const h = DISCLAIMER.exec(sentenceBefore(text, m.index)); return h ? h[0] : ""; };
  // On-site seasonal or live-in work (camps, AmeriCorps, room and board) pays weekly stipends; a remote mention cancels it.
  const LIVE_IN = /\b(?:room\s*(?:and|&)\s*board|(?:free|provided|included|on-?site|staff)\s+(?:housing|lodging|meals)|(?:housing|lodging|meals)\s+(?:is\s+|are\s+)?(?:provided|included|available|on-?site)|(?:summer|day|overnight|residential|sleepaway)\s+camps?|campers?|americorps)\b/i;
  const REMOTE = /\b(?:remote(?:ly)?|work(?:ing)?\s+from\s+home|wfh|from\s+anywhere|online|virtual(?:ly)?|telecommut\w*)\b/i;
  const liveIn = (text, m) => { if (REMOTE.test(text)) return ""; const h = LIVE_IN.exec(text); return h ? h[0] : ""; };
  const GUARDS = {negation: negated, post_hire: postHire, disclaimer, live_in: liveIn};

  // ---------------- rulepack ----------------
  const RULES = RULEPACK.rules.filter(r => (r.status || "active") === "active").map(r => ({
    id: r.id, severity: r.severity, weight: r.weight, title: r.title, why: r.why,
    guards: r.guards || [], min: Math.max(1, r.min_matches || 1), bonus: r.bonus == null ? 3 : r.bonus,
    rx: (r.phrases || []).map(p => new RegExp("\\b" + reEsc(p.toLowerCase()).replace(/ /g, "\\s+") + "\\b", "gi"))
      .concat((r.patterns || []).map(p => new RegExp(p, "gi"))),
  }));

  function runTextRules(text) {
    text = normalize(text);
    const out = [];
    for (const rule of RULES) {
      const seen = new Map();
      for (const rx of rule.rx) for (const m of allMatches(rx, text)) {
        if (rule.guards.some(g => GUARDS[g](text, m))) continue;
        const key = m[0].toLowerCase().replace(/\s+/g, " ").trim();
        if (!seen.has(key)) seen.set(key, key);
      }
      if (seen.size >= rule.min) {
        const weight = rule.weight + Math.min(2 * rule.bonus, rule.bonus * (seen.size - 1));
        const shown = [...seen.keys()].sort().slice(0, 5).map(s => s.slice(0, 90));
        out.push(F(rule.id, rule.severity, weight, rule.title, rule.why, shown));
      }
    }
    return out;
  }
  function F(rule_id, severity, weight, title, why, matched) { return {rule_id, severity, weight, title, why, matched: matched || []}; }

  // ---------------- implied hourly pay ----------------
  const PAY = /\$\s?([\d,]+(?:\.\d+)?)\s*(?:(?:per|a|each|\/)\s*)?(week|weekly|day|daily)\b/i;
  const HOURS_DAYS = /(\d+(?:\.\d+)?)\s*(?:-|to)\s*(\d+(?:\.\d+)?)\s*hrs?\.?\s*(\d+)\s*days?\s*(?:a|per)\s*week/i;
  const HOURS = /(\d+(?:\.\d+)?)\s*(?:-|to)\s*(\d+(?:\.\d+)?)\s*(?:hrs?|hours?)\s*(?:(?:per|a|\/|each)\s*)?(week|weekly|day|daily)?/i;
  function impliedHourly(text) {
    text = normalize(text);
    const pay = PAY.exec(text); if (!pay) return null;
    const amount = parseFloat(pay[1].replace(/,/g, ""));
    const perWeek = amount * (pay[2].toLowerCase().startsWith("d") ? 5 : 1);
    let hours = null, m = HOURS_DAYS.exec(text);
    if (m) hours = parseFloat(m[2]) * parseFloat(m[3]);
    else { m = HOURS.exec(text); if (m) { const u = (m[3] || "").toLowerCase();
      // "8-9 hours" with no unit is a workday, not a week; short unitless ranges ("1-2 hours") stay ambiguous
      const perDay = u.startsWith("d") || (!u && parseFloat(m[2]) >= 6); hours = parseFloat(m[2]) * (perDay ? 5 : 1); } }
    if (!hours || hours <= 0) return null;
    const rate = perWeek / hours; if (rate < 60) return null;
    const p = pay[0].trim();
    return F("implied_hourly", "warning", 18, "The pay works out to far above market",
      `${p} for at most about ${fmtG(hours)} hours a week is roughly $${fmt0(rate)}/hour. Real employers do not pay this for casual, no-experience work.`,
      [`${p} / about ${fmtG(hours)} hrs per week`]);
  }

  // ---------------- compensation vs national medians ----------------
  const BLS = {
    data_entry: ["Data Entry Keyers", 37790, ["data entry", "data-entry", "data processor", "typing", "keyer"]],
    admin_assistant: ["Secretaries & Administrative Assistants", 46010, ["administrative assistant", "admin assistant", "secretary", "office assistant", "administrative support", "clerical"]],
    customer_service: ["Customer Service Representatives", 39680, ["customer service", "customer support", "call center", "customer care", "support representative"]],
    shipping_receiving: ["Shipping, Receiving & Inventory Clerks", 40260, ["shipping", "receiving", "warehouse clerk", "package handler", "reshipping", "shipping coordinator", "logistics coordinator"]],
    personal_assistant: ["Personal & Executive Assistants", 46010, ["personal assistant", "executive assistant", "virtual assistant"]],
    bookkeeper: ["Bookkeeping & Accounting Clerks", 47440, ["bookkeeper", "bookkeeping", "accounting clerk", "accounts payable", "accounts receivable", "payment processor", "payment processing"]],
    receptionist: ["Receptionists", 35840, ["receptionist", "front desk"]],
    general_office: ["General Office Clerks", 40480, ["office clerk", "general office", "remote assistant", "work from home assistant", "remote worker"]],
    sales_rep: ["Sales Representatives (non-technical)", 63230, ["sales representative", "sales rep", "account executive", "inside sales"]],
    software_dev: ["Software Developers", 132270, ["software engineer", "software developer", "developer", "programmer", "full stack", "backend engineer", "frontend engineer"]],
    data_analyst: ["Data / Operations Analysts", 83640, ["data analyst", "business analyst", "operations analyst"]],
  };
  const PAYPAT = /\$\s?([\d,]+(?:\.\d+)?)\s*(?:-|–|to|\+)?\s*(?:\$?\s?([\d,]+(?:\.\d+)?))?\s*(?:\/|per|an?\s)?\s*(hour|hr|day|week|month|year|annum|yr)/gi;
  function compensation(ttl, desc) {
    const text = `${ttl}\n${desc}`; const pays = [];
    for (const m of allMatches(PAYPAT, text)) {
      const hi = parseFloat((m[2] || m[1]).replace(/,/g, "")); const u = m[3].toLowerCase();
      pays.push(u === "hour" || u === "hr" ? hi * 2080 : u === "day" ? hi * 260 : u === "week" ? hi * 52 : u === "month" ? hi * 12 : hi);
    }
    if (!pays.length) return null;
    const adv = Math.max(...pays); const hay = `${ttl} ${desc}`.toLowerCase();
    let best = null, bestLen = 0;
    for (const k in BLS) for (const kw of BLS[k][2]) if (hay.includes(kw) && kw.length > bestLen) { best = BLS[k]; bestLen = kw.length; }
    if (!best) return null;
    const ratio = adv / best[1];
    if (ratio < 1.8) return null;
    const detail = `advertised ~$${fmt0(adv)}/yr is ${ratio.toFixed(1)}x the national median of $${fmt0(best[1])} for ${best[0]}`;
    return F("pay_anomaly", "warning", 17, "The stated pay is out of band", detail + ". Figures far above market for the described work are the hook.", [detail]);
  }

  // The same check as a status for the security report's Pay tile (scam_detector/enrichment/compensation.py's result):
  // {status: no_pay_found | title_unmapped | within_range | flagged, ratio_to_median}.
  function compensationInfo(ttl, desc) {
    const text = `${ttl}\n${desc}`; const pays = [];
    for (const m of allMatches(PAYPAT, text)) {
      const hi = parseFloat((m[2] || m[1]).replace(/,/g, "")); const u = m[3].toLowerCase();
      pays.push(u === "hour" || u === "hr" ? hi * 2080 : u === "day" ? hi * 260 : u === "week" ? hi * 52 : u === "month" ? hi * 12 : hi);
    }
    if (!pays.length) return {status: "no_pay_found", ratio_to_median: null};
    const adv = Math.max(...pays); const hay = `${ttl} ${desc}`.toLowerCase();
    let best = null, bestLen = 0;
    for (const k in BLS) for (const kw of BLS[k][2]) if (hay.includes(kw) && kw.length > bestLen) { best = BLS[k]; bestLen = kw.length; }
    if (!best) return {status: "title_unmapped", ratio_to_median: null};
    const ratio = Math.round(adv / best[1] * 100) / 100;
    return {status: ratio >= 1.8 ? "flagged" : "within_range", ratio_to_median: ratio};
  }

  // ---------------- email domains ----------------
  const FREE_MAIL = new Set(["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com", "protonmail.com", "proton.me", "mail.com", "yandex.com", "gmx.com", "icloud.com", "live.com", "msn.com"]);
  function emailDomains(text, company) {
    const ds = new Set((text.match(/[\w.+-]+@[\w-]+\.[\w.-]+/gi) || []).map(e => e.split("@")[1].toLowerCase().replace(/[.,;:]+$/, "")));
    const free = [...ds].filter(d => FREE_MAIL.has(d)).sort();
    if (free.length && company.trim())
      return [F("personal_email", "warning", 18, "Recruiter writing from a personal address",
        `Corporate hiring comes from the company's own domain. Nothing here comes from a ${company.trim()} address.`, free.map(d => "@" + d))];
    return [];
  }

  // ---------------- apply-link structure ----------------
  const NEUTRAL = ["linkedin.com", "indeed.com", "glassdoor.com", "ziprecruiter.com", "greenhouse.io", "lever.co", "workday.com", "myworkdayjobs.com", "smartrecruiters.com", "jobs.polymer.co", "polymer.co", "ashbyhq.com", "icims.com", "taleo.net", "bamboohr.com", "careers-page.com"];
  const TRACKING = new Set(["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_category", "cpc", "affiliate", "extra_id_consumer_run", "extra_prev_uid", "extrlint"]);
  const URL_SPECS = {
    redirect_hop: ["note", 6, "The apply link passes through a redirect/tracking hop", "A redirect before the real listing is common for legitimate aggregators too, but it's worth knowing you're not going straight to the employer."],
    tracking_params: ["note", 5, "The apply link carries campaign tracking parameters", "UTM and similar tags mean this link is part of a marketing/affiliate campaign, not a direct posting from the employer."],
    paid_click: ["warning", 14, "The apply link is paid-per-click traffic", "A cost-per-click parameter means someone gets paid each time this link is clicked, regardless of whether you're hired -- that's an ad, not a job posting."],
    signup_wall: ["warning", 15, "An account signup is forced before you can see the listing", "Legitimate job boards let you see the posting before asking you to create an account. A forced signup wall exists to harvest your email and profile."],
    domain_mismatch: ["warning", 16, "The apply link doesn't lead to the claimed employer", "The application ultimately goes to a domain unrelated to the company the listing named, and it isn't a recognized job platform -- a sign you're dealing with a reposting or aggregator, not the employer directly."],
  };
  function splitUrl(url) {
    const m = /^[a-z][a-z0-9+.\-]*:\/\/([^/?#]*)([^?#]*)(?:\?([^#]*))?/i.exec(url || "");
    if (!m) return {host: "", path: "", params: new Set()};
    let host = m[1].toLowerCase(); if (host.startsWith("www.")) host = host.slice(4);
    const params = new Set((m[3] || "").split(/[&;]/).map(kv => kv.split("=")).filter(kv => kv[0] && kv.length > 1 && kv[1] !== "").map(kv => decodeURIComponent(kv[0]).toLowerCase()));
    return {host, path: (m[2] || "").toLowerCase(), params};
  }
  function urlChain(urls, company) {
    if (!urls || !urls.length) return [];
    const hits = {};
    const add = (k, d) => (hits[k] = hits[k] || []).push(d);
    for (const url of urls) {
      const {host, path, params} = splitUrl(url);
      if (["/away/", "/out/", "/click/", "/redirect/", "/go/"].some(x => path.includes(x))) add("redirect_hop", `${host}${path} is a redirect/tracking hop`);
      const tracked = [...params].filter(p => TRACKING.has(p)).sort();
      if (tracked.length) add("tracking_params", `${host} URL carries tracking params: ${tracked.join(", ")}`);
      if (params.has("cpc") || url.toLowerCase().includes("cpc")) add("paid_click", `${host} URL contains a cost-per-click parameter -- paid traffic arbitrage`);
      if (["/register", "/signup", "/sign-up", "/apply-with-ai", "/start_google_auth"].some(x => path.includes(x))) add("signup_wall", `${host}${path} forces account creation before showing the listing`);
    }
    const fin = splitUrl(urls[urls.length - 1]).host;
    if (urls.length === 1 && company.trim() && fin && !NEUTRAL.some(p => fin.endsWith(p))) {
      const ck = company.toLowerCase().replace(/[^a-z]/g, ""), dk = fin.split(".")[0].replace(/[^a-z]/g, "");
      if (ck.length > 3 && !(dk.includes(ck.slice(0, 6)) || ck.includes(dk.slice(0, 6))))
        add("domain_mismatch", `Final application domain (${fin}) doesn't match the claimed employer name (${company.trim()}) and isn't a known job platform`);
    }
    return Object.keys(hits).map(k => F("url_" + k, URL_SPECS[k][0], URL_SPECS[k][1], URL_SPECS[k][2], URL_SPECS[k][3], hits[k].slice(0, 3)));
  }

  // ---------------- lead-generation axis ----------------
  const URL_POINTS = {url_signup_wall: [4, "The apply link forces an account signup"], url_paid_click: [4, "The apply link is paid-per-click traffic"],
    url_tracking_params: [2, "The apply link carries campaign tracking parameters"], url_redirect_hop: [2, "The apply link passes through a redirect hop"],
    url_domain_mismatch: [3, "The apply link doesn't lead to the named employer"]};
  const LG_TEXT = [
    [/\b(?:we are|is|are)\s+not\s+the\s+employer(?:\s+of\s+record)?\b|\baggregat(?:or|ed)\b|\bcross-?posted\b/i, 3, "The listing describes itself as an aggregator"],
    [/\ba\s+(?:remote\s+|growing\s+|leading\s+)?(?:company|firm|organization|business)\s+(?:is\s+)?(?:seeking|looking|hiring)\b|\bour\s+clients?\b|\b(?:confidential|undisclosed)\s+(?:employer|company|client)\b/i, 2, "The employer is described but not named"],
    [/\bregardless\s+of\s+(?:your\s+)?experience\b/i, 1, "Generic 'regardless of experience' boilerplate"],
    [/\btaking\s+a\s+(?:minute|moment)\s+to\s+(?:fill\s+out|complete|finish)\s+our\s+(?:online\s+)?application\b/i, 4, "Boilerplate 'start a career, fill out our application' pitch with no real role"],
    [/\b(?:research|market\s+research|focus\s+group|survey)\s+panel(?:ist)?s?\b|\bpaid\s+(?:focus\s+groups?|surveys?|research\s+studies)\b|\btake\s+(?:paid\s+)?surveys?\b|\bfocus\s+group\s+(?:participants?|studies)\b/i, 4, "A survey or focus-group panel signup dressed up as a job"],
    [/\byou\s+will\s+receive\s+an\s+email\s+within\b|\bcheck\s+your\s+(?:inbox|email)\s+or\s+spam\b/i, 4, "An automated funnel that emails you right after you apply"],
    [/\bnot\s+a\s+salaried\s+job\b|\b(?:independent\s+)?(?:business|income)\s+opportunity\b|\bearnings\s+depend\s+on\s+your\b/i, 4, "An income or referral 'opportunity', not a job with an employer"],
    [/\bcreate\s+(?:your\s+)?(?:a\s+)?free\s+account\b|\bsign\s+up\s+(?:for\s+)?free\b/i, 2, "Asks you to create an account on a third-party site"],
    [/\bljbffr\b/i, 3, "Carries a scraped job ID from a reposting network"],
    [/\b(?:recruiting|hiring|sourcing\s+candidates)\s+(?:for|on\s+behalf\s+of)\s+(?:one\s+of\s+)?(?:our|a|an)\s+clients?\b|\babout\s+our\s+client\s*:/i, 6, "A staffing firm or reposter hiring for a client it never names"],
    [/\b(?:income|performance)[- ]based\s+(?:income|earnings?|earning\s+potential)\b|\bincome[- ]earning\s+potential\b/i, 4, "Pay is 'earning potential' instead of a wage"],
    [/\bbuild\s+(?:something\s+of\s+your\s+own|an?\s+income\s+from\s+home|your\s+own\s+business)\b|\bbe\s+your\s+own\s+boss\b/i, 2, "Pitched as building your own business, not a job"],
    [/\bbegin\s+a\s+long[- ]lasting\s+(?:career|profession)\s+with\s+(?:limitless|unlimited)\s+opportunit/i, 3, "Funnel boilerplate: 'begin a long-lasting career with limitless opportunity'"],
  ];
  const LG_VERDICT = "This looks like an aggregator or lead-generation listing: the link goes through a middleman, not the employer. It may collect your email and profile. Find the employer's own posting before you apply.";
  function leadGen(text, urlFindings) {
    let points = 0; const reasons = [];
    for (const f of urlFindings) { const s = URL_POINTS[f.rule_id]; if (s) { points += s[0]; reasons.push({source: "link", points: s[0], reason: s[1], matched: f.matched.slice(0, 2)}); } }
    const norm = normalize(text);
    for (const [rx, pts, reason] of LG_TEXT) { const m = rx.exec(norm); if (m) { points += pts; reasons.push({source: "text", points: pts, reason, matched: [m[0].slice(0, 80)]}); } }
    const flag = points >= 6;
    return {flag, level: points >= 8 ? "likely" : flag ? "possible" : null, points, reasons, verdict: flag ? LG_VERDICT : ""};
  }

  // ---------------- the scorer ----------------
  const SEV = {critical: 0, warning: 1, note: 2};
  const bySeverity = (a, b) => SEV[a.severity] - SEV[b.severity] || b.weight - a.weight;
  function band(score, critical) { return critical || score >= 65 ? "block" : score >= 35 ? "review" : score >= 15 ? "caution" : "clear"; }
  function scorePosting(ttl, description, company, urlChainList) {
    company = company || "";
    const full = `${ttl}\n${description}`;
    let findings = runTextRules(full);
    const h = impliedHourly(full); if (h) findings.push(h);
    findings = findings.concat(emailDomains(full, company));
    const c = compensation(ttl, description); if (c) findings.push(c);
    const fired = new Set(findings.map(f => f.rule_id));
    if (["banking_pii", "mule_recruitment", "off_platform"].filter(x => fired.has(x)).length >= 2)
      findings.push(F("mule_combo", "critical", 28, "Combined pattern: recruitment + banking/ID + off-platform",
        "This message combines a recruitment pitch, a request for banking or identity details, and a push to an outside app. Together these are the money-mule hiring scam - walk away.",
        ["multiple money-mule signals present together"]));
    const lead_gen = leadGen(full, urlChain(urlChainList || [], company));
    findings.sort(bySeverity);
    const score = Math.min(100, findings.reduce((s, f) => s + f.weight, 0));
    return {score, band: band(score, findings.some(f => f.severity === "critical")), findings, lead_gen, ruleset: RULEPACK.version};
  }

  // ---------------- "Is this a scam?" (msgcheck.py) ----------------
  const LEVELS = [
    ["ok", "No known scam signs", "Nothing here matches a known scam pattern. That isn't a guarantee: confirm the employer through their own website or the FSU Career Center before sharing personal details."],
    ["caution", "Be careful", "A few things are off. Verify the sender through an official channel you find yourself before you reply or click anything."],
    ["warn", "Likely a scam", "Several strong scam signals. Don't reply with personal information, don't click links, and don't send or accept money."],
    ["bad", "Scam. Stop here.", "This matches patterns that only scams use. Don't respond, don't click links, and never send money, gift cards, or bank details."],
  ];
  const BAND_LEVEL = {clear: 0, caution: 1, review: 2, block: 3};
  const SHORT = new Set(["bit.ly", "tinyurl.com", "t.co", "rb.gy", "cutt.ly", "shorturl.at", "is.gd", "ow.ly", "buff.ly", "tiny.cc", "rebrand.ly", "s.id", "t.ly", "lnkd.in", "shorturl.com", "bl.ink", "short.io"]);
  const CHAT = new Set(["wa.me", "chat.whatsapp.com", "t.me", "telegram.me", "signal.me", "m.me", "discord.gg"]);
  const FORMS = new Set(["forms.gle", "docs.google.com", "forms.office.com", "jotform.com", "typeform.com"]);
  const CLAIMS_SCHOOL = /\b(?:professor|prof\.|dr\.|department|dept\.?|university|career (?:center|services)|fsu|florida state|financial aid|registrar|dean|faculty|student employment)\b/i;
  const CLAIMS_COMPANY = /\b(?:hr|human resources|recruit(?:er|ing|ment)|talent acquisition|hiring manager|onboarding)\b/i;
  const URL_RX = /(?:https?:\/\/|www\.)[^\s<>"')\]]+/gi;
  const EMAIL_RX = /[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/gi;
  const isFsu = d => { d = d.toLowerCase().replace(/\.$/, ""); return d === "fsu.edu" || d.endsWith(".fsu.edu"); };
  const looksFsu = d => { d = d.toLowerCase().replace(/\.$/, ""); if (isFsu(d)) return false; const f = d.replace(/[^a-z0-9]/g, ""); return f.includes("fsu") || f.includes("floridastate") || f.includes("seminole"); };
  function senderFindings(sender, text) {
    const out = []; sender = (sender || "").trim();
    const domains = new Set(allMatches(EMAIL_RX, sender + " " + text).map(m => m[1].toLowerCase()));
    const sm = new RegExp(EMAIL_RX.source, "i").exec(sender); const sd = sm ? sm[1].toLowerCase() : "";
    for (const d of [...domains].sort()) if (looksFsu(d))
      out.push(F("fsu_lookalike", "critical", 40, "An address pretends to be FSU", `${d} is not an FSU address. Real FSU email ends in exactly @fsu.edu (or a department subdomain like @cs.fsu.edu). Look-alike domains are a classic phishing move.`, ["@" + d]));
    if (FREE_MAIL.has(sd)) {
      const claim = CLAIMS_SCHOOL.exec(text + " " + sender) || CLAIMS_COMPANY.exec(text + " " + sender);
      if (claim) out.push(F("personal_sender", "warning", 18, "Official-sounding message from a personal account", `It claims to be a ${claim[0].toLowerCase()} but was sent from ${sd}. Universities and real companies write from their own domain.`, ["@" + sd]));
    }
    if (sender && /\b(?:fsu|florida state|career center)\b/i.test(sender) && sd && !isFsu(sd))
      out.push(F("display_spoof", "warning", 20, "The sender name says FSU but the address doesn't", `The name shown mentions FSU, but the address is at ${sd}.`, [sender.slice(0, 80)]));
    return out;
  }
  function linkFindings(text) {
    const out = [], seen = new Set();
    for (const m of allMatches(URL_RX, text || "")) {
      const raw = m[0]; const url = raw.toLowerCase().startsWith("http") ? raw : "http://" + raw;
      let host = (/^https?:\/\/(?:[^@\/?#]*@)?(\[[^\]]*\]|[^:\/?#]*)/i.exec(url) || [,""])[1].toLowerCase();
      if (host.startsWith("www.")) host = host.slice(4);
      if (!host || seen.has(host)) continue; seen.add(host);
      const ev = [raw.slice(0, 80)];
      if (SHORT.has(host)) out.push(F("short_link", "warning", 14, "A shortened link hides where it goes", `${host} links hide the real destination. Don't open it; ask for the company's own site instead.`, ev));
      else if (CHAT.has(host)) out.push(F("chat_link", "warning", 18, "Pushes you to a chat app", "Moving a 'job' to WhatsApp, Telegram or Signal is how scammers avoid the platforms that screen them.", ev));
      else if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) out.push(F("ip_link", "critical", 34, "A link to a bare IP address", "Real employers don't send links to raw number addresses.", ev));
      else if (looksFsu(host)) out.push(F("fsu_lookalike_link", "critical", 40, "A link pretends to be FSU", `${host} is not an FSU website. FSU sites end in fsu.edu.`, ev));
      else if (FORMS.has(host) || host.endsWith(".jotform.com")) out.push(F("form_link", "note", 8, "Asks you to fill in an outside form", "Forms are fine for events, but a 'job' that starts with a form asking for your details is a common data-harvesting step.", ev));
    }
    return out;
  }
  // ---------------- what cleared a would-be flag (shown in green, never as "safe") ----------------
  const GUARD_REASONS = {
    negation: "It's mentioned only to say it won't happen, so it wasn't counted.",
    post_hire: "It only comes up after you're hired, which is normal for payroll and tax forms, so it wasn't counted.",
    disclaimer: "It's part of a safety warning or the employer's own promise, so it wasn't counted.",
    live_in: "It's a stipend for an on-site seasonal or live-in job, where weekly stipends are normal, so it wasn't counted.",
  };
  const SENSITIVE = /\b(?:bank|banking|routing|account\s+number|log-?in|password|ssn|social\s+security|driver'?s?\s+licen[sc]e|passport|photo\s+id|id\s+card|gift\s*cards?|zelle|cash\s?app|venmo|paypal|western\s+union|moneygram|wire|bitcoin|btc|crypto\w*|usdt|telegram|whats\s?app|signal)\b|\$\s?\d/i;
  const WEAK_NEG = new Set(["not", "no", "nor", "without", "zero", "neither", "nothing"]);
  const ASK_VERB = /\b(?:pay|send|transfer|wire|buy|purchase|deposit|reply\s+with|text\s+(?:me|us)|upload|share)\b/i;
  const NEG_STRONG = /\b(?:never|will\s+not|won't|do\s+not|don't|does\s+not|doesn't|cannot|can't|at\s+no\s+time)\b/i;
  function cueAt(text, cue, m) {
    const low = text.toLowerCase(), c = cue.toLowerCase(), end = m.index + m[0].length;
    let i = low.lastIndexOf(c, m.index + m[0].length - c.length);
    if (i >= Math.max(0, m.index - 160)) return SENT_BREAK.test(text.slice(i + c.length, m.index)) ? -1 : i;
    i = low.indexOf(c, m.index);
    return i >= 0 && i <= end + 160 && !SENT_BREAK.test(text.slice(end, i)) ? i : -1;
  }
  function clauseAround(text, a, b) {
    let lo = a; while (lo > 0 && !/[.;!?\n]/.test(text[lo - 1]) && a - lo < 120) lo--;
    let hi = b; while (hi < text.length && !/[.;!?\n]/.test(text[hi]) && hi - b < 80) hi++;
    return text.slice(lo, hi).replace(/\s+/g, " ").replace(/^[\s,-]+|[\s,-]+$/g, "");
  }
  function showAsCleared(clause, cue, guard) {
    const cl = clause.toLowerCase(), cu = cue.toLowerCase().trim();
    if (!cu || !cl.includes(cu)) return false;
    if (SENSITIVE.test(clause) && (guard === "disclaimer" || WEAK_NEG.has(cu))) return false;
    const after = clause.slice(cl.indexOf(cu) + cu.length);
    if (ASK_VERB.test(after) && SENSITIVE.test(after)) return false;
    if (guard === "negation" && cl.indexOf(cu) > 0 && ASK_VERB.test(after) && !NEG_STRONG.test(cu)) return false;
    return true;
  }
  function clearedMatches(text, findings) {
    text = normalize(text);
    const fired = new Set(findings.map(f => f.rule_id));
    const evidence = findings.flatMap(f => f.matched || []).filter(e => e.length >= 4).map(e => e.toLowerCase());
    const out = [], seen = new Set();
    for (const rule of RULES) {
      if (fired.has(rule.id)) continue;
      for (const rx of rule.rx) for (const m of allMatches(rx, text)) {
        for (const g of rule.guards) {
          const cue = GUARDS[g](text, m);
          if (!cue) continue;
          const ci = cueAt(text, cue, m);
          if (ci >= 0) {
            const clause = clauseAround(text, Math.min(ci, m.index), Math.max(ci + cue.length, m.index + m[0].length));
            const key = clause.toLowerCase();
            if (!seen.has(key) && showAsCleared(clause, cue, g) && !evidence.some(e => key.includes(e) || e.includes(key))) {
              seen.add(key);
              out.push({rule_id: rule.id, title: rule.title, guard: g, cue, clause: clause.slice(0, 200), why: GUARD_REASONS[g]});
            }
          }
          break;
        }
        if (out.length >= 6) return out;
      }
    }
    return out;
  }

  function check(text, sender) {
    text = (text || "").trim().slice(0, 8000); sender = (sender || "").trim().slice(0, 200);
    const r = scorePosting("", text + (sender ? "\n" + sender : ""), "", null);
    const best = new Map();
    for (const f of r.findings.concat(senderFindings(sender, text), linkFindings(text)))
      if (!best.has(f.rule_id) || f.weight > best.get(f.rule_id).weight) best.set(f.rule_id, f);
    const findings = [...best.values()].sort(bySeverity);
    const score = Math.min(100, findings.reduce((s, f) => s + f.weight, 0));
    const b = band(score, findings.some(f => f.severity === "critical"));
    let level = BAND_LEVEL[b];
    if (r.lead_gen.flag && level < 1) level = 1;
    const [key, ttl, advice] = LEVELS[level];
    return {level, key, title: ttl, advice, score, band: b, findings, lead_gen: r.lead_gen};
  }
  return {normalize, runTextRules, scorePosting, check, linkFindings, clearedMatches, leadGen, urlChain,
          compensation, compensationInfo, LEVELS, ruleset: RULEPACK.version, rules: RULES};
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {createEngine};
}
if (typeof window !== "undefined" && window.NCS_RULEPACK) {
  window.NCS = createEngine(window.NCS_RULEPACK);
}
