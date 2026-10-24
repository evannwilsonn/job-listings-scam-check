#!/usr/bin/env node
/*
 * Run parity cases through the browser engine under Node.
 *
 *   node web/parity_runner.js < tests/fixtures/parity_cases.jsonl > /tmp/js.json
 *
 * Reads one JSON object per line: {id, title, description, company, urls}.
 * Prints one JSON array of {id, score, band, findings, lead_gen} in the same shape tools/parity.py
 * produces from the Python engine, so the two can be diffed field by field.
 */
"use strict";
const fs = require("fs");
const path = require("path");
const {createEngine} = require(path.join(__dirname, "engine.js"));

const core = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "scam_detector", "rulepack", "core.json"), "utf8"));
const engine = createEngine(core);

const lines = fs.readFileSync(0, "utf8").split("\n").filter(l => l.trim());
const out = lines.map(line => {
  const c = JSON.parse(line);
  const r = engine.scorePosting(c.title || "", c.description || "", c.company || "", c.urls || []);
  return {
    id: c.id,
    score: r.score,
    band: r.band,
    findings: r.findings.map(f => ({rule_id: f.rule_id, severity: f.severity, weight: f.weight, matched: f.matched})),
    lead_gen: {points: r.lead_gen.points, flag: r.lead_gen.flag, level: r.lead_gen.level,
               reasons: r.lead_gen.reasons.map(x => x.reason)},
  };
});
process.stdout.write(JSON.stringify(out));
