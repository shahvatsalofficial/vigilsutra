import type { Rule } from "../types.js";
import { secretRules } from "./secrets.js";
import { infraRules } from "./infra.js";
import { codeRules } from "./code.js";
import { agentPrivacyRules, processRules } from "./agents-privacy.js";
import { supplyRules } from "./supply.js";

export const RULES_VERSION = "1.2.0";

export const ALL_RULES: Rule[] = [...secretRules, ...infraRules, ...codeRules, ...agentPrivacyRules, ...processRules, ...supplyRules];

export const CWE_NOTE = "CWE ids are orientation only, taken from the MITRE CWE list; no OWASP/NIST control mapping is asserted (mapping unverified).";

export function findRule(id: string): Rule | undefined {
  return ALL_RULES.find((r) => r.id.toLowerCase() === id.toLowerCase());
}
