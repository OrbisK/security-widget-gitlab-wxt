/**
 * Regenerates lib/semgrep-rule-ids.json from a checkout of GitLab's sast-rules:
 *
 *   git clone --depth 1 https://gitlab.com/gitlab-org/security-products/sast-rules.git
 *   pnpm generate:semgrep-rule-ids path/to/sast-rules
 *
 * A `nosemgrep` comment has to name the id a rule runs under, but GitLab's
 * semgrep analyzer swaps that for the rule's `primary_identifier` before it
 * writes the report. The mapping files define both: `id` becomes the rule id
 * when the rule pack is assembled, `primary_id` is what the report carries.
 * Most rules use one value for both, so only the ones that differ are kept.
 */
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';

interface MappingFile {
  [rulePack: string]: {
    mappings: { id: string; rules: { path: string; id?: string; primary_id?: string }[] }[];
  };
}

const checkout = process.argv[2];
if (!checkout) {
  console.error('usage: pnpm generate:semgrep-rule-ids <path to sast-rules checkout>');
  process.exit(1);
}

const ruleIds = new Map<string, Set<string>>();
const mappingDir = join(checkout, 'mappings');

for (const file of readdirSync(mappingDir).filter((name) => name.endsWith('.yml')).sort()) {
  const mapping = parse(readFileSync(join(mappingDir, file), 'utf8')) as MappingFile;
  for (const pack of Object.values(mapping)) {
    for (const { rules } of pack.mappings) {
      for (const rule of rules) {
        if (!rule.id || !rule.primary_id) continue;
        if (!ruleIds.has(rule.primary_id)) ruleIds.set(rule.primary_id, new Set());
        ruleIds.get(rule.primary_id)!.add(rule.id);
      }
    }
  }
}

const differing = Object.fromEntries(
  [...ruleIds]
    .map(([primary, ids]) => [primary, [...ids].sort()] as const)
    .filter(([primary, ids]) => !(ids.length === 1 && ids[0] === primary))
    .sort(([a], [b]) => a.localeCompare(b)),
);

const commit = execFileSync('git', ['-C', checkout, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();

writeFileSync(
  new URL('../lib/semgrep-rule-ids.json', import.meta.url),
  `${JSON.stringify({ source: `gitlab-org/security-products/sast-rules@${commit}`, ruleIds: differing }, null, 2)}\n`,
);

console.log(`${Object.keys(differing).length} primary identifiers with differing rule ids`);
