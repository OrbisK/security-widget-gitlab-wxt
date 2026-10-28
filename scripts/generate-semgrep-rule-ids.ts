/**
 * Regenerates lib/semgrep-rule-ids.json from the rule pack GitLab's semgrep
 * analyzer ships:
 *
 *   pnpm generate:semgrep-rule-ids           # the version the analyzer's main branch pins
 *   pnpm generate:semgrep-rule-ids 2.10.1    # a specific sast-rules release
 *
 * A `nosemgrep` comment has to name the id a rule runs under, but the analyzer
 * swaps that for the rule's `primary_identifier` before it writes the report.
 * The released rule pack carries both, so it is read rather than the mapping
 * files on sast-rules' main branch, which can be ahead of any release. Most
 * rules use one value for both, so only the ones that differ are kept.
 *
 * Needs `unzip` on the PATH.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parse } from 'yaml';

const ANALYZER_DOCKERFILE =
  'https://gitlab.com/gitlab-org/security-products/analyzers/semgrep/-/raw/main/Dockerfile';
const SAST_RULES_PROJECT_ID = 27038823;

interface RulePack {
  rules?: { id: string; metadata?: { primary_identifier?: string } }[];
}

async function download(url: string): Promise<Response> {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`${url}: ${response.status} ${response.statusText}`);
  return response;
}

/** The sast-rules release the analyzer's Dockerfile installs. */
async function pinnedVersion(): Promise<string> {
  const dockerfile = await (await download(ANALYZER_DOCKERFILE)).text();
  const version = dockerfile.match(/^ENV SAST_RULES_VERSION=(\S+)$/m)?.[1];
  if (!version) throw new Error(`no SAST_RULES_VERSION in ${ANALYZER_DOCKERFILE}`);
  return version;
}

function* yamlFiles(dir: string): Generator<string> {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) yield* yamlFiles(path);
    else if (entry.name.endsWith('.yml')) yield path;
  }
}

const version = process.argv[2] ?? (await pinnedVersion());
const workdir = mkdtempSync(join(tmpdir(), 'sast-rules-'));

try {
  const zip = join(workdir, 'sast-rules.zip');
  const archive = await download(
    `https://gitlab.com/api/v4/projects/${SAST_RULES_PROJECT_ID}/packages/generic/sast-rules/v${version}/sast-rules-v${version}.zip`,
  );
  writeFileSync(zip, Buffer.from(await archive.arrayBuffer()));
  execFileSync('unzip', ['-q', zip, 'dist/*', '-d', workdir]);

  const ruleIds = new Map<string, Set<string>>();
  for (const file of [...yamlFiles(join(workdir, 'dist'))].sort()) {
    const pack = (parse(readFileSync(file, 'utf8')) ?? {}) as RulePack;
    for (const rule of pack.rules ?? []) {
      // Mirrors the analyzer: a rule without a primary identifier is reported
      // under its own id.
      const primary = rule.metadata?.primary_identifier || rule.id;
      if (!ruleIds.has(primary)) ruleIds.set(primary, new Set());
      ruleIds.get(primary)!.add(rule.id);
    }
  }

  const differing = Object.fromEntries(
    [...ruleIds]
      .map(([primary, ids]) => [primary, [...ids].sort()] as const)
      .filter(([primary, ids]) => !(ids.length === 1 && ids[0] === primary))
      .sort(([a], [b]) => a.localeCompare(b)),
  );

  writeFileSync(
    new URL('../lib/semgrep-rule-ids.json', import.meta.url),
    `${JSON.stringify({ source: `gitlab-org/security-products/sast-rules v${version}`, ruleIds: differing }, null, 2)}\n`,
  );

  console.log(
    `sast-rules v${version}: ${Object.keys(differing).length} of ${ruleIds.size} primary identifiers run under other rule ids`,
  );
} finally {
  rmSync(workdir, { recursive: true, force: true });
}
