import semgrepRuleIdMap from './semgrep-rule-ids.json';
import type { Finding } from './types';

/**
 * An inline comment that tells the finding's scanner to skip that line, ready
 * to paste into the reported file.
 */
export interface Suppression {
  comment: string;
  /** Where the comment has to go relative to the reported line. */
  placement: 'same-line' | 'line-above' | 'file-start';
  /** What the comment silences, for the button's tooltip. */
  scope: string;
}

type CommentStyle = (text: string) => string;

const hash: CommentStyle = (text) => `# ${text}`;
const slashes: CommentStyle = (text) => `// ${text}`;
const dashes: CommentStyle = (text) => `-- ${text}`;
const markup: CommentStyle = (text) => `<!-- ${text} -->`;
const block: CommentStyle = (text) => `/* ${text} */`;

const STYLE_BY_EXTENSION: Partial<Record<string, CommentStyle>> = {
  ...Object.fromEntries(
    [
      'py', 'rb', 'sh', 'bash', 'zsh', 'pl', 'r', 'ps1', 'ex', 'exs',
      'yml', 'yaml', 'toml', 'tf', 'tfvars', 'hcl', 'properties', 'cfg', 'conf', 'env',
    ].map((extension) => [extension, hash]),
  ),
  ...Object.fromEntries(
    [
      'js', 'jsx', 'mjs', 'cjs', 'ts', 'tsx', 'mts', 'cts',
      'go', 'java', 'kt', 'kts', 'scala', 'groovy', 'gradle', 'swift', 'dart', 'rs',
      'c', 'h', 'cc', 'cpp', 'hpp', 'cs', 'php', 'sol',
    ].map((extension) => [extension, slashes]),
  ),
  ...Object.fromEntries(['sql', 'lua', 'hs'].map((extension) => [extension, dashes])),
  ...Object.fromEntries(['html', 'htm', 'xml'].map((extension) => [extension, markup])),
  ...Object.fromEntries(['css', 'scss', 'less'].map((extension) => [extension, block])),
};

/** Files that are named rather than suffixed by their type. */
const STYLE_BY_FILENAME: Partial<Record<string, CommentStyle>> = {
  dockerfile: hash,
  containerfile: hash,
  makefile: hash,
  gemfile: hash,
  rakefile: hash,
  '.env': hash,
};

/**
 * The comment syntax of the reported file, or undefined when we cannot tell
 * — JSON, say, has none, and a wrong guess would be pasted into code.
 */
export function commentStyleFor(file: string): CommentStyle | undefined {
  const basename = file.split('/').pop()!.toLowerCase();
  const byName =
    STYLE_BY_FILENAME[basename] ??
    // `.env.local`, `Dockerfile.prod` and friends.
    STYLE_BY_FILENAME[basename.split('.').slice(0, basename.startsWith('.') ? 2 : 1).join('.')];
  if (byName) return byName;

  const dot = basename.lastIndexOf('.');
  return dot > 0 ? STYLE_BY_EXTENSION[basename.slice(dot + 1)] : undefined;
}

/** The finding's identifier of one type, e.g. its `semgrep_id`. */
function identifier(finding: Finding, type: string): string | undefined {
  return finding.typedIdentifiers?.find((candidate) => candidate.type === type)?.value;
}

/**
 * The ids a semgrep rule runs under, which is what `nosemgrep` matches on. The
 * report only carries GitLab's primary identifier; for most rules that is the
 * rule id too, and the bundled mapping covers the rest — split rules such as
 * `bandit.B611` running as `bandit.B611-1` and `bandit.B611-2`.
 */
function semgrepRuleIds(primaryIdentifier: string): string[] {
  return (semgrepRuleIdMap.ruleIds as Partial<Record<string, string[]>>)[primaryIdentifier] ?? [
    primaryIdentifier,
  ];
}

type Suppressor = (finding: Finding, style: CommentStyle) => Suppression;

/**
 * How to silence a finding in source, keyed by `Finding.scannerId`. Only
 * scanners that read an inline marker are listed; anything else — dependency
 * and container scanning, DAST, third-party tools — gets no suppression and is
 * dismissed in GitLab instead.
 *
 * Each names the finding's rule whenever the scanner can: a marker that names
 * no rule also silences whatever else is later found on that line.
 */
const SCANNERS: Partial<Record<string, Suppressor>> = {
  // Semgrep honors the marker on the first line of the match or the line above it.
  semgrep: (finding, style) => {
    const primaryIdentifier = identifier(finding, 'semgrep_id');
    if (!primaryIdentifier) {
      return {
        comment: style('nosemgrep'),
        placement: 'line-above',
        scope: 'every Semgrep rule on the next line',
      };
    }
    const ruleIds = semgrepRuleIds(primaryIdentifier);
    return {
      comment: style(`nosemgrep: ${ruleIds.join(', ')}`),
      placement: 'line-above',
      scope: `${ruleIds.join(', ')} on the next line`,
    };
  },
  // Gitleaks looks for the marker anywhere on the line holding the secret, and
  // has no inline form that names a rule.
  gitleaks: (_finding, style) => ({
    comment: style('gitleaks:allow'),
    placement: 'same-line',
    scope: 'secret detection on this line',
  }),
  // KICS can only name a query file-wide: `disable=` is read from the comments
  // that open the file, and `ignore-line` takes no query id.
  kics: (finding, style) => {
    const queryId = identifier(finding, 'kics_id');
    if (!queryId) {
      return {
        comment: style('kics-scan ignore-line'),
        placement: 'line-above',
        scope: 'every KICS query on the next line',
      };
    }
    return {
      comment: style(`kics-scan disable=${queryId}`),
      placement: 'file-start',
      scope: 'this KICS query in the whole file',
    };
  },
};

export function suppressionFor(finding: Finding): Suppression | undefined {
  if (!finding.scannerId || !finding.file) return undefined;
  const scanner = SCANNERS[finding.scannerId];
  const style = commentStyleFor(finding.file);
  return scanner && style ? scanner(finding, style) : undefined;
}
