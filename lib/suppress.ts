import type { Finding } from './types';

/**
 * An inline comment that tells the finding's scanner to skip that line, ready
 * to paste into the reported file.
 */
export interface Suppression {
  comment: string;
  /** Where the comment has to go relative to the reported line. */
  placement: 'same-line' | 'line-above';
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

/**
 * How to silence a finding in source, keyed by `Finding.scannerId`. Only
 * scanners that read an inline marker are listed; anything else — dependency
 * and container scanning, DAST, third-party tools — gets no suppression and is
 * dismissed in GitLab instead.
 */
const SCANNERS: Partial<Record<string, (style: CommentStyle) => Suppression>> = {
  // Semgrep honors the marker on the first line of the match or the line above
  // it. Without a rule id it silences every rule on that line; the report only
  // carries GitLab's primary identifier (e.g. `bandit.B101`), not the semgrep
  // rule id the marker would need to be narrower.
  semgrep: (style) => ({
    comment: style('nosemgrep'),
    placement: 'line-above',
    scope: 'every Semgrep rule on the next line',
  }),
  // Gitleaks looks for the marker anywhere on the line holding the secret.
  gitleaks: (style) => ({
    comment: style('gitleaks:allow'),
    placement: 'same-line',
    scope: 'secret detection on this line',
  }),
  kics: (style) => ({
    comment: style('kics-scan ignore-line'),
    placement: 'line-above',
    scope: 'every KICS query on the next line',
  }),
};

export function suppressionFor(finding: Finding): Suppression | undefined {
  if (!finding.scannerId || !finding.file) return undefined;
  const scanner = SCANNERS[finding.scannerId];
  const style = commentStyleFor(finding.file);
  return scanner && style ? scanner(style) : undefined;
}
