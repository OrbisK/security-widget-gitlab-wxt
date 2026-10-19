import { severityRank } from './severity';
import {
  REPORT_TYPE_LABELS,
  SEVERITIES,
  type Finding,
  type FindingStatus,
  type Severity,
} from './types';

/**
 * A small filter language for the widget's search box, e.g.
 *
 *   severity:>=high path:!*.test.ts -scanner:semgrep is:new xss
 *
 * - Whitespace separates terms, and every term has to match (AND).
 * - The same key given more than once, or a comma list (`sev:high,critical`),
 *   matches any of its values (OR).
 * - `-key:value` and `key:!value` both negate a term.
 * - A bare word is a case-insensitive substring search over the finding's name,
 *   location, identifiers, scanner and dependency.
 * - Double quotes keep spaces in a value: `path:"my dir/*"`, `"sql injection"`.
 * - Values containing `*` or `?` are globs matched against the whole field
 *   (`*` spans `/`, so `*.ts` matches `src/a/b.ts`); anything else is a substring.
 *
 * Parsing never throws: a term it cannot make sense of is reported in `errors`
 * and skipped, so a half-typed query never empties the list.
 */

export interface QueryError {
  term: string;
  message: string;
}

export interface CompiledQuery {
  /** True when there is nothing to filter by, so every finding matches. */
  isEmpty: boolean;
  errors: QueryError[];
  test(finding: Finding, status?: FindingStatus): boolean;
}

type Matcher = (finding: Finding, status: FindingStatus | undefined) => boolean;

/** Key aliases, mapped onto the field they filter. */
const FIELDS = {
  severity: 'severity',
  sev: 'severity',
  type: 'type',
  report: 'type',
  path: 'path',
  file: 'path',
  id: 'id',
  scanner: 'scanner',
  dep: 'dep',
  package: 'dep',
  name: 'name',
  is: 'is',
} as const;

type Field = (typeof FIELDS)[keyof typeof FIELDS];

const IS_VALUES = ['new', 'existing', 'uncomparable', 'fixed', 'fp'] as const;

export const QUERY_HELP =
  'Filter findings, e.g. severity:>=high path:!*.test.ts -scanner:semgrep is:new\n' +
  'Keys: severity (sev), type, path (file), id, scanner, dep, name, is:new|existing|uncomparable|fixed|fp\n' +
  'Prefix a term with - or its value with ! to exclude; commas mean "any of"; * and ? are wildcards.';

interface Token {
  text: string;
  /** Whether a quote opened the token, which keeps `"a:b"` a plain search. */
  quotedStart: boolean;
}

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let text = '';
  let inToken = false;
  let quotedStart = false;
  let inQuotes = false;

  for (const char of input) {
    if (char === '"') {
      if (!inToken) quotedStart = true;
      inToken = true;
      inQuotes = !inQuotes;
    } else if (/\s/.test(char) && !inQuotes) {
      if (inToken) tokens.push({ text, quotedStart });
      text = '';
      inToken = false;
      quotedStart = false;
    } else {
      inToken = true;
      text += char;
    }
  }
  if (inToken) tokens.push({ text, quotedStart });
  return tokens;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.+^${}()|[\]\\]/g, '\\$&');
}

/** A glob when the value has wildcards, a substring search otherwise. */
function textMatcher(value: string): (candidate: string | undefined) => boolean {
  if (/[*?]/.test(value)) {
    const pattern = escapeRegExp(value).replace(/\*/g, '.*').replace(/\?/g, '.');
    const regex = new RegExp(`^${pattern}$`, 'i');
    return (candidate) => candidate !== undefined && regex.test(candidate);
  }
  const needle = value.toLowerCase();
  return (candidate) => candidate !== undefined && candidate.toLowerCase().includes(needle);
}

function anyOf(candidates: (string | undefined)[], match: (c: string | undefined) => boolean) {
  return candidates.some(match);
}

function freeTextFields(finding: Finding): (string | undefined)[] {
  return [
    finding.name,
    finding.file,
    finding.path,
    finding.locationLabel,
    finding.scanner,
    finding.dependency,
    finding.packageName,
    finding.image,
    ...finding.identifiers,
  ];
}

const SEVERITY_OPS = ['>=', '<=', '>', '<', '='] as const;

/** `>=high` means "high or worse", following how the severities are ranked. */
function severityMatcher(raw: string): Matcher | string {
  const op = SEVERITY_OPS.find((candidate) => raw.startsWith(candidate)) ?? '=';
  const name = raw.slice(raw.startsWith(op) ? op.length : 0).toLowerCase();
  if (!(SEVERITIES as readonly string[]).includes(name)) {
    return `unknown severity "${name}", expected one of ${SEVERITIES.join(', ')}`;
  }
  // Lower rank is worse, so "more severe than" is a smaller rank.
  const target = severityRank(name as Severity);
  return (finding) => {
    const rank = severityRank(finding.severity);
    switch (op) {
      case '>=':
        return rank <= target;
      case '<=':
        return rank >= target;
      case '>':
        return rank < target;
      case '<':
        return rank > target;
      default:
        return rank === target;
    }
  };
}

function isMatcher(raw: string): Matcher | string {
  const value = raw.toLowerCase();
  if (!(IS_VALUES as readonly string[]).includes(value)) {
    return `unknown "is:${value}", expected one of ${IS_VALUES.join(', ')}`;
  }
  if (value === 'fp') return (finding) => finding.likelyFalsePositive;
  return (_finding, status) => status === value;
}

function fieldMatcher(field: Field, value: string): Matcher | string {
  if (field === 'severity') return severityMatcher(value);
  if (field === 'is') return isMatcher(value);

  const match = textMatcher(value);
  switch (field) {
    case 'type':
      return (finding) =>
        anyOf([finding.reportType, REPORT_TYPE_LABELS[finding.reportType]], match);
    case 'path':
      return (finding) => anyOf([finding.file, finding.path, finding.locationLabel], match);
    case 'id':
      return (finding) => anyOf(finding.identifiers, match);
    case 'scanner':
      return (finding) => match(finding.scanner);
    case 'dep':
      return (finding) =>
        anyOf([finding.dependency, finding.packageName, finding.image], match);
    case 'name':
      return (finding) => match(finding.name);
  }
}

export function compileQuery(input: string): CompiledQuery {
  const errors: QueryError[] = [];
  /** Positive terms grouped by field: any value of a field may match. */
  const included = new Map<Field, Matcher[]>();
  /** Negated terms and bare words, each of which has to hold on its own. */
  const required: Matcher[] = [];

  for (const { text, quotedStart } of tokenize(input)) {
    let term = text;
    let negate = false;
    if (term.length > 1 && term.startsWith('-')) {
      negate = true;
      term = term.slice(1);
    }

    const field = quotedStart ? null : /^([a-z]+):(.*)$/i.exec(term);
    if (!field) {
      if (!term) continue;
      const match = textMatcher(term);
      const matcher: Matcher = (finding) => anyOf(freeTextFields(finding), match);
      required.push(negate ? (f, s) => !matcher(f, s) : matcher);
      continue;
    }

    const key = field[1].toLowerCase();
    let rest = field[2];
    if (!(key in FIELDS)) {
      errors.push({ term: text, message: `unknown key "${key}"` });
      continue;
    }
    if (rest.startsWith('!')) {
      negate = !negate;
      rest = rest.slice(1);
    }

    const matchers: Matcher[] = [];
    for (const value of rest.split(',').filter(Boolean)) {
      const matcher = fieldMatcher(FIELDS[key as keyof typeof FIELDS], value);
      if (typeof matcher === 'string') errors.push({ term: text, message: matcher });
      else matchers.push(matcher);
    }
    // `sev:` while still typing: nothing to filter by yet, and not worth an error.
    if (!matchers.length) continue;

    const anyMatches: Matcher = (f, s) => matchers.some((matcher) => matcher(f, s));
    if (negate) {
      required.push((f, s) => !anyMatches(f, s));
    } else {
      const canonical = FIELDS[key as keyof typeof FIELDS];
      included.set(canonical, [...(included.get(canonical) ?? []), anyMatches]);
    }
  }

  const groups = [...included.values()];
  return {
    isEmpty: groups.length === 0 && required.length === 0,
    errors,
    test(finding, status) {
      return (
        required.every((matcher) => matcher(finding, status)) &&
        groups.every((group) => group.some((matcher) => matcher(finding, status)))
      );
    },
  };
}
