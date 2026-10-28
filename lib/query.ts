import { severityRank } from './severity';
import {
  REPORT_TYPE_LABELS,
  SECURITY_REPORT_TYPES,
  SEVERITIES,
  type Finding,
  type FindingStatus,
  type Severity,
} from './types';

/**
 * A small filter language for the widget's search box, e.g.
 *
 *   severity:>=high file:!*.test.ts -scanner:semgrep is:new xss
 *
 * - Whitespace separates terms, and every term has to match (AND).
 * - The same key given more than once, or a comma list (`sev:high,critical`),
 *   matches any of its values (OR).
 * - `-key:value` and `key:!value` both negate a term.
 * - A bare word is a case-insensitive substring search over the finding's name,
 *   location, identifiers, scanner and dependency.
 * - Double quotes keep spaces in a value: `file:"my dir/*"`, `"sql injection"`.
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
  file: 'file',
  path: 'file',
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
  'Filter findings, e.g. severity:>=high file:!*.test.ts -scanner:semgrep is:new\n' +
  'Keys: severity (sev), type, file (path), id, scanner, dep, name, is:new|existing|uncomparable|fixed|fp\n' +
  'Prefix a term with - or its value with ! to exclude; commas mean "any of"; * and ? are wildcards.';

interface Token {
  text: string;
  /** Whether a quote opened the token, which keeps `"a:b"` a plain search. */
  quotedStart: boolean;
  /** Where the token sits in the input, quotes included: `[start, end)`. */
  start: number;
  end: number;
}

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let text = '';
  let inToken = false;
  let quotedStart = false;
  let inQuotes = false;
  let start = 0;

  for (let index = 0; index < input.length; index++) {
    const char = input[index];
    if (!inToken && (char === '"' || !/\s/.test(char))) start = index;
    if (char === '"') {
      if (!inToken) quotedStart = true;
      inToken = true;
      inQuotes = !inQuotes;
    } else if (/\s/.test(char) && !inQuotes) {
      if (inToken) tokens.push({ text, quotedStart, start, end: index });
      text = '';
      inToken = false;
      quotedStart = false;
    } else {
      inToken = true;
      text += char;
    }
  }
  if (inToken) tokens.push({ text, quotedStart, start, end: input.length });
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
    case 'file':
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

/**
 * A field whose values come from a fixed set, which the widget can show as
 * buttons: the severities, and the statuses `is:` takes.
 */
interface Choice<T extends string> {
  field: Field;
  /** The key a new term is written with. */
  key: string;
  values: readonly T[];
  /** Whether `matcher` lets a finding with this value through. */
  admits(matcher: Matcher, value: T): boolean;
  /** Whether a typed value belongs to the choice; `is:fp` does not. */
  owns(value: string): boolean;
}

const SEVERITY_CHOICE: Choice<Severity> = {
  field: 'severity',
  key: 'sev',
  values: SEVERITIES,
  // The matchers only ever look at the severity.
  admits: (matcher, severity) => matcher({ severity } as Finding, undefined),
  owns: () => true,
};

const STATUSES = ['new', 'existing', 'uncomparable', 'fixed'] as const satisfies FindingStatus[];

const STATUS_CHOICE: Choice<FindingStatus> = {
  field: 'is',
  key: 'is',
  values: STATUSES,
  admits: (matcher, status) => matcher({ likelyFalsePositive: false } as Finding, status),
  owns: (value) => value.toLowerCase() !== 'fp',
};

interface ChoiceTerm {
  token: Token;
  /** The key as typed, so a rewrite can keep `severity:` rather than `sev:`. */
  key: string;
  negate: boolean;
  values: string[];
}

/** The token as a term of the choice's field, or null when it is something else. */
function choiceTerm(token: Token, choice: Choice<string>): ChoiceTerm | null {
  if (token.quotedStart) return null;
  let term = token.text;
  let negate = false;
  if (term.length > 1 && term.startsWith('-')) {
    negate = true;
    term = term.slice(1);
  }
  const field = /^([a-z]+):(.*)$/i.exec(term);
  if (!field || !Object.hasOwn(FIELDS, field[1].toLowerCase())) return null;
  if (FIELDS[field[1].toLowerCase() as keyof typeof FIELDS] !== choice.field) return null;
  let rest = field[2];
  if (rest.startsWith('!')) {
    negate = !negate;
    rest = rest.slice(1);
  }
  const values = rest.split(',').filter(Boolean);
  // `is:new,fp` mixes in something no button stands for, so it is left alone.
  if (!values.every((value) => choice.owns(value))) return null;
  return { token, key: field[1], negate, values };
}

function choiceTerms(input: string, choice: Choice<string>): ChoiceTerm[] {
  return tokenize(input)
    .map((token) => choiceTerm(token, choice))
    .filter((term) => term !== null);
}

/**
 * The values the query's terms for the choice let through, or null when it has
 * none — which the buttons read as "nothing picked" rather than "all of them".
 * Every other term is ignored: this answers what is selected, not which
 * findings match.
 */
function selected<T extends string>(input: string, choice: Choice<T>): Set<T> | null {
  const included: Matcher[] = [];
  const excluded: Matcher[] = [];
  for (const term of choiceTerms(input, choice)) {
    for (const value of term.values) {
      const matcher = fieldMatcher(choice.field, value);
      if (typeof matcher !== 'string') (term.negate ? excluded : included).push(matcher);
    }
  }
  if (!included.length && !excluded.length) return null;

  return new Set(
    choice.values.filter(
      (value) =>
        (!included.length || included.some((matcher) => choice.admits(matcher, value))) &&
        !excluded.some((matcher) => choice.admits(matcher, value)),
    ),
  );
}

/**
 * Adds `values` to the query's selection for the choice, or takes them out if
 * they are all in already — what clicking one of its buttons does. A plain list
 * (`sev:info,low`) is edited in place and keeps its order; anything else
 * (`sev:>=high`, negations, several terms) is spelled out as the list it amounts
 * to first. The rest of the query is left as it was.
 */
function toggle<T extends string>(input: string, choice: Choice<T>, values: readonly T[]): string {
  const terms = choiceTerms(input, choice);
  const current = selected(input, choice);

  const isValue = (value: string) => (choice.values as readonly string[]).includes(value);
  const plain = terms.every(
    (term) => !term.negate && term.values.every((value) => isValue(value.toLowerCase())),
  );
  let list: string[] =
    current && plain
      ? [...new Set(terms.flatMap((term) => term.values.map((value) => value.toLowerCase())))]
      : choice.values.filter((value) => current?.has(value));
  list = values.every((value) => list.includes(value))
    ? list.filter((value) => !(values as readonly string[]).includes(value))
    : [...list, ...values.filter((value) => !list.includes(value))];

  const key = terms.find((term) => !term.negate)?.key ?? choice.key;
  const replacement = list.length ? `${key}:${list.join(',')}` : '';

  if (!terms.length) return [input.trimEnd(), replacement].filter(Boolean).join(' ');

  // The first term becomes the new one, the others go, along with the
  // whitespace after them so no gaps are left behind.
  let output = '';
  let last = 0;
  terms.forEach(({ token }, index) => {
    const keep = index === 0 && replacement;
    let end = token.end;
    if (!keep) while (end < input.length && /\s/.test(input[end])) end++;
    output += input.slice(last, token.start) + (keep ? replacement : '');
    last = end;
  });
  return (output + input.slice(last)).trim();
}

/** The severities the search narrows to; null when it does not. */
export function selectedSeverities(input: string): Set<Severity> | null {
  return selected(input, SEVERITY_CHOICE);
}

/** The statuses the search narrows to with `is:`; null when it does not. */
export function selectedStatuses(input: string): Set<FindingStatus> | null {
  return selected(input, STATUS_CHOICE);
}

/** What clicking a severity pill does to the search. */
export function toggleSeverity(input: string, severity: Severity): string {
  return toggle(input, SEVERITY_CHOICE, [severity]);
}

/** What clicking a status label does to the search, e.g. "new or not compared". */
export function toggleStatuses(input: string, statuses: readonly FindingStatus[]): string {
  return toggle(input, STATUS_CHOICE, statuses);
}

export interface Suggestion {
  /** What the list shows. */
  label: string;
  /** Replaces the input between `from` and the cursor. */
  insert: string;
}

export interface Suggestions {
  from: number;
  items: Suggestion[];
}

/** The keys offered while typing, one per field plus the aliases people reach for. */
const SUGGESTED_KEYS = ['severity', 'sev', 'type', 'file', 'id', 'scanner', 'dep', 'name', 'is'];

/** Values worth completing: the fields whose values come from a fixed set. */
const SUGGESTED_VALUES: Partial<Record<Field, readonly string[]>> = {
  severity: SEVERITIES,
  is: IS_VALUES,
  type: SECURITY_REPORT_TYPES,
};

/**
 * Completions for the term the cursor is in: keys while it has no `:` yet, and
 * values for keys that have a fixed set of them. Quotes are not considered,
 * which only matters for values with spaces — and none of the completed ones
 * have any.
 */
export function suggest(input: string, cursor: number): Suggestions {
  const before = input.slice(0, cursor);
  const termStart = before.search(/\S*$/);
  let term = before.slice(termStart);
  let offset = termStart;

  if (term.startsWith('-')) {
    term = term.slice(1);
    offset += 1;
  }

  const colon = term.indexOf(':');
  if (colon === -1) {
    if (!term || term.startsWith('"')) return { from: cursor, items: [] };
    const partial = term.toLowerCase();
    const items = SUGGESTED_KEYS.filter((key) => key.startsWith(partial) && key !== partial).map(
      (key) => ({ label: `${key}:`, insert: `${key}:` }),
    );
    return { from: offset, items };
  }

  const key = term.slice(0, colon).toLowerCase();
  const values = key in FIELDS ? SUGGESTED_VALUES[FIELDS[key as keyof typeof FIELDS]] : undefined;
  if (!values) return { from: cursor, items: [] };

  // Complete only the last comma-separated value, after any `!` or comparison.
  const valueStart = term.lastIndexOf(',') + 1 || colon + 1;
  const prefix = /^!?(?:>=|<=|>|<|=)?/.exec(term.slice(valueStart))![0];
  const partial = term.slice(valueStart + prefix.length).toLowerCase();
  const items = values
    .filter((value) => value.startsWith(partial) && value !== partial)
    .map((value) => ({ label: value, insert: `${value} ` }));
  return { from: offset + valueStart + prefix.length, items };
}
