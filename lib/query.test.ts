import { describe, expect, it } from 'vitest';
import { compileQuery, suggest } from './query';
import type { Finding, FindingStatus } from './types';

function finding(extra: Partial<Finding> = {}): Finding {
  return {
    reportType: 'sast',
    severity: 'high',
    name: 'Possible SQL injection',
    scanner: 'Semgrep',
    file: 'app/models/user.ts',
    identifiers: ['CWE-89', 'sql-injection'],
    links: [],
    likelyFalsePositive: false,
    key: 'k',
    ...extra,
  };
}

const ts = finding();
const testTs = finding({ file: 'app/models/user.test.ts', severity: 'low' });
const ruby = finding({ file: 'app/db.rb', severity: 'critical', name: 'Hardcoded secret' });
const dep = finding({
  reportType: 'dependency_scanning',
  severity: 'medium',
  name: 'Prototype pollution',
  file: 'package-lock.json',
  dependency: 'lodash 4.17.20',
  packageName: 'lodash',
  identifiers: ['CVE-2021-23337'],
  scanner: 'Gemnasium',
});
const all = [ts, testTs, ruby, dep];

function names(query: string, status?: (f: Finding) => FindingStatus): string[] {
  const compiled = compileQuery(query);
  return all.filter((f) => compiled.test(f, status?.(f))).map((f) => f.file!);
}

describe('compileQuery', () => {
  it('matches everything when empty', () => {
    const compiled = compileQuery('   ');
    expect(compiled.isEmpty).toBe(true);
    expect(names('')).toHaveLength(all.length);
  });

  it('searches bare words across name, location and identifiers', () => {
    expect(names('secret')).toEqual(['app/db.rb']);
    expect(names('cve-2021')).toEqual(['package-lock.json']);
    expect(names('models')).toEqual(['app/models/user.ts', 'app/models/user.test.ts']);
  });

  it('keeps quoted phrases together', () => {
    expect(names('"sql injection"')).toEqual(['app/models/user.ts', 'app/models/user.test.ts']);
    expect(names('"hardcoded secret" db')).toEqual(['app/db.rb']);
  });

  it('treats a quoted key:value as plain text', () => {
    const compiled = compileQuery('"foo:bar"');
    expect(compiled.errors).toEqual([]);
    expect(compiled.isEmpty).toBe(false);
  });

  it('filters severity exactly and by rank', () => {
    expect(names('severity:high')).toEqual(['app/models/user.ts']);
    expect(names('sev:>=high')).toEqual(['app/models/user.ts', 'app/db.rb']);
    expect(names('sev:>high')).toEqual(['app/db.rb']);
    expect(names('sev:<=medium')).toEqual(['app/models/user.test.ts', 'package-lock.json']);
    expect(names('sev:<medium')).toEqual(['app/models/user.test.ts']);
  });

  it('ORs values of the same key and ANDs different keys', () => {
    expect(names('sev:high,critical')).toEqual(['app/models/user.ts', 'app/db.rb']);
    expect(names('sev:high sev:critical')).toEqual(['app/models/user.ts', 'app/db.rb']);
    expect(names('sev:high,critical file:*.rb')).toEqual(['app/db.rb']);
  });

  it('matches globs against the whole path, across directories', () => {
    expect(names('file:*.ts')).toEqual(['app/models/user.ts', 'app/models/user.test.ts']);
    expect(names('file:*.TEST.ts')).toEqual(['app/models/user.test.ts']);
    expect(names('file:app/*/user.?s')).toEqual(['app/models/user.ts']);
  });

  it('matches values without wildcards as substrings', () => {
    expect(names('file:models/')).toEqual(['app/models/user.ts', 'app/models/user.test.ts']);
  });

  it('accepts path: as an alias for file:', () => {
    expect(names('path:*.rb')).toEqual(['app/db.rb']);
    // Aliases share a field, so they OR together like a repeated key.
    expect(names('path:*.rb file:*.json')).toEqual(['app/db.rb', 'package-lock.json']);
  });

  it('negates with a leading - or a ! on the value', () => {
    expect(names('file:!*.ts')).toEqual(['app/db.rb', 'package-lock.json']);
    expect(names('-file:*.ts')).toEqual(['app/db.rb', 'package-lock.json']);
    expect(names('-secret')).toHaveLength(3);
    // Every exclusion holds, and a comma list excludes any of its values.
    expect(names('-file:*.ts -file:*.rb')).toEqual(['package-lock.json']);
    expect(names('file:!*.ts,*.rb')).toEqual(['package-lock.json']);
    // Two negations cancel out.
    expect(names('-file:!*.rb')).toEqual(['app/db.rb']);
  });

  it('filters by report type, identifier, scanner and dependency', () => {
    expect(names('type:dependency')).toEqual(['package-lock.json']);
    expect(names('type:"Dependency scanning"')).toEqual(['package-lock.json']);
    expect(names('id:CWE-89')).toEqual(['app/models/user.ts', 'app/models/user.test.ts', 'app/db.rb']);
    expect(names('scanner:gemnasium')).toEqual(['package-lock.json']);
    expect(names('dep:lodash')).toEqual(['package-lock.json']);
  });

  it('filters by comparison status and false-positive flag', () => {
    const status = (f: Finding): FindingStatus => (f === ruby ? 'new' : 'existing');
    expect(names('is:new', status)).toEqual(['app/db.rb']);
    expect(names('-is:new', status)).toHaveLength(3);
    // No comparison, no status: nothing is new.
    expect(names('is:new')).toEqual([]);

    const fp = finding({ likelyFalsePositive: true });
    expect(compileQuery('is:fp').test(fp)).toBe(true);
    expect(compileQuery('-is:fp').test(fp)).toBe(false);
  });

  it('reports terms it cannot use and ignores them', () => {
    const compiled = compileQuery('colour:red sev:hgih is:old secret');
    expect(compiled.errors.map((e) => e.term)).toEqual(['colour:red', 'sev:hgih', 'is:old']);
    expect(names('colour:red sev:hgih is:old secret')).toEqual(['app/db.rb']);
  });

  it('ignores a key that has no value yet', () => {
    const compiled = compileQuery('sev:');
    expect(compiled.errors).toEqual([]);
    expect(compiled.isEmpty).toBe(true);
  });

  it('does not treat regex characters in values as special', () => {
    expect(names('file:app/(db).rb')).toEqual([]);
    expect(names('file:app/db.rb')).toEqual(['app/db.rb']);
    expect(names('file:app/db+rb')).toEqual([]);
  });
});

describe('suggest', () => {
  function labels(input: string, cursor = input.length): string[] {
    return suggest(input, cursor).items.map((item) => item.label);
  }

  /** The input after picking the first suggestion, as the widget does it. */
  function pick(input: string, cursor = input.length): string {
    const { from, items } = suggest(input, cursor);
    return input.slice(0, from) + items[0].insert + input.slice(cursor);
  }

  it('offers keys for a term without a colon', () => {
    expect(labels('se')).toEqual(['severity:', 'sev:']);
    expect(labels('sev:high s')).toEqual(['severity:', 'sev:', 'scanner:']);
    expect(pick('sev:high fi')).toBe('sev:high file:');
    // The alias still works when typed, but is not offered.
    expect(labels('pa')).toEqual([]);
  });

  it('offers nothing for an empty or quoted term', () => {
    expect(labels('')).toEqual([]);
    expect(labels('sev:high ')).toEqual([]);
    expect(labels('"se')).toEqual([]);
  });

  it('keeps a leading minus', () => {
    expect(pick('-fi')).toBe('-file:');
  });

  it('offers values for keys with a fixed set', () => {
    expect(labels('sev:')).toEqual(['critical', 'high', 'medium', 'low', 'info', 'unknown']);
    expect(labels('is:n')).toEqual(['new']);
    expect(labels('type:d')).toEqual(['dependency_scanning', 'dast']);
    expect(labels('file:')).toEqual([]);
    expect(labels('colour:')).toEqual([]);
  });

  it('completes after negation, comparisons and commas', () => {
    expect(pick('sev:>=h')).toBe('sev:>=high ');
    expect(pick('is:!n')).toBe('is:!new ');
    expect(pick('sev:high,c')).toBe('sev:high,critical ');
    expect(pick('-severity:i')).toBe('-severity:info ');
  });

  it('completes the term at the cursor, not the end', () => {
    expect(pick('se file:x', 2)).toBe('severity: file:x');
  });

  it('drops a suggestion that is already typed out', () => {
    expect(labels('sev:high')).toEqual([]);
    expect(labels('is')).toEqual([]);
  });
});
