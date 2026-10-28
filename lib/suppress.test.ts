import { describe, expect, it } from 'vitest';
import { commentStyleFor, suppressionFor } from './suppress';
import type { Finding } from './types';

function finding(extra: Partial<Finding> = {}): Finding {
  return {
    reportType: 'sast',
    severity: 'high',
    name: 'Use of assert detected',
    scannerId: 'semgrep',
    file: 'app/main.py',
    startLine: 12,
    identifiers: ['bandit.B101'],
    typedIdentifiers: [
      { type: 'semgrep_id', value: 'bandit.B101' },
      { type: 'cwe', value: '754' },
      { type: 'bandit_test_id', value: 'B101' },
    ],
    links: [],
    likelyFalsePositive: false,
    key: 'k',
    ...extra,
  };
}

describe('commentStyleFor', () => {
  it.each([
    ['app/main.py', '# x'],
    ['src/index.ts', '// x'],
    ['db/schema.sql', '-- x'],
    ['public/index.html', '<!-- x -->'],
    ['styles/app.css', '/* x */'],
    ['Dockerfile', '# x'],
    ['deploy/Dockerfile.prod', '# x'],
    ['.env', '# x'],
    ['.env.local', '# x'],
  ])('comments %s as %s', (file, expected) => {
    expect(commentStyleFor(file)?.('x')).toBe(expected);
  });

  it.each(['package-lock.json', 'README', 'notes.unknownext'])(
    'gives up on %s rather than guess',
    (file) => {
      expect(commentStyleFor(file)).toBeUndefined();
    },
  );
});

describe('suppressionFor', () => {
  it('names the semgrep rule, which is usually the primary identifier', () => {
    expect(suppressionFor(finding())).toMatchObject({
      comment: '# nosemgrep: bandit.B101',
      placement: 'line-above',
    });
  });

  it('names every rule a split primary identifier runs as', () => {
    const split = finding({ typedIdentifiers: [{ type: 'semgrep_id', value: 'bandit.B611' }] });
    expect(suppressionFor(split)?.comment).toBe('# nosemgrep: bandit.B611-1, bandit.B611-2');
  });

  it('falls back to a bare nosemgrep without a semgrep id', () => {
    expect(suppressionFor(finding({ typedIdentifiers: [] }))?.comment).toBe('# nosemgrep');
  });

  it('suggests gitleaks:allow on the same line for secret detection', () => {
    const secret = finding({ reportType: 'secret_detection', scannerId: 'gitleaks', file: 'config/app.ts' });
    expect(suppressionFor(secret)).toMatchObject({
      comment: '// gitleaks:allow',
      placement: 'same-line',
    });
  });

  it('disables the kics query for the file', () => {
    const iac = finding({
      scannerId: 'kics',
      file: 'infra/main.tf',
      typedIdentifiers: [{ type: 'kics_id', value: '1a427b25-2e9e-4298-9530-0499a55e736b' }],
    });
    expect(suppressionFor(iac)).toMatchObject({
      comment: '# kics-scan disable=1a427b25-2e9e-4298-9530-0499a55e736b',
      placement: 'file-start',
    });
  });

  it('falls back to a kics ignore-line without a query id', () => {
    const iac = finding({ scannerId: 'kics', file: 'infra/main.tf', typedIdentifiers: [] });
    expect(suppressionFor(iac)).toMatchObject({
      comment: '# kics-scan ignore-line',
      placement: 'line-above',
    });
  });

  it('offers nothing for scanners without an inline marker', () => {
    expect(suppressionFor(finding({ scannerId: 'gemnasium', file: 'package.json' }))).toBeUndefined();
    expect(suppressionFor(finding({ scannerId: 'trivy' }))).toBeUndefined();
    expect(suppressionFor(finding({ scannerId: undefined }))).toBeUndefined();
  });

  it('offers nothing without a file to put the comment in', () => {
    expect(suppressionFor(finding({ file: undefined }))).toBeUndefined();
    expect(suppressionFor(finding({ file: 'data/fixtures.json' }))).toBeUndefined();
  });
});
