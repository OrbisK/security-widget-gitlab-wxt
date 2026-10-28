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
  it('suggests nosemgrep on the line above for semgrep', () => {
    expect(suppressionFor(finding())).toMatchObject({
      comment: '# nosemgrep',
      placement: 'line-above',
    });
  });

  it('suggests gitleaks:allow on the same line for secret detection', () => {
    const secret = finding({ reportType: 'secret_detection', scannerId: 'gitleaks', file: 'config/app.ts' });
    expect(suppressionFor(secret)).toMatchObject({
      comment: '// gitleaks:allow',
      placement: 'same-line',
    });
  });

  it('suggests a kics ignore-line for IaC findings', () => {
    expect(suppressionFor(finding({ scannerId: 'kics', file: 'infra/main.tf' }))).toMatchObject({
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
