import { describe, expect, it } from 'vitest';
import { createSSRApp, h } from 'vue';
import { renderToString } from 'vue/server-renderer';
import SecurityWidget from './SecurityWidget.vue';
import { parseReport } from '@/lib/reports';
import { compareReports } from '@/lib/compare';
import { countBySeverity } from '@/lib/severity';
import { DEFAULT_SETTINGS, type Settings } from '@/lib/storage';
import type { BasePipeline, ComparisonState, ParsedReport, ScanResult } from '@/lib/types';

function report(vulnerabilities: unknown[]): ParsedReport {
  const jobWebUrl = 'https://gitlab.example/g/p/-/jobs/7';
  return parseReport({ vulnerabilities }, {
    reportType: 'sast',
    jobId: 7,
    jobName: 'semgrep-sast',
    jobWebUrl,
    downloadUrl: `${jobWebUrl}/artifacts/download?file_type=sast`,
  });
}

const base: BasePipeline = {
  strategy: 'merge-base',
  pipelineId: 55,
  pipelineWebUrl: 'https://gitlab.example/g/p/-/pipelines/55',
  targetBranch: 'main',
  sha: 'abcdef1234567890',
  commitWebUrl: 'https://gitlab.example/g/p/-/commit/abcdef1234567890',
};

/** A widget rendered from head reports, optionally compared with base ones. */
async function render(
  head: ParsedReport[],
  options: {
    base?: ParsedReport[];
    comparison?: ComparisonState;
    settings?: Partial<Settings>;
    query?: string;
  } = {},
): Promise<string> {
  const findings = head.flatMap((report) => report.findings);
  const comparison: ComparisonState = options.base
    ? { status: 'ready', comparison: { base, ...compareReports(head, options.base) } }
    : (options.comparison ?? { status: 'off' });

  const result: ScanResult = {
    reports: head,
    findings,
    counts: countBySeverity(findings),
    pipelineId: 99,
    pipelineWebUrl: 'https://gitlab.example/g/p/-/pipelines/99',
    comparison,
  };

  return renderToString(
    createSSRApp(() =>
      h(SecurityWidget, {
        state: { status: 'ok', result },
        settings: { ...DEFAULT_SETTINGS, startCollapsed: false, ...options.settings },
        initialQuery: options.query,
      }),
    ),
  );
}

const sqlInjection = {
  name: 'Possible SQL injection',
  severity: 'high',
  identifiers: [{ type: 'semgrep_id', name: 'rules.sql-injection', value: 'sql-injection' }],
  location: { file: 'app/db.rb', start_line: 12 },
};
const hardcodedSecret = { name: 'Hardcoded secret', severity: 'critical' };

describe('SecurityWidget header', () => {
  it('is green only when there is nothing to report', async () => {
    const html = await render([report([])]);

    expect(html).toContain('glsw-tone-success');
    expect(html).toContain('detected no vulnerabilities');
  });

  it('stays amber for findings this merge request did not introduce', async () => {
    const html = await render([report([sqlInjection])], { base: [report([sqlInjection])] });

    expect(html).toContain('glsw-tone-warning');
    expect(html).not.toContain('glsw-tone-success');
    expect(html).toContain('No new vulnerabilities, 1 already on main');
  });

  it('still shows the severity of findings that are not new', async () => {
    const html = await render([report([sqlInjection])], { base: [report([sqlInjection])] });

    expect(html).toContain('already there:');
    expect(html).toContain('glsw-sev-high');
  });

  it('turns red when the merge request adds a finding', async () => {
    const html = await render([report([sqlInjection, hardcodedSecret])], {
      base: [report([sqlInjection])],
    });

    expect(html).toContain('glsw-tone-danger');
    expect(html).toContain('This merge request adds 1 potential vulnerability');
    // The new finding is counted apart from the pre-existing one.
    expect(html).toContain('new:');
    expect(html).toContain('already there:');
    expect(html).toContain('glsw-badge-new');
  });

  it('links the commit it compared against', async () => {
    const html = await render([report([sqlInjection])], { base: [report([sqlInjection])] });

    expect(html).toContain('Compared with main at');
    expect(html).toContain(`href="${base.commitWebUrl}"`);
    // Abbreviated, as GitLab shows shas.
    expect(html).toContain('>abcdef12<');
  });

  it('says what it could not compare instead of calling it new', async () => {
    const html = await render([report([sqlInjection])], {
      base: [{ ...report([]), error: { kind: 'expired', message: 'gone' } }],
    });

    expect(html).toContain('could not be compared with main');
    expect(html).toContain('not compared');
    expect(html).not.toContain('glsw-badge-new');
    // Unknown is not a clean bill of health.
    expect(html).toContain('glsw-tone-warning');
  });

  it('keeps the plain totals while the comparison is still running', async () => {
    const html = await render([report([sqlInjection])], { comparison: { status: 'loading' } });

    expect(html).toContain('Security scanning detected 1 potential vulnerability');
    expect(html).toContain('Comparing with the target branch…');
    expect(html).toContain('glsw-tone-warning');
  });

  it('gives the reason when no base could be established', async () => {
    const html = await render([report([sqlInjection])], {
      comparison: { status: 'unavailable', reason: 'main has no finished pipeline' },
    });

    expect(html).toContain('Not compared with the target branch');
    expect(html).toContain('main has no finished pipeline');
    expect(html).not.toContain('glsw-badge-new');
  });

  it('lists what the merge request fixed', async () => {
    const html = await render([report([sqlInjection])], {
      base: [report([sqlInjection, hardcodedSecret])],
    });

    expect(html).toContain('Fixed by this merge request');
    expect(html).toContain('glsw-badge-fixed');
    expect(html).toContain('1 fixed here');
  });

  it('hides pre-existing findings on request, but never uncomparable ones', async () => {
    const html = await render([report([sqlInjection, hardcodedSecret])], {
      base: [report([sqlInjection])],
      settings: { showOnlyNew: true },
    });

    expect(html).toContain('Hardcoded secret');
    expect(html).not.toContain('Possible SQL injection');
    expect(html).toContain('1 hidden by filters');
  });

  it('stays amber when show-only-new is what emptied the list', async () => {
    // Nothing is on screen, but the findings are still in the code under review:
    // a green check here would be the filter congratulating the reader.
    const html = await render([report([sqlInjection])], {
      base: [report([sqlInjection])],
      settings: { showOnlyNew: true },
    });

    expect(html).toContain('glsw-tone-warning');
    expect(html).not.toContain('glsw-tone-success');
    expect(html).toContain('No new vulnerabilities, 1 already on main');
    // …and the pills keep saying what is there, even with the list hiding it.
    expect(html).toContain('already there:');
    expect(html).toContain('glsw-sev-high');
    expect(html).not.toContain('above your severity filter');
  });

  it('names the report type it could not compare', async () => {
    const html = await render([report([sqlInjection])], {
      base: [{ ...report([]), error: { kind: 'expired', message: 'gone' } }],
    });

    expect(html).toContain('1 not compared (SAST)');
  });

  it('is still green when show-only-new has nothing to hide', async () => {
    const html = await render([report([])], {
      base: [report([])],
      settings: { showOnlyNew: true },
    });

    expect(html).toContain('glsw-tone-success');
  });

  it('lists as many findings per report as the setting allows', async () => {
    const many = Array.from({ length: 8 }, (_, index) => ({
      ...sqlInjection,
      name: `Finding ${index}`,
    }));

    const html = await render([report(many)], { settings: { findingsPerPage: 5 } });

    expect(html).toContain('Finding 4');
    expect(html).not.toContain('Finding 5');
    expect(html).toContain('Show 3 more of 8');
  });
});

describe('SecurityWidget search', () => {
  it('narrows the list without touching the header', async () => {
    const html = await render([report([sqlInjection, hardcodedSecret])], {
      base: [report([sqlInjection])],
      query: 'sev:high',
    });

    expect(html).toContain('Possible SQL injection');
    expect(html).not.toContain('Hardcoded secret');
    expect(html).toContain('1 of 2 match');
    // The new critical finding is filtered out of the list, but the header still
    // reports it.
    expect(html).toContain('glsw-tone-danger');
    expect(html).toContain('This merge request adds 1 potential vulnerability');
    expect(html).not.toContain('hidden by filters');
  });

  it('says when a section has findings but none match', async () => {
    const html = await render([report([sqlInjection])], { query: 'file:*.ts' });

    expect(html).toContain('No findings match the search.');
    expect(html).toContain('glsw-tone-warning');
  });

  it('names the terms it ignored', async () => {
    const html = await render([report([sqlInjection])], { query: 'colour:red' });

    expect(html).toContain('Possible SQL injection');
    expect(html).toContain('unknown key');
  });

  it('applies to fixed findings too', async () => {
    const html = await render([report([sqlInjection])], {
      base: [report([sqlInjection, hardcodedSecret])],
      query: '-is:fixed',
    });

    expect(html).not.toContain('Fixed by this merge request');
    expect(html).toContain('1 fixed here');
  });

  it('is not offered when switched off or when there is nothing to search', async () => {
    const off = await render([report([sqlInjection])], { settings: { showSearch: false } });
    const empty = await render([report([])]);

    expect(off).not.toContain('glsw-search');
    expect(empty).not.toContain('glsw-search');
  });
});
