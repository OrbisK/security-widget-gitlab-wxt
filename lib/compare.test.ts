import { describe, expect, it } from 'vitest';
import { compareReports, fingerprint } from './compare';
import { parseReport } from './reports';
import { artifactDownloadUrl } from './gitlab-api';
import type { Finding, ParsedReport, ReportError, ReportSource, ReportType } from './types';

function source(reportType: ReportType = 'sast', jobName = 'semgrep-sast', jobId = 99): ReportSource {
  const jobWebUrl = `https://gitlab.example.com/group/project/-/jobs/${jobId}`;
  return {
    reportType,
    jobId,
    jobName,
    jobWebUrl,
    downloadUrl: artifactDownloadUrl(jobWebUrl, reportType),
  };
}

/** Builds a report the way the real pipeline does: raw JSON through the parser. */
function report(
  vulnerabilities: unknown[],
  options: { type?: ReportType; jobName?: string; jobId?: number; error?: ReportError } = {},
): ParsedReport {
  const parsed = parseReport(
    { vulnerabilities },
    source(options.type ?? 'sast', options.jobName ?? 'semgrep-sast', options.jobId ?? 99),
  );
  return options.error ? { ...parsed, findings: [], error: options.error } : parsed;
}

function sqlInjection(line: number, extra: Record<string, unknown> = {}) {
  return {
    name: 'Possible SQL injection',
    severity: 'high',
    identifiers: [{ type: 'semgrep_id', name: 'rules.sql-injection', value: 'sql-injection' }],
    location: { file: 'app/db.rb', start_line: line },
    ...extra,
  };
}

function statuses(head: ParsedReport[], base: ParsedReport[]): Record<string, string> {
  const { status } = compareReports(head, base);
  const byName: Record<string, string> = {};
  for (const finding of head.flatMap((r) => r.findings)) {
    byName[`${finding.name}:${finding.startLine ?? ''}`] = status[finding.key];
  }
  return byName;
}

describe('fingerprint', () => {
  it('survives the finding moving to another line', () => {
    const [before] = report([sqlInjection(12)]).findings;
    const [after] = report([sqlInjection(48)]).findings;

    expect(fingerprint(after)).toBe(fingerprint(before));
  });

  it('survives the reporting job being renamed', () => {
    const [before] = report([sqlInjection(12)], { jobName: 'sast', jobId: 1 }).findings;
    const [after] = report([sqlInjection(12)], { jobName: 'semgrep-sast', jobId: 2 }).findings;

    // `key` embeds the job, which is exactly why it cannot be the match key.
    expect(after.key).not.toBe(before.key);
    expect(fingerprint(after)).toBe(fingerprint(before));
  });

  it('separates two occurrences of one rule in different files', () => {
    const [a] = report([sqlInjection(12)]).findings;
    const [b] = report([
      sqlInjection(12, { location: { file: 'app/other.rb', start_line: 12 } }),
    ]).findings;

    expect(fingerprint(a)).not.toBe(fingerprint(b));
  });

  it('ignores the version of a vulnerable dependency', () => {
    const advisory = (version: string) => ({
      name: 'Denial of service in nokogiri',
      severity: 'low',
      identifiers: [{ type: 'cve', name: 'CVE-2022-1234', value: 'CVE-2022-1234' }],
      location: {
        file: 'Gemfile.lock',
        dependency: { package: { name: 'nokogiri' }, version },
      },
    });

    const [before] = report([advisory('1.13.0')], { type: 'dependency_scanning' }).findings;
    const [after] = report([advisory('1.13.4')], { type: 'dependency_scanning' }).findings;

    // A bump that leaves the advisory unresolved has not fixed anything.
    expect(fingerprint(after)).toBe(fingerprint(before));
  });

  it('ignores the image tag in container scanning', () => {
    const vulnerability = (image: string) => ({
      name: 'CVE-2021-1234 in openssl',
      severity: 'critical',
      identifiers: [{ type: 'cve', name: 'CVE-2021-1234', value: 'CVE-2021-1234' }],
      location: { image, dependency: { package: { name: 'openssl' } } },
    });

    const [before] = report([vulnerability('registry.example:5000/team/app:build-41')], {
      type: 'container_scanning',
    }).findings;
    const [after] = report([vulnerability('registry.example:5000/team/app:build-42')], {
      type: 'container_scanning',
    }).findings;

    expect(fingerprint(after)).toBe(fingerprint(before));
    // The registry port is not mistaken for a tag.
    expect(fingerprint(after)).toContain('registry.example:5000/team/app');
  });

  it('ignores the hostname of a per-pipeline review app in DAST', () => {
    const alert = (hostname: string) => ({
      name: 'Missing Content-Security-Policy',
      severity: 'info',
      identifiers: [{ type: 'zap_id', name: '10038', value: '10038' }],
      location: { hostname, path: '/login', param: 'redirect' },
    });

    const [before] = report([alert('https://mr-41.review.example.com')], { type: 'dast' }).findings;
    const [after] = report([alert('https://mr-42.review.example.com')], { type: 'dast' }).findings;

    expect(fingerprint(after)).toBe(fingerprint(before));
  });
});

describe('compareReports', () => {
  it('labels findings the target branch does not have as new', () => {
    const head = [report([sqlInjection(12), { name: 'Hardcoded secret', severity: 'critical' }])];
    const base = [report([sqlInjection(12)])];

    expect(statuses(head, base)).toEqual({
      'Possible SQL injection:12': 'existing',
      'Hardcoded secret:': 'new',
    });
  });

  it('does not report a finding as new because its line moved', () => {
    expect(statuses([report([sqlInjection(48)])], [report([sqlInjection(12)])])).toEqual({
      'Possible SQL injection:48': 'existing',
    });
  });

  it('attributes an added occurrence to the one with no counterpart', () => {
    // Two occurrences existed; the merge request added a third and shifted one.
    const head = [report([sqlInjection(12), sqlInjection(30), sqlInjection(64)])];
    const base = [report([sqlInjection(12), sqlInjection(28)])];

    const result = compareReports(head, base);
    expect(result.newFindings).toHaveLength(1);
    expect(result.existingCount).toBe(2);
    // The unmoved one pairs first, so the addition is the later of the other two.
    expect(result.newFindings[0].startLine).toBe(64);
  });

  it('matches on the report id even when the fingerprint drifted', () => {
    const head = [
      report([{ id: 'a1b2c3', name: 'Renamed rule', severity: 'high', location: { file: 'a.rb' } }]),
    ];
    const base = [
      report([{ id: 'a1b2c3', name: 'Old rule name', severity: 'high', location: { file: 'b.rb' } }]),
    ];

    expect(statuses(head, base)).toEqual({ 'Renamed rule:': 'existing' });
  });

  it('does not let two jobs sharing a finding id collapse into one status', () => {
    // The same id from two jobs is ordinary — GitLab derives it from the finding,
    // not the job. Only one of the two is on the target branch, and the statuses
    // must not overwrite each other on the way into the map.
    const vulnerability = { id: 'a1b2c3', name: 'Shell injection', severity: 'high' };
    const head = [
      report([vulnerability], { jobName: 'sast-app', jobId: 1 }),
      report([vulnerability], { jobName: 'sast-lib', jobId: 2 }),
    ];
    const base = [report([vulnerability], { jobName: 'sast-app', jobId: 3 })];

    const result = compareReports(head, base);
    const [inApp, inLib] = head.map((r) => r.findings[0]);

    expect(result.status[inApp.key]).toBe('existing');
    expect(result.status[inLib.key]).toBe('new');
    expect(result.newFindings).toHaveLength(1);
    expect(result.existingCount).toBe(1);
  });

  it('reports findings the merge request removed as fixed', () => {
    const head = [report([sqlInjection(12)])];
    const base = [report([sqlInjection(12), { name: 'Hardcoded secret', severity: 'critical' }])];

    const { fixed } = compareReports(head, base);
    expect(fixed.map((finding: Finding) => finding.name)).toEqual(['Hardcoded secret']);
  });

  it('calls a report type the base pipeline never ran uncomparable, not new', () => {
    // Secret detection was added by this merge request, so nothing was read that
    // could show its findings already exist on the target branch.
    const head = [report([sqlInjection(12)]), report([{ name: 'AWS key', severity: 'critical' }], { type: 'secret_detection' })];
    const base = [report([sqlInjection(12)])];

    const result = compareReports(head, base);
    expect(result.status[head[1].findings[0].key]).toBe('uncomparable');
    expect(result.newFindings).toHaveLength(0);
    expect(result.uncomparableCount).toBe(1);
  });

  it('calls findings uncomparable when the base artifact expired', () => {
    const head = [report([sqlInjection(12)])];
    const base = [report([], { error: { kind: 'expired', message: 'gone' } })];

    const result = compareReports(head, base);
    expect(result.uncomparableCount).toBe(1);
    expect(result.newFindings).toHaveLength(0);
  });

  it('does not claim a finding is fixed when our own report of that type failed', () => {
    const head = [report([], { error: { kind: 'unavailable', message: 'boom' } })];
    const base = [report([sqlInjection(12)])];

    expect(compareReports(head, base).fixed).toEqual([]);
  });

  describe('while the head pipeline is still running', () => {
    const iacFinding = { name: 'Insecure default', severity: 'medium', location: { file: 'main.tf' } };
    const head = [report([sqlInjection(12)], { jobName: 'semgrep-sast', jobId: 1 })];
    const base = [
      report([sqlInjection(12)], { jobName: 'semgrep-sast', jobId: 3 }),
      report([iacFinding], { jobName: 'iac-sast', jobId: 4 }),
    ];
    const fixedNames = (result: ReturnType<typeof compareReports>) =>
      result.fixed.map((finding: Finding) => finding.name);

    it('does not claim findings of an unfinished job are fixed', () => {
      const result = compareReports(head, base, {
        unfinishedJobs: ['iac-sast'],
        manualJobs: [],
        jobNames: ['semgrep-sast', 'iac-sast'],
        awaitingDownstream: false,
      });

      expect(result.fixed).toEqual([]);
      expect(result.pendingJobs).toEqual(['iac-sast']);
    });

    it('holds back jobs that may be in a downstream pipeline not created yet', () => {
      const result = compareReports(head, base, {
        unfinishedJobs: [],
        manualJobs: [],
        jobNames: ['semgrep-sast', 'trigger-child'],
        awaitingDownstream: true,
      });

      expect(result.fixed).toEqual([]);
      expect(result.pendingJobs).toEqual(['iac-sast']);
    });

    it('still reports fixes once every job is listed and finished', () => {
      // `iac-sast` is gone from the head pipeline altogether, as after a rename;
      // with nothing still running, its findings really are absent.
      const result = compareReports(head, base, {
        unfinishedJobs: [],
        manualJobs: [],
        jobNames: ['semgrep-sast'],
        awaitingDownstream: false,
      });

      expect(fixedNames(result)).toEqual(['Insecure default']);
      expect(result.pendingJobs).toEqual([]);
    });
  });

  it('matches across jobs of the same report type', () => {
    // The base ran one sast job; the head split it into two.
    const head = [
      report([sqlInjection(12)], { jobName: 'semgrep-sast', jobId: 1 }),
      report([{ name: 'Insecure default', severity: 'medium', location: { file: 'main.tf' } }], {
        jobName: 'iac-sast',
        jobId: 2,
      }),
    ];
    const base = [
      report(
        [sqlInjection(12), { name: 'Insecure default', severity: 'medium', location: { file: 'main.tf' } }],
        { jobName: 'sast', jobId: 3 },
      ),
    ];

    expect(compareReports(head, base).newFindings).toEqual([]);
  });

  it('counts new findings by severity', () => {
    const head = [
      report([
        sqlInjection(12),
        { name: 'Hardcoded secret', severity: 'critical' },
        { name: 'Weak hash', severity: 'medium' },
      ]),
    ];
    const base = [report([sqlInjection(12)])];

    const { newCounts } = compareReports(head, base);
    expect(newCounts).toMatchObject({ critical: 1, medium: 1, high: 0, total: 2 });
  });

  it('counts how much of the base was readable', () => {
    // A second sast job on the base whose artifact expired: the type stays
    // comparable, but the comparison is partial and the widget has to say so.
    const head = [report([sqlInjection(12)])];
    const base = [
      report([sqlInjection(12)], { jobName: 'semgrep-sast', jobId: 1 }),
      report([], { jobName: 'iac-sast', jobId: 2, error: { kind: 'expired', message: 'gone' } }),
    ];

    const result = compareReports(head, base);
    expect(result).toMatchObject({ baseReportCount: 2, baseUnreadableCount: 1 });
    expect(result.status[head[0].findings[0].key]).toBe('existing');
  });

  it('treats an empty base report as a clean target branch, not as unknown', () => {
    const head = [report([sqlInjection(12)])];
    const base = [report([])];

    expect(statuses(head, base)).toEqual({ 'Possible SQL injection:12': 'new' });
  });
});
