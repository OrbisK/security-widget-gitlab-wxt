import { describe, expect, it } from 'vitest';
import { parseReport } from './reports';
import { artifactDownloadUrl, dedupeSources } from './gitlab-api';
import type { ReportSource } from './types';

function source(
  reportType: ReportSource['reportType'] = 'sast',
  jobName = 'semgrep-sast',
  jobId = 99,
): ReportSource {
  const jobWebUrl = `https://gitlab.example.com/group/project/-/jobs/${jobId}`;
  return {
    reportType,
    jobId,
    jobName,
    jobWebUrl,
    downloadUrl: artifactDownloadUrl(jobWebUrl, reportType),
  };
}

const blobUrl = (file: string, line?: number) =>
  `/group/project/-/blob/deadbeef/${file}${line ? `#L${line}` : ''}`;

describe('parseReport', () => {
  it('normalizes a current-schema SAST report', () => {
    const report = parseReport(
      {
        version: '15.0.6',
        scan: { type: 'sast', scanner: { id: 'semgrep', name: 'Semgrep' } },
        vulnerabilities: [
          {
            id: 'a1b2c3',
            name: 'Improper neutralization of special elements',
            description: 'User input flows into a shell command.',
            severity: 'Critical',
            solution: 'Use a parameterized API.',
            scanner: { id: 'semgrep', name: 'Semgrep' },
            location: { file: 'app/services/deploy.rb', start_line: 42, end_line: 44 },
            identifiers: [
              { type: 'cwe', name: 'CWE-78', value: '78', url: 'https://cwe.mitre.org/78' },
              { type: 'semgrep_id', value: 'rules.shell-injection' },
            ],
            links: [{ name: 'OWASP', url: 'https://owasp.org/command-injection' }],
          },
        ],
      },
      source(),
      { blobUrl },
    );

    expect(report.scanners).toEqual(['Semgrep']);
    expect(report.findings).toHaveLength(1);

    const [finding] = report.findings;
    expect(finding).toMatchObject({
      reportType: 'sast',
      severity: 'critical',
      name: 'Improper neutralization of special elements',
      file: 'app/services/deploy.rb',
      startLine: 42,
      endLine: 44,
      blobUrl: '/group/project/-/blob/deadbeef/app/services/deploy.rb#L42',
      solution: 'Use a parameterized API.',
      likelyFalsePositive: false,
      // The report's own id is kept for cross-branch matching, but the key it
      // feeds is namespaced by job: GitLab derives that id from the finding, so
      // two jobs scanning one file report the same one.
      reportId: 'a1b2c3',
      key: 'sast:99:0:a1b2c3',
    });
    expect(finding.identifiers).toEqual(['CWE-78', 'SEMGREP_ID-rules.shell-injection']);
    expect(finding.typedIdentifiers).toEqual([
      { type: 'cwe', value: '78' },
      { type: 'semgrep_id', value: 'rules.shell-injection' },
    ]);
    expect(finding.links).toEqual([{ name: 'OWASP', url: 'https://owasp.org/command-injection' }]);
  });

  it('takes the scanner id from the report, then the analyzer, then the finding', () => {
    const scannerIdOf = (raw: object) => parseReport(raw, source()).findings[0].scannerId;
    const vulnerability = { name: 'x', scanner: { id: 'legacy', name: 'Legacy' } };

    expect(
      scannerIdOf({
        scan: { scanner: { id: 'semgrep' }, analyzer: { id: 'semgrep-analyzer' } },
        vulnerabilities: [vulnerability],
      }),
    ).toBe('semgrep');
    expect(
      scannerIdOf({ scan: { analyzer: { id: 'kics' } }, vulnerabilities: [vulnerability] }),
    ).toBe('kics');
    expect(scannerIdOf({ vulnerabilities: [vulnerability] })).toBe('legacy');
    expect(scannerIdOf({ vulnerabilities: [{ name: 'x' }] })).toBeUndefined();
  });

  it('falls back to message and cve on older analyzer output', () => {
    const report = parseReport(
      {
        version: '2.0',
        vulnerabilities: [
          {
            message: 'Possible SQL injection',
            cve: 'app/db.rb:1:abcdef',
            severity: 'HIGH',
            location: { file: 'app/db.rb', start_line: 12 },
          },
        ],
      },
      source(),
    );

    const [finding] = report.findings;
    expect(finding.name).toBe('Possible SQL injection');
    // `message` was consumed as the name, so it is not repeated as description.
    expect(finding.description).toBeUndefined();
    expect(finding.severity).toBe('high');
    // No head sha was supplied, so no repository link is invented.
    expect(finding.blobUrl).toBeUndefined();
  });

  it('maps unrecognized severities to unknown and survives missing fields', () => {
    const report = parseReport({ vulnerabilities: [{}, { severity: 'catastrophic' }] }, source());

    expect(report.findings.map((finding) => finding.severity)).toEqual(['unknown', 'unknown']);
    expect(report.findings.map((finding) => finding.name)).toEqual([
      'Unnamed finding',
      'Unnamed finding',
    ]);
    // Keys stay distinct so Vue's list rendering does not collapse them.
    expect(new Set(report.findings.map((finding) => finding.key)).size).toBe(2);
  });

  it('keeps keys distinct when two jobs report the same finding id', () => {
    // GitLab derives `id` from the finding rather than the job, so two jobs
    // scanning one file — a matrix build over a monorepo — emit the same one. A
    // colliding key would silently overwrite an entry in the comparison's status
    // map and mislabel one of the two findings.
    const vulnerability = { id: 'a1b2c3', name: 'Shell injection', severity: 'high' };
    const [inApp] = parseReport({ vulnerabilities: [vulnerability] }, source('sast', 'sast-app', 1))
      .findings;
    const [inLib] = parseReport({ vulnerabilities: [vulnerability] }, source('sast', 'sast-lib', 2))
      .findings;

    expect(inLib.key).not.toBe(inApp.key);
    // The report's own id is untouched, so cross-branch matching still sees it.
    expect(inLib.reportId).toBe(inApp.reportId);
  });

  it('keeps keys distinct across two report types from one job', () => {
    const vulnerability = { id: 'a1b2c3', name: 'Hardcoded token', severity: 'critical' };
    const [asSast] = parseReport({ vulnerabilities: [vulnerability] }, source('sast')).findings;
    const [asSecret] = parseReport(
      { vulnerabilities: [vulnerability] },
      source('secret_detection'),
    ).findings;

    expect(asSecret.key).not.toBe(asSast.key);
  });

  it('picks up scanner-flagged false positives', () => {
    const report = parseReport(
      {
        vulnerabilities: [
          {
            name: 'Hardcoded password',
            severity: 'Medium',
            flags: [{ type: 'flagged-as-likely-false-positive', description: 'test fixture' }],
          },
        ],
      },
      source('secret_detection'),
    );

    expect(report.findings[0].likelyFalsePositive).toBe(true);
    expect(report.findings[0].reportType).toBe('secret_detection');
  });

  it('describes dependency locations', () => {
    const report = parseReport(
      {
        scan: { type: 'dependency_scanning', analyzer: { name: 'Gemnasium' } },
        vulnerabilities: [
          {
            name: 'Denial of service in nokogiri',
            severity: 'Low',
            location: {
              file: 'Gemfile.lock',
              dependency: { package: { name: 'nokogiri' }, version: '1.13.0' },
            },
          },
        ],
      },
      source('dependency_scanning'),
    );

    expect(report.findings[0].dependency).toBe('nokogiri 1.13.0');
    expect(report.scanners).toEqual(['Gemnasium']);
  });

  it('describes DAST locations that have no file', () => {
    const report = parseReport(
      {
        scan: { type: 'dast' },
        vulnerabilities: [
          {
            name: 'Missing Content-Security-Policy',
            severity: 'Info',
            location: { hostname: 'https://staging.example.com', path: '/login' },
          },
        ],
      },
      source('dast'),
    );

    expect(report.findings[0].file).toBeUndefined();
    expect(report.findings[0].locationLabel).toBe('https://staging.example.com/login');
  });

  it('tolerates a report with no vulnerabilities array at all', () => {
    expect(parseReport({}, source()).findings).toEqual([]);
    expect(parseReport(null, source()).findings).toEqual([]);
  });
});

describe('dedupeSources', () => {
  it('keeps every job that reports the same type', () => {
    // GitLab's IaC scanning and code scanning both declare artifacts:reports:sast.
    const semgrep = source('sast', 'semgrep-sast', 10);
    const kics = source('sast', 'iac-sast', 11);
    const secrets = source('secret_detection', 'secret_detection', 12);

    expect(dedupeSources([semgrep, kics, secrets])).toEqual([semgrep, kics, secrets]);
  });

  it('collapses a job seen twice, as happens via two bridges to one pipeline', () => {
    const job = source('sast', 'semgrep-sast', 10);

    expect(dedupeSources([job, { ...job }])).toEqual([job]);
  });
});

describe('artifactDownloadUrl', () => {
  it('targets the report artifact rather than the archive', () => {
    expect(artifactDownloadUrl('https://gitlab.example.com/g/p/-/jobs/7', 'sast')).toBe(
      'https://gitlab.example.com/g/p/-/jobs/7/artifacts/download?file_type=sast',
    );
  });
});
