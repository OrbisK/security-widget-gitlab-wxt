import { normalizeSeverity } from './severity';
import type { Finding, ParsedReport, ReportSource } from './types';

/**
 * Shape of the GitLab security report schema, as far as we care about it.
 * Kept loose on purpose: schema versions 2 through 15 all flow through here and
 * older analyzers fill in `message`/`cve` where newer ones use `name`.
 */
interface RawReport {
  version?: string;
  scan?: {
    type?: string;
    scanner?: { id?: string; name?: string; version?: string };
    analyzer?: { id?: string; name?: string };
  };
  vulnerabilities?: RawVulnerability[];
}

interface RawVulnerability {
  id?: string;
  name?: string;
  message?: string;
  description?: string;
  cve?: string;
  severity?: string;
  solution?: string;
  scanner?: { id?: string; name?: string };
  location?: RawLocation;
  identifiers?: { type?: string; name?: string; value?: string; url?: string }[];
  links?: { name?: string; url?: string }[];
  flags?: { type?: string; description?: string }[];
}

interface RawLocation {
  file?: string;
  start_line?: number;
  end_line?: number;
  class?: string;
  method?: string;
  dependency?: {
    package?: { name?: string };
    version?: string;
  };
  image?: string;
  operating_system?: string;
  hostname?: string;
  path?: string;
  param?: string;
}

export interface ParseContext {
  /** Builds a repository link for a reported file, when the head sha is known. */
  blobUrl?: (file: string, line?: number) => string | undefined;
}

export function parseReport(
  raw: unknown,
  source: ReportSource,
  context: ParseContext = {},
): ParsedReport {
  const report = (raw ?? {}) as RawReport;
  const vulnerabilities = Array.isArray(report.vulnerabilities) ? report.vulnerabilities : [];

  const scanners = new Set<string>();
  const reportScanner = report.scan?.scanner?.name ?? report.scan?.analyzer?.name;
  if (reportScanner) scanners.add(reportScanner);

  const reportScannerId = firstNonEmpty(report.scan?.scanner?.id, report.scan?.analyzer?.id);

  const findings = vulnerabilities.map((vulnerability, index) => {
    const finding = toFinding(vulnerability, source, index, context, reportScannerId);
    if (finding.scanner) scanners.add(finding.scanner);
    return finding;
  });

  return {
    reportType: source.reportType,
    source,
    scanners: [...scanners],
    findings,
  };
}

function toFinding(
  raw: RawVulnerability,
  source: ReportSource,
  index: number,
  context: ParseContext,
  reportScannerId: string | undefined,
): Finding {
  const location = raw.location ?? {};
  const file = location.file || undefined;
  const startLine = numberOrUndefined(location.start_line);

  const name =
    firstNonEmpty(raw.name, raw.message, raw.cve, describeIdentifiers(raw)) ?? 'Unnamed finding';

  const description = firstNonEmpty(
    raw.description,
    // Only fall back to `message` when it is not already doing duty as the name.
    raw.message === name ? undefined : raw.message,
  );

  return {
    reportType: source.reportType,
    severity: normalizeSeverity(raw.severity),
    name,
    description,
    scanner: raw.scanner?.name || undefined,
    // The report-level id wins: newer schemas dropped the per-finding scanner,
    // which only older analyzers still fill in.
    scannerId: reportScannerId ?? firstNonEmpty(raw.scanner?.id),
    file,
    startLine,
    endLine: numberOrUndefined(location.end_line),
    blobUrl: file ? context.blobUrl?.(file, startLine) : undefined,
    identifiers: (raw.identifiers ?? [])
      .map((identifier) => identifier.name || joinIdentifier(identifier))
      .filter((value): value is string => Boolean(value)),
    typedIdentifiers: (raw.identifiers ?? []).flatMap(({ type, value }) =>
      type && value ? [{ type, value }] : [],
    ),
    solution: firstNonEmpty(raw.solution),
    links: (raw.links ?? [])
      .filter((link): link is { name?: string; url: string } => Boolean(link.url))
      .map((link) => ({ name: link.name, url: link.url })),
    dependency: describeDependency(location),
    locationLabel: file ? undefined : describeGenericLocation(location),
    packageName: location.dependency?.package?.name || undefined,
    image: location.image || undefined,
    path: location.path || undefined,
    param: location.param || undefined,
    likelyFalsePositive: (raw.flags ?? []).some(
      (flag) => flag.type === 'flagged-as-likely-false-positive',
    ),
    reportId: raw.id || undefined,
    // Unique within one scan, which is what the job, the report type and the
    // finding's index in its report are here to guarantee: `raw.id` alone does
    // not, because GitLab derives it from the finding rather than the job, so
    // two jobs scanning one file report the same id — and one job can carry
    // artifacts of two report types. A colliding key would silently overwrite an
    // entry in the comparison's status map.
    //
    // Deliberately not used to match across branches: it embeds the job and the
    // report ordering, either of which can differ between two pipelines. See
    // `fingerprint` in lib/compare.ts.
    key: `${source.reportType}:${source.jobId}:${index}:${
      raw.id || `${file ?? ''}:${startLine ?? ''}:${name}`
    }`,
  };
}

function describeDependency(location: RawLocation): string | undefined {
  const name = location.dependency?.package?.name;
  if (!name) return undefined;
  const version = location.dependency?.version;
  return version ? `${name} ${version}` : name;
}

function describeGenericLocation(location: RawLocation): string | undefined {
  // DAST reports a URL rather than a file; container scanning reports an image.
  if (location.hostname || location.path) {
    return [location.hostname, location.path].filter(Boolean).join('');
  }
  return firstNonEmpty(location.image, location.operating_system);
}

function describeIdentifiers(raw: RawVulnerability): string | undefined {
  return raw.identifiers?.map((identifier) => identifier.name).find(Boolean) ?? undefined;
}

function joinIdentifier(identifier: { type?: string; value?: string }): string | undefined {
  if (!identifier.type || !identifier.value) return undefined;
  return `${identifier.type.toUpperCase()}-${identifier.value}`;
}

function firstNonEmpty(...values: (string | undefined | null)[]): string | undefined {
  for (const value of values) {
    const trimmed = value?.trim();
    if (trimmed) return trimmed;
  }
  return undefined;
}

function numberOrUndefined(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}
