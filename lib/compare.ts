import { compareFindings, countBySeverity } from './severity';
import type {
  Comparison,
  Finding,
  FindingStatus,
  ParsedReport,
  PipelineProgress,
  ReportType,
} from './types';

/**
 * Identity of a finding *across branches*, which is a different question from
 * `Finding.key` — that one identifies a finding within a single scan and embeds
 * the job name and the report's own ordering, so a renamed job or a reordered
 * report would break every match.
 *
 * Line numbers are deliberately left out. They shift whenever a file is edited
 * above the finding, and a merge request that edits a file is exactly the case
 * this comparison exists for; including them would report every finding in a
 * touched file as newly introduced.
 *
 * The identifier component is the report's *first* identifier, which is what
 * GitLab itself treats as a finding's primary identifier — the scanner's own
 * rule id in practice, with the classification identifiers (CWE, OWASP) after
 * it. Falls back to the name for reports that carry no identifiers at all.
 */
export function fingerprint(finding: Finding): string {
  return [finding.reportType, primaryIdentifier(finding), locationKey(finding)].join('|');
}

function primaryIdentifier(finding: Finding): string {
  return finding.identifiers[0] ?? finding.name;
}

/**
 * The location component, per report type. Each type reports where a finding
 * lives differently, and each has its own sources of churn between two
 * pipelines that are not a change in the finding itself.
 */
function locationKey(finding: Finding): string {
  switch (finding.reportType) {
    case 'dependency_scanning':
      // Not the version: a bump that leaves the advisory unresolved has not
      // fixed anything, and the identifier already carries the CVE.
      return join(finding.file, finding.packageName);

    case 'container_scanning':
    case 'cluster_image_scanning':
      // The tag moves on every build, so only the repository part is stable.
      return join(imageWithoutTag(finding.image), finding.packageName);

    case 'dast':
    case 'api_fuzzing':
      // The hostname is a per-pipeline review app more often than not, so the
      // request path and parameter are all that carry over.
      return join(finding.path, finding.param) || finding.locationLabel || '';

    default:
      return finding.file ?? finding.locationLabel ?? '';
  }
}

function join(...parts: (string | undefined)[]): string {
  return parts.filter(Boolean).join('@');
}

/** "registry.example:5000/team/app:1.2.3" -> "registry.example:5000/team/app" */
function imageWithoutTag(image: string | undefined): string | undefined {
  if (!image) return undefined;

  const digest = image.indexOf('@');
  const base = digest === -1 ? image : image.slice(0, digest);
  // Only a colon after the last slash is a tag; an earlier one is a registry port.
  const colon = base.indexOf(':', base.lastIndexOf('/') + 1);
  return colon === -1 ? base : base.slice(0, colon);
}

/**
 * Classifies every head finding against the target branch's reports.
 *
 * Two properties this is built around:
 *
 * Matching is per *report type*, not per job. Jobs get renamed and split, and a
 * finding does not become new because the job that reported it did.
 *
 * A report type the base pipeline has nothing readable for yields
 * `uncomparable` rather than `new` — a scanner added by this merge request, or
 * a base artifact that expired, must not make its findings look introduced.
 * `fixed` is withheld symmetrically: base findings of a type this merge
 * request's pipeline no longer reports are dropped rather than claimed as
 * resolved.
 *
 * So are base findings from a job the merge request's pipeline is still
 * running. Matching per type would otherwise read a finished `semgrep-sast`
 * alongside a running `iac-sast` as every IaC finding having been fixed.
 * `progress` describes the head pipeline; leaving it out treats it as finished.
 */
export function compareReports(
  head: ParsedReport[],
  base: ParsedReport[],
  progress?: PipelineProgress,
): Omit<Comparison, 'base'> {
  const comparableTypes = readableTypes(base);
  const headTypes = readableTypes(head);

  const headFindings = head.flatMap((report) => report.findings);
  const baseFindings = base.filter((report) => !report.error).flatMap((report) => report.findings);

  const status: Record<string, FindingStatus> = {};
  const consumed = new Set<Finding>();

  const comparable = headFindings.filter((finding) => {
    if (comparableTypes.has(finding.reportType)) return true;
    status[finding.key] = 'uncomparable';
    return false;
  });

  // Pass one: an identical report id is a definite match, whatever the
  // fingerprints say. Cheap, and it survives an analyzer that changed how it
  // names or locates a finding between the two pipelines.
  const baseById = groupBy(
    baseFindings.filter((finding) => finding.reportId),
    (finding) => `${finding.reportType}:${finding.reportId}`,
  );
  const unmatchedHead = comparable.filter((finding) => {
    if (!finding.reportId) return true;

    const candidate = take(
      baseById.get(`${finding.reportType}:${finding.reportId}`) ?? [],
      (base) => !consumed.has(base),
    );
    if (!candidate) return true;

    consumed.add(candidate);
    status[finding.key] = 'existing';
    return false;
  });

  // Pass two: fingerprints, matched as multisets. Dropping line numbers means
  // several occurrences of one rule in one file share a fingerprint, so what
  // matters is how many the base had, not merely whether it had any.
  const basePool = groupBy(
    baseFindings.filter((finding) => !consumed.has(finding)),
    fingerprint,
  );

  for (const [, group] of groupBy(unmatchedHead, fingerprint)) {
    const pool = basePool.get(fingerprint(group[0])) ?? [];

    // Findings that did not move at all pair up first, so that a group where
    // one of three occurrences was added attributes the addition to the one
    // with no counterpart rather than to whichever came first in the report.
    const moved: Finding[] = [];
    for (const finding of group) {
      const same = take(pool, (candidate) => candidate.startLine === finding.startLine);
      if (!same) {
        moved.push(finding);
        continue;
      }
      consumed.add(same);
      status[finding.key] = 'existing';
    }

    // Whatever is left in the pool is the same finding at a different line.
    byLine(moved);
    byLine(pool);
    for (const finding of moved) {
      const candidate = pool.shift();
      if (!candidate) {
        status[finding.key] = 'new';
        continue;
      }
      consumed.add(candidate);
      status[finding.key] = 'existing';
    }
  }

  const newFindings = headFindings.filter((finding) => status[finding.key] === 'new');
  const pendingJobs = unfinishedBaseJobs(base, progress);
  const fixed = base
    .filter((report) => !report.error && !pendingJobs.includes(report.source.jobName))
    .flatMap((report) => report.findings)
    .filter((finding) => !consumed.has(finding) && headTypes.has(finding.reportType))
    .sort(compareFindings);

  return {
    status,
    fixed,
    newFindings,
    newCounts: countBySeverity(newFindings),
    existingCount: count(status, 'existing'),
    uncomparableCount: count(status, 'uncomparable'),
    baseReportCount: base.length,
    baseUnreadableCount: base.filter((report) => report.error).length,
    pendingJobs,
  };
}

/**
 * Base jobs the head pipeline has yet to finish its own run of: listed and
 * unfinished, or not listed at all while a downstream pipeline that may hold
 * them has still to be created. Matched by name, the only thing two pipelines'
 * runs of one job share.
 */
function unfinishedBaseJobs(base: ParsedReport[], progress: PipelineProgress | undefined): string[] {
  if (!progress) return [];
  const unfinished = new Set(progress.unfinishedJobs);
  const listed = new Set(progress.jobNames);
  const names = base
    .filter((report) => !report.error)
    .map((report) => report.source.jobName)
    .filter((name) => unfinished.has(name) || (progress.awaitingDownstream && !listed.has(name)));
  return [...new Set(names)].sort();
}

/** Report types a set of reports actually delivered findings from, error-free. */
function readableTypes(reports: ParsedReport[]): Set<ReportType> {
  return new Set(reports.filter((report) => !report.error).map((report) => report.reportType));
}

function count(status: Record<string, FindingStatus>, wanted: FindingStatus): number {
  return Object.values(status).filter((value) => value === wanted).length;
}

function groupBy<T>(items: T[], key: (item: T) => string): Map<string, T[]> {
  const groups = new Map<string, T[]>();
  for (const item of items) {
    const group = groups.get(key(item));
    if (group) group.push(item);
    else groups.set(key(item), [item]);
  }
  return groups;
}

/** Removes and returns the first match, so a base finding is only claimed once. */
function take<T>(pool: T[], predicate: (item: T) => boolean): T | null {
  const index = pool.findIndex(predicate);
  return index === -1 ? null : pool.splice(index, 1)[0];
}

function byLine(findings: Finding[]): void {
  findings.sort((a, b) => (a.startLine ?? 0) - (b.startLine ?? 0));
}
