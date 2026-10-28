import {
  discoverReportSources,
  fetchMrDiffRefs,
  fetchMrInfo,
  findBasePipelines,
  downloadReportJson,
  HttpError,
  type BasePipelineCandidate,
  type MrDiffRefs,
  type MrInfo,
} from './gitlab-api';
import { compareReports } from './compare';
import { log } from './debug';
import type { MrPageContext } from './gitlab-page';
import { parseReport } from './reports';
import type { Settings } from './storage';
import { compareFindings, countBySeverity } from './severity';
import {
  SECURITY_REPORT_TYPES,
  type ComparisonState,
  type ParsedReport,
  type PipelineProgress,
  type ReportError,
  type ReportSource,
  type ScanResult,
} from './types';

export interface Discovery {
  info: MrInfo;
  sources: ReportSource[];
  progress: PipelineProgress;
}

export type DiscoveryOutcome =
  /** Not an MR we understand, or it has no pipeline — stay invisible. */
  | { status: 'not-applicable'; reason: string }
  /** A pipeline exists but we could not enumerate its artifacts. Worth showing. */
  | { status: 'error'; message: string }
  | { status: 'found'; discovery: Discovery };

/**
 * Phase one: work out whether this merge request has security reports at all.
 *
 * Split from the download step so the widget can appear with a loading state as
 * soon as we know there is something to show, without flashing on merge
 * requests that have no security scanning.
 *
 * Failures are classified rather than thrown: a merge request whose widget data
 * we cannot read is almost certainly not our business, whereas a pipeline whose
 * jobs we cannot list points at a real problem (API disabled, missing scope)
 * that the user should see.
 */
export async function discoverReports(
  page: MrPageContext,
  settings: Settings,
): Promise<DiscoveryOutcome> {
  let info: MrInfo;
  try {
    info = await fetchMrInfo(page.pathPrefix, page.iid);
  } catch (error) {
    return {
      status: 'not-applicable',
      reason: `could not read the merge request widget data: ${describe(error)}`,
    };
  }

  if (!info.pipelineId) {
    return { status: 'not-applicable', reason: 'this merge request has no head pipeline' };
  }

  try {
    const { sources, progress } = await discoverReportSources(
      info,
      info.pipelineId,
      settings.childPipelineDepth,
    );
    return { status: 'found', discovery: { info, sources, progress } };
  } catch (error) {
    return {
      status: 'error',
      message: `Could not list the pipeline's job artifacts: ${describe(error)}`,
    };
  }
}

function describe(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Turns a failed artifact download into something worth reading.
 *
 * A 404 here is usually an expired artifact: we only ask for URLs the jobs API
 * just listed, and GitLab erases the file while the job itself stays. The list
 * can also simply be stale — artifacts erased between the listing and the
 * download, or unlocked by a newer pipeline mid-session — so the wording is
 * hedged unless `artifacts_expire_at` is a date that has actually passed.
 *
 * A 404 for an artifact whose expiry is still ahead is not expiry, though.
 * GitLab answers 404 rather than 403 when the user may see the job but not its
 * artifacts (`artifacts:access`, or a public project restricting artifacts to
 * members), so that case is reported as unavailable rather than waved off.
 */
export function describeDownloadFailure(error: unknown, source: ReportSource, now: Date): ReportError {
  if (!(error instanceof HttpError) || error.status !== 404) {
    return { kind: 'unavailable', message: describe(error) };
  }

  if (futureExpiry(source.artifactsExpireAt, now)) {
    return {
      kind: 'unavailable',
      message:
        'The report artifact has not expired but could not be downloaded — your account may not have access to job artifacts in this project.',
    };
  }

  const expiredOn = pastExpiry(source.artifactsExpireAt, now);
  return {
    kind: 'expired',
    message: expiredOn
      ? `The report artifact expired on ${expiredOn} and is no longer stored.`
      : 'The report artifact is no longer available — it has most likely expired.',
  };
}

/** True only if `artifacts_expire_at` parses and is still in the future. */
function futureExpiry(value: string | undefined, now: Date): boolean {
  if (!value) return false;
  const at = new Date(value);
  return !Number.isNaN(at.getTime()) && at.getTime() > now.getTime();
}

/** Formats `artifacts_expire_at` only if it parses and is in the past. */
function pastExpiry(value: string | undefined, now: Date): string | null {
  if (!value) return null;
  const at = new Date(value);
  if (Number.isNaN(at.getTime()) || at.getTime() > now.getTime()) return null;
  return at.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

/**
 * Phase two: download and normalize each report.
 *
 * A failure to read one report does not fail the scan — that report carries an
 * `error` and the others are still shown.
 */
export async function loadReports(
  page: MrPageContext,
  { info, sources, progress }: Discovery,
): Promise<ScanResult> {
  const reports = sortReports(
    await downloadReports(sources, blobUrlBuilder(page, info.diffHeadSha)),
  );

  const findings = reports.flatMap((report) => report.findings).sort(compareFindings);

  return {
    reports,
    findings,
    counts: countBySeverity(findings),
    pipelineId: info.pipelineId!,
    pipelineWebUrl: info.pipelineWebUrl,
    progress,
    // Filled in by phase three, which runs once these are already on screen.
    comparison: { status: 'loading' },
  };
}

/** Downloads and parses each source; a failure becomes that report's `error`. */
async function downloadReports(
  sources: ReportSource[],
  blobUrl: BlobUrlBuilder | undefined,
): Promise<ParsedReport[]> {
  return Promise.all(
    sources.map(async (source): Promise<ParsedReport> => {
      try {
        const raw = await downloadReportJson(source.downloadUrl);
        return parseReport(raw, source, { blobUrl });
      } catch (cause) {
        const failure = describeDownloadFailure(cause, source, new Date());
        log(
          `could not read ${source.reportType} from job ${source.jobName}#${source.jobId}:`,
          `${failure.kind} —`,
          failure.message,
        );
        return {
          reportType: source.reportType,
          source,
          scanners: [],
          findings: [],
          error: failure,
        };
      }
    }),
  );
}

/**
 * Group by report type, then by job name so the several jobs that can share a
 * type (semgrep-sast and iac-sast, say) keep a stable order between reloads.
 */
function sortReports(reports: ParsedReport[]): ParsedReport[] {
  return reports.sort((a, b) => {
    const byType =
      SECURITY_REPORT_TYPES.indexOf(a.reportType) - SECURITY_REPORT_TYPES.indexOf(b.reportType);
    return byType !== 0 ? byType : a.source.jobName.localeCompare(b.source.jobName);
  });
}

type BlobUrlBuilder = (file: string, line?: number) => string | undefined;

function blobUrlBuilder(page: MrPageContext, sha: string | undefined): BlobUrlBuilder | undefined {
  if (!sha) return undefined;
  return (file, line) => buildBlobUrl(page.pathPrefix, sha, file, line);
}

/**
 * Base reports keyed by `projectId:pipelineId`.
 *
 * Every merge request targeting one branch compares against the same pipeline,
 * and soft navigation between merge requests keeps this content script alive, so
 * the second one is free. Reports for a finished pipeline do not change.
 */
const baseReportCache = new Map<string, Promise<ParsedReport[]>>();

/**
 * How many pipelines' base reports stay in memory. Not a setting: it is a
 * per-tab memory bound with no effect a reader would notice beyond one extra
 * fetch after switching between more merge requests than this.
 */
const BASE_CACHE_LIMIT = 8;

/**
 * Phase three: work out which of the head pipeline's findings the target branch
 * already had.
 *
 * Deliberately fallible and deliberately last. It costs a second pipeline's
 * worth of requests, so it runs after the findings are on screen; and when no
 * base can be established it returns `unavailable` with a reason rather than
 * labelling anything, because a missing base makes every finding look new.
 */
export async function loadComparison(
  page: MrPageContext,
  info: MrInfo,
  head: ScanResult,
  settings: Settings,
): Promise<ComparisonState> {
  let refs: MrDiffRefs;
  try {
    refs = await fetchMrDiffRefs(info, page.iid);
  } catch (error) {
    return {
      status: 'unavailable',
      reason: `could not read the merge request's target branch: ${describe(error)}`,
    };
  }

  const { candidates, failure } = await findBasePipelines(info, refs, head.pipelineId);

  if (candidates.length === 0) {
    // A failed lookup and a branch with no pipeline are the same empty list, and
    // only one of them is a statement about the branch.
    return {
      status: 'unavailable',
      reason: failure
        ? `could not list the pipelines on ${refs.targetBranch}: ${failure}`
        : `${refs.targetBranch} has no finished pipeline to compare against`,
    };
  }

  for (const candidate of candidates.slice(0, settings.maxBasePipelines)) {
    let reports: ParsedReport[];
    try {
      reports = await loadBaseReports(page, info, candidate, settings);
    } catch (error) {
      log(`base pipeline ${candidate.pipelineId} could not be read:`, describe(error));
      continue;
    }

    // No security artifacts at all, or none of them readable: this pipeline
    // cannot stand in for the target branch, so try an older one.
    if (reports.length === 0 || reports.every((report) => report.error)) {
      log(`base pipeline ${candidate.pipelineId} has no readable security reports`);
      continue;
    }

    const comparison = {
      base: {
        ...candidate,
        commitWebUrl: candidate.sha
          ? `${page.pathPrefix}/-/commit/${candidate.sha}`
          : undefined,
      },
      ...compareReports(head.reports, reports, head.progress),
    };
    log(
      `compared with pipeline ${candidate.pipelineId} (${candidate.strategy})`,
      `${comparison.newCounts.total} new, ${comparison.existingCount} existing,`,
      `${comparison.uncomparableCount} uncomparable, ${comparison.fixed.length} fixed`,
      comparison.pendingJobs.length ? `(fixes not checked for ${comparison.pendingJobs.join(', ')})` : '',
    );
    return { status: 'ready', comparison };
  }

  return {
    status: 'unavailable',
    reason:
      candidates.length > settings.maxBasePipelines
        ? `none of the last ${settings.maxBasePipelines} pipelines on ${refs.targetBranch} has readable security reports`
        : `no pipeline on ${refs.targetBranch} has readable security reports`,
  };
}

function loadBaseReports(
  page: MrPageContext,
  info: MrInfo,
  candidate: BasePipelineCandidate,
  settings: Settings,
): Promise<ParsedReport[]> {
  // The depth is part of the key: raising it is a request to look somewhere the
  // cached entry never looked.
  const key = `${info.projectId}:${candidate.pipelineId}:${settings.childPipelineDepth}`;
  const cached = baseReportCache.get(key);
  if (cached) {
    // Re-inserted so eviction below drops the least recently used rather than
    // the oldest, which would be the branch the reader keeps coming back to.
    baseReportCache.delete(key);
    baseReportCache.set(key, cached);
    return cached;
  }

  const pending = (async () => {
    // Candidates are finished pipelines, so their progress has nothing to add.
    const { sources } = await discoverReportSources(
      info,
      candidate.pipelineId,
      settings.childPipelineDepth,
    );
    if (sources.length === 0) return [];
    // Links in the fixed-findings list point at the base commit, where those
    // findings still are.
    return sortReports(await downloadReports(sources, blobUrlBuilder(page, candidate.sha)));
  })();

  // A rejection is not worth remembering; a reload should be able to retry.
  pending.catch(() => baseReportCache.delete(key));

  if (baseReportCache.size >= BASE_CACHE_LIMIT) {
    baseReportCache.delete(baseReportCache.keys().next().value!);
  }
  baseReportCache.set(key, pending);

  return pending;
}

function buildBlobUrl(
  pathPrefix: string,
  sha: string,
  file: string,
  line: number | undefined,
): string {
  // Encode each path segment but keep the separators intact.
  const encoded = file
    .replace(/^\/+/, '')
    .split('/')
    .map((segment) => encodeURIComponent(segment))
    .join('/');
  const anchor = line ? `#L${line}` : '';
  return `${pathPrefix}/-/blob/${sha}/${encoded}${anchor}`;
}
