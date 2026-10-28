import {
  isSecurityReportType,
  type PipelineProgress,
  type ReportSource,
  type ReportType,
} from './types';
import { splitRelativeRoot } from './gitlab-page';
import { log, trace } from './debug';

/**
 * All requests here are same-origin and rely on the user's existing
 * `_gitlab_session` cookie, which is why they run in the content script rather
 * than the background worker: a background fetch would be cross-site and
 * GitLab's session cookie would not ride along.
 */
async function fetchJson<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    credentials: 'same-origin',
    headers: { accept: 'application/json' },
  });

  trace('GET', url, '->', response.status, response.headers.get('content-type'));

  if (!response.ok) {
    throw new HttpError(`GET ${url} failed`, response.status, url);
  }

  // A signed-out session or an unexpected route answers with an HTML page, and
  // `response.json()` would fail with an opaque SyntaxError.
  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('json')) {
    throw new Error(`GET ${url} returned ${contentType || 'an unknown content type'}, not JSON`);
  }

  return (await response.json()) as T;
}

export class HttpError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly url: string,
  ) {
    super(`${message} (HTTP ${status})`);
    this.name = 'HttpError';
  }
}

interface CachedWidgetResponse {
  target_project_id?: number;
  diff_head_sha?: string | null;
  pipeline?: { id?: number; path?: string } | null;
}

interface WidgetResponse {
  target_project_full_path?: string;
  source_project_full_path?: string;
  /** Present on EE; a map of report type -> enabled. Purely a hint for us. */
  enabled_reports?: Record<string, boolean>;
}

interface JobArtifact {
  file_type: string;
  filename?: string;
  file_format?: string | null;
  size?: number;
}

interface Job {
  id: number;
  name: string;
  web_url: string;
  status?: string;
  artifacts?: JobArtifact[] | null;
  /** When the job's artifacts are due to be erased; null means they are kept. */
  artifacts_expire_at?: string | null;
}

interface Bridge {
  name?: string;
  status?: string;
  downstream_pipeline?: { id: number; project_id: number } | null;
}

export interface MrInfo {
  pipelineId: number | null;
  pipelineWebUrl?: string;
  diffHeadSha?: string;
  projectId: number;
  projectFullPath: string;
  relativeRoot: string;
  apiBase: string;
  enabledReports?: Record<string, boolean>;
}

/**
 * Resolves the head pipeline plus enough project identity to talk to the REST
 * API. GitLab's internal MR JSON endpoints are used for this because they are
 * reachable purely from the page path, even under a relative URL root — the
 * project's full path they report is what lets us locate `/api/v4`.
 */
export async function fetchMrInfo(pathPrefix: string, iid: number): Promise<MrInfo> {
  const [cached, widget] = await Promise.all([
    fetchJson<CachedWidgetResponse>(`${pathPrefix}/-/merge_requests/${iid}/cached_widget.json`),
    fetchJson<WidgetResponse>(`${pathPrefix}/-/merge_requests/${iid}.json?serializer=widget`),
  ]);

  const projectFullPath = widget.target_project_full_path;
  if (!projectFullPath) {
    throw new Error('Could not determine the project path from the merge request widget data');
  }
  if (!cached.target_project_id) {
    throw new Error('Could not determine the project id from the merge request widget data');
  }

  const { relativeRoot } = splitRelativeRoot(pathPrefix, projectFullPath);
  const pipelineId = cached.pipeline?.id ?? null;

  log('merge request resolved', {
    projectFullPath,
    projectId: cached.target_project_id,
    pipelineId,
    relativeRoot: relativeRoot || '(none)',
    diffHeadSha: cached.diff_head_sha,
    enabledReports: widget.enabled_reports,
  });

  return {
    pipelineId,
    pipelineWebUrl: pipelineId ? `${pathPrefix}/-/pipelines/${pipelineId}` : undefined,
    diffHeadSha: cached.diff_head_sha ?? undefined,
    projectId: cached.target_project_id,
    projectFullPath,
    relativeRoot,
    apiBase: `${relativeRoot}/api/v4`,
    enabledReports: widget.enabled_reports,
  };
}

interface MergeRequestResponse {
  target_branch?: string;
  diff_refs?: { base_sha?: string | null } | null;
}

/** What the comparison needs to locate the target branch's own pipeline. */
export interface MrDiffRefs {
  targetBranch: string;
  /** The merge base: the commit this merge request branched from. */
  baseSha?: string;
}

/**
 * Reads the target branch and merge base from the documented REST endpoint.
 *
 * The internal widget JSON `fetchMrInfo` uses does not carry the merge base, and
 * this is the one part of the chain where guessing is not an option: comparing
 * against the wrong commit would mislabel findings rather than fail visibly.
 */
export async function fetchMrDiffRefs(
  info: Pick<MrInfo, 'apiBase' | 'projectId'>,
  iid: number,
): Promise<MrDiffRefs> {
  const response = await fetchJson<MergeRequestResponse>(
    `${info.apiBase}/projects/${info.projectId}/merge_requests/${iid}`,
  );

  if (!response.target_branch) {
    throw new Error('The merge request API did not report a target branch');
  }

  const refs = {
    targetBranch: response.target_branch,
    baseSha: response.diff_refs?.base_sha ?? undefined,
  };
  log('merge request diff refs', refs);
  return refs;
}

interface Pipeline {
  id: number;
  sha?: string;
  status?: string;
  web_url?: string;
}

/**
 * Only a pipeline that has stopped running can stand in for the target branch.
 * A running one may not have reached its scan jobs yet, and a base with half its
 * findings missing would report the other half as newly introduced.
 *
 * `failed` is kept: a pipeline fails for reasons that have nothing to do with
 * the scan jobs, which may well have completed and uploaded their reports.
 */
const FINISHED_STATUSES = ['success', 'failed'];

/**
 * How deep each base pipeline lookup scans the branch's history.
 *
 * Deliberately not the same knob as how many candidates the caller will *try*
 * (the `maxBasePipelines` setting, whose ceiling this is): this one is a single
 * cheap listing, and it has to look past the running and canceled pipelines that
 * get filtered out below before the caller sees a candidate at all.
 */
const PIPELINE_LOOKUP_PAGE_SIZE = 10;

/**
 * Base pipeline candidates, best first, for the caller to walk until one yields
 * readable reports.
 *
 * The merge base comes first because it is the only apples-to-apples comparison:
 * the target branch as this merge request left it, which is what GitLab's own
 * `base_pipeline` uses. Branches whose merge base has no pipeline at all are
 * common enough — pipelines expire, and not every project builds every commit —
 * that the target branch's latest finished pipeline is worth falling back to,
 * with the caveat that it can contain commits this merge request never saw. The
 * strategy travels with the candidate so the widget can say which it used.
 *
 * Everything here is looked up in the *target* project, which is where the
 * target branch and its pipelines live even when the merge request comes from a
 * fork.
 *
 * Neither lookup failing is fatal — the other may still yield a base — so a
 * failure is reported alongside the candidates rather than thrown. The caller
 * needs it to tell "the branch has no finished pipeline" apart from "we were not
 * allowed to ask", which are the same empty list otherwise.
 */
export async function findBasePipelines(
  info: Pick<MrInfo, 'apiBase' | 'projectId'>,
  refs: MrDiffRefs,
  excludePipelineId: number,
): Promise<BasePipelineSearch> {
  const base =
    `${info.apiBase}/projects/${info.projectId}/pipelines` +
    `?order_by=id&sort=desc&per_page=${PIPELINE_LOOKUP_PAGE_SIZE}`;

  const [atMergeBase, onTargetBranch] = await Promise.all([
    refs.baseSha
      ? lookupPipelines(`${base}&sha=${encodeURIComponent(refs.baseSha)}`)
      : Promise.resolve<PipelineLookup>({ pipelines: [] }),
    lookupPipelines(`${base}&ref=${encodeURIComponent(refs.targetBranch)}`),
  ]);

  const candidates = [
    ...toCandidates(atMergeBase.pipelines, 'merge-base', refs.targetBranch),
    ...toCandidates(onTargetBranch.pipelines, 'target-branch', refs.targetBranch),
  ].filter((candidate) => candidate.pipelineId !== excludePipelineId);

  // First wins: a pipeline both queries return is the merge base, and saying so
  // is the stronger claim of the two.
  const byId = new Map<number, BasePipelineCandidate>();
  for (const candidate of candidates) {
    if (!byId.has(candidate.pipelineId)) byId.set(candidate.pipelineId, candidate);
  }
  const deduped = [...byId.values()];

  log(
    `base pipeline candidates for ${refs.targetBranch}`,
    deduped.map((c) => `${c.pipelineId} (${c.strategy})`),
  );

  // The branch lookup is the one worth naming: the merge base having no pipeline
  // is ordinary, and its failure alone still leaves the fallback intact.
  return { candidates: deduped, failure: onTargetBranch.error ?? atMergeBase.error };
}

export interface BasePipelineSearch {
  candidates: BasePipelineCandidate[];
  /** Why a lookup came back empty, when it failed rather than found nothing. */
  failure?: string;
}

interface PipelineLookup {
  pipelines: Pipeline[];
  error?: string;
}

async function lookupPipelines(url: string): Promise<PipelineLookup> {
  try {
    return { pipelines: await fetchJson<Pipeline[]>(url) };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    log('pipeline lookup failed:', message);
    return { pipelines: [], error: message };
  }
}

export interface BasePipelineCandidate {
  strategy: 'merge-base' | 'target-branch';
  pipelineId: number;
  pipelineWebUrl?: string;
  targetBranch: string;
  sha?: string;
}

function toCandidates(
  pipelines: Pipeline[],
  strategy: BasePipelineCandidate['strategy'],
  targetBranch: string,
): BasePipelineCandidate[] {
  return pipelines
    .filter((pipeline) => FINISHED_STATUSES.includes(pipeline.status ?? ''))
    .map((pipeline) => ({
      strategy,
      pipelineId: pipeline.id,
      pipelineWebUrl: pipeline.web_url,
      targetBranch,
      sha: pipeline.sha,
    }));
}

/**
 * Page size and page cap for the listing endpoints, together the most rows we
 * will read from one: 100 is GitLab's own maximum for `per_page`, and five pages
 * covers a 500-job pipeline. Not a setting — a pipeline large enough to be
 * truncated here is rare enough that guessing at a number is worse than the cap
 * being visible in one place.
 */
const LIST_PAGE_SIZE = 100;
const MAX_LIST_PAGES = 5;

/** Follows `x-next-page` so large pipelines are covered, with a hard page cap. */
async function fetchPaginated<T>(url: string, maxPages = MAX_LIST_PAGES): Promise<T[]> {
  const results: T[] = [];

  for (let page = 1; page <= maxPages; page += 1) {
    const pageUrl = page === 1 ? url : withQuery(url, { page: String(page) });
    const response = await fetch(pageUrl, {
      credentials: 'same-origin',
      headers: { accept: 'application/json' },
    });
    if (!response.ok) {
      throw new HttpError(`GET ${pageUrl} failed`, response.status, pageUrl);
    }
    results.push(...((await response.json()) as T[]));

    if (!response.headers.get('x-next-page')) break;
  }

  return results;
}

function withQuery(url: string, params: Record<string, string>): string {
  const [base, search = ''] = url.split('?');
  const query = new URLSearchParams(search);
  for (const [key, value] of Object.entries(params)) query.set(key, value);
  return `${base}?${query}`;
}

/**
 * Job statuses that mean the job has not run to completion yet, so any report
 * it declares is still to come. `manual` is among them: a scan job nobody has
 * started has not reported anything either.
 */
const UNFINISHED_JOB_STATUSES = [
  'created',
  'waiting_for_resource',
  'preparing',
  'pending',
  'running',
  'canceling',
  'scheduled',
  'manual',
];

function isUnfinished(status: string | undefined): boolean {
  return UNFINISHED_JOB_STATUSES.includes(status ?? '');
}

function emptyProgress(): PipelineProgress {
  return { unfinishedJobs: [], manualJobs: [], jobNames: [], awaitingDownstream: false };
}

export interface DiscoveredSources {
  sources: ReportSource[];
  progress: PipelineProgress;
}

/**
 * Finds every job artifact in the pipeline that holds a security report,
 * following `childDepth` levels of downstream pipelines, along with which jobs
 * have yet to finish — a running pipeline is common on a merge request page, and
 * its unfinished jobs' reports are missing rather than empty.
 *
 * The download URL is built from the job's own `web_url`, so it stays correct
 * for jobs that live in a forked source project or under a relative URL root.
 */
export async function discoverReportSources(
  info: Pick<MrInfo, 'apiBase' | 'projectId'>,
  pipelineId: number,
  childDepth: number,
): Promise<DiscoveredSources> {
  const { sources, progress } = await collectFromPipeline(
    info.apiBase,
    info.projectId,
    pipelineId,
    childDepth,
  );
  const deduped = dedupeSources(sources);

  log(
    `pipeline ${pipelineId}: ${deduped.length} security report artifact(s)`,
    deduped.map((source) => `${source.reportType} (job ${source.jobName}#${source.jobId})`),
  );
  if (progress.unfinishedJobs.length > 0) {
    log(
      `pipeline ${pipelineId} has unfinished jobs:`,
      progress.unfinishedJobs,
      progress.manualJobs.length ? `(waiting to be started: ${progress.manualJobs.join(', ')})` : '',
      progress.awaitingDownstream ? '(and a downstream pipeline is yet to be created)' : '',
    );
  }

  return { sources: deduped, progress };
}

/**
 * More than one job legitimately produces the same report type, so the dedupe
 * key is the job rather than the type: GitLab's IaC scanning (`iac-sast`, KICS)
 * declares `artifacts:reports:sast` exactly like its code scanning
 * (`semgrep-sast`) does, and so does any hand-written scanner job. Keying on the
 * report type kept only whichever job came last and silently dropped the rest.
 *
 * Retried jobs are not a concern here: the pipeline jobs endpoint omits them
 * unless `include_retried=true`. What this does still collapse is the same job
 * seen twice, which happens when two bridges point at one downstream pipeline.
 */
export function dedupeSources(sources: ReportSource[]): ReportSource[] {
  const byJob = new Map<string, ReportSource>();
  for (const source of sources) byJob.set(`${source.jobId}:${source.reportType}`, source);
  return [...byJob.values()];
}

async function collectFromPipeline(
  apiBase: string,
  projectId: number,
  pipelineId: number,
  depthRemaining: number,
): Promise<DiscoveredSources> {
  const jobsUrl =
    `${apiBase}/projects/${projectId}/pipelines/${pipelineId}/jobs?per_page=${LIST_PAGE_SIZE}`;
  const jobs = await fetchPaginated<Job>(jobsUrl);

  // Log every artifact type present, so a report type we failed to recognize is
  // visible rather than silently skipped.
  log(
    `pipeline ${pipelineId}: ${jobs.length} job(s)`,
    jobs.map(
      (job) =>
        `${job.name}#${job.id} [${(job.artifacts ?? []).map((a) => a.file_type).join(',') || 'no artifacts'}]`,
    ),
  );

  const sources: ReportSource[] = [];
  const progress: PipelineProgress = {
    unfinishedJobs: jobs.filter((job) => isUnfinished(job.status)).map((job) => job.name),
    manualJobs: jobs.filter((job) => job.status === 'manual').map((job) => job.name),
    jobNames: jobs.map((job) => job.name),
    awaitingDownstream: false,
  };
  for (const job of jobs) {
    for (const artifact of job.artifacts ?? []) {
      if (!isSecurityReportType(artifact.file_type)) continue;
      sources.push({
        reportType: artifact.file_type,
        jobId: job.id,
        jobName: job.name,
        jobWebUrl: job.web_url,
        downloadUrl: artifactDownloadUrl(job.web_url, artifact.file_type),
        artifactsExpireAt: job.artifacts_expire_at ?? undefined,
      });
    }
  }

  if (depthRemaining > 0) {
    const bridges = await fetchPaginated<Bridge>(
      `${apiBase}/projects/${projectId}/pipelines/${pipelineId}/bridges?per_page=${LIST_PAGE_SIZE}`,
    ).catch(() => [] as Bridge[]);

    // A trigger job creates its downstream pipeline when it runs, so until then
    // there are no jobs to list and nothing to say which reports are coming.
    progress.awaitingDownstream = bridges.some(
      (bridge) => !bridge.downstream_pipeline && isUnfinished(bridge.status),
    );
    // Listed with the jobs, so a manual trigger counts as waiting on someone
    // rather than as running, just as a manual job does.
    for (const bridge of bridges) {
      if (!bridge.name || !isUnfinished(bridge.status)) continue;
      progress.unfinishedJobs.push(bridge.name);
      if (bridge.status === 'manual') progress.manualJobs.push(bridge.name);
    }

    const children = bridges
      .map((bridge) => bridge.downstream_pipeline)
      .filter((pipeline): pipeline is { id: number; project_id: number } => Boolean(pipeline));

    const nested = await Promise.all(
      children.map((child) =>
        collectFromPipeline(apiBase, child.project_id, child.id, depthRemaining - 1).catch(
          (): DiscoveredSources => ({ sources: [], progress: emptyProgress() }),
        ),
      ),
    );
    for (const child of nested) {
      sources.push(...child.sources);
      progress.unfinishedJobs.push(...child.progress.unfinishedJobs);
      progress.manualJobs.push(...child.progress.manualJobs);
      progress.jobNames.push(...child.progress.jobNames);
      progress.awaitingDownstream ||= child.progress.awaitingDownstream;
    }
  }

  return { sources, progress };
}

/**
 * Report-type artifacts are not part of the artifacts archive, so the archive
 * API returns 404 for them. The web download route does serve them, keyed by
 * `file_type` — this is the same route GitLab's own "Download results" button
 * uses.
 */
export function artifactDownloadUrl(jobWebUrl: string, fileType: ReportType): string {
  return `${jobWebUrl.replace(/\/+$/, '')}/artifacts/download?file_type=${fileType}`;
}

/**
 * Report artifacts are stored gzipped. Depending on the instance's storage and
 * proxy setup the browser may or may not have already decompressed them by the
 * time we see the body, so sniff the gzip magic bytes instead of assuming.
 */
export async function downloadReportJson(url: string): Promise<unknown> {
  const response = await fetch(url, { credentials: 'same-origin' });
  if (!response.ok) {
    throw new HttpError(`GET ${url} failed`, response.status, url);
  }

  const bytes = new Uint8Array(await response.arrayBuffer());
  const isGzip = bytes.length > 2 && bytes[0] === 0x1f && bytes[1] === 0x8b;
  const text = isGzip ? await gunzipToText(bytes) : new TextDecoder().decode(bytes);

  log('downloaded report', url, `${bytes.length} bytes`, isGzip ? '(gzip)' : '(plain)');

  return JSON.parse(text);
}

async function gunzipToText(bytes: Uint8Array): Promise<string> {
  if (typeof DecompressionStream === 'undefined') {
    throw new Error('This browser cannot decompress gzipped artifacts');
  }
  const stream = new Blob([bytes as BlobPart])
    .stream()
    .pipeThrough(new DecompressionStream('gzip'));
  return new Response(stream).text();
}
