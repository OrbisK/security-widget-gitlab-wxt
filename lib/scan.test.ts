import { afterEach, describe, expect, it, vi } from 'vitest';
import { HttpError, type MrInfo } from './gitlab-api';
import {
  describeDownloadFailure,
  discoveryChanged,
  rediscoverReports,
  type Discovery,
} from './scan';
import { DEFAULT_SETTINGS } from './storage';
import type { PipelineProgress, ReportSource } from './types';

const NOW = new Date('2026-07-30T12:00:00Z');

function source(overrides: Partial<ReportSource> = {}): ReportSource {
  return {
    reportType: 'sast',
    jobId: 42,
    jobName: 'semgrep-sast',
    jobWebUrl: 'https://gitlab.example/group/proj/-/jobs/42',
    downloadUrl: 'https://gitlab.example/group/proj/-/jobs/42/artifacts/download?file_type=sast',
    ...overrides,
  };
}

function fail(status: number, url = 'https://gitlab.example/x'): HttpError {
  return new HttpError(`GET ${url} failed`, status, url);
}

describe('describeDownloadFailure', () => {
  it('names the date when the job says the artifact has already expired', () => {
    const error = describeDownloadFailure(
      fail(404),
      source({ artifactsExpireAt: '2026-07-01T00:00:00Z' }),
      NOW,
    );

    expect(error.kind).toBe('expired');
    expect(error.message).toMatch(/expired on .+ and is no longer stored/);
    expect(error.message).toContain('2026');
  });

  it('hedges on a 404 with no expiry timestamp', () => {
    const error = describeDownloadFailure(fail(404), source(), NOW);

    expect(error).toEqual({
      kind: 'expired',
      message: 'The report artifact is no longer available — it has most likely expired.',
    });
  });

  // A future expiry means the file should still be there, so the 404 is
  // something else — typically artifacts restricted to project members.
  it('reports a 404 before the expiry date as unavailable, not expired', () => {
    const error = describeDownloadFailure(
      fail(404),
      source({ artifactsExpireAt: '2026-12-01T00:00:00Z' }),
      NOW,
    );

    expect(error.kind).toBe('unavailable');
    expect(error.message).toMatch(/has not expired/);
    expect(error.message).toMatch(/access/);
  });

  it('hedges when the expiry timestamp is unparseable', () => {
    const error = describeDownloadFailure(fail(404), source({ artifactsExpireAt: 'never' }), NOW);

    expect(error.kind).toBe('expired');
    expect(error.message).not.toMatch(/expired on/);
  });

  it.each([403, 500, 502])('reports HTTP %i as unavailable, not expired', (status) => {
    const error = describeDownloadFailure(fail(status), source(), NOW);

    expect(error.kind).toBe('unavailable');
    expect(error.message).toContain(`HTTP ${status}`);
  });

  it('passes through a non-HTTP failure such as malformed JSON', () => {
    const error = describeDownloadFailure(new SyntaxError('Unexpected token <'), source(), NOW);

    expect(error).toEqual({ kind: 'unavailable', message: 'Unexpected token <' });
  });

  it('stringifies a thrown non-Error', () => {
    expect(describeDownloadFailure('boom', source(), NOW)).toEqual({
      kind: 'unavailable',
      message: 'boom',
    });
  });
});

function discovery(
  overrides: { pipelineId?: number; sources?: ReportSource[]; progress?: Partial<PipelineProgress> } = {},
): Discovery {
  const info: MrInfo = {
    pipelineId: overrides.pipelineId ?? 7,
    projectId: 3,
    projectFullPath: 'group/proj',
    relativeRoot: '',
    apiBase: '/api/v4',
  };
  return {
    info,
    sources: overrides.sources ?? [source()],
    progress: {
      unfinishedJobs: [],
      manualJobs: [],
      jobNames: ['semgrep-sast'],
      awaitingDownstream: false,
      ...overrides.progress,
    },
  };
}

describe('discoveryChanged', () => {
  it('ignores a discovery that found the same thing', () => {
    expect(discoveryChanged(discovery(), discovery())).toBe(false);
  });

  it('notices a new head pipeline', () => {
    expect(discoveryChanged(discovery(), discovery({ pipelineId: 8 }))).toBe(true);
  });

  it('notices a job that finished and uploaded its report', () => {
    const running = discovery({ progress: { unfinishedJobs: ['iac-sast'] } });
    const finished = discovery({
      sources: [source(), source({ jobId: 43, jobName: 'iac-sast' })],
    });

    expect(discoveryChanged(running, finished)).toBe(true);
  });

  it('notices a job that finished without a report', () => {
    const running = discovery({ progress: { unfinishedJobs: ['iac-sast'] } });

    expect(discoveryChanged(running, discovery())).toBe(true);
  });
});

describe('rediscoverReports', () => {
  const page = { pathPrefix: '/group/proj', iid: 5 };

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  /** Answers the merge request widget data with `pipelineId` as the head pipeline. */
  function stubMergeRequest(pipelineId: number): string[] {
    const seen: string[] = [];
    vi.stubGlobal('fetch', async (url: string) => {
      seen.push(url);
      const body = url.includes('cached_widget.json')
        ? { target_project_id: 3, pipeline: { id: pipelineId } }
        : url.includes('serializer=widget')
          ? { target_project_full_path: 'group/proj' }
          : [];
      return new Response(JSON.stringify(body), {
        headers: { 'content-type': 'application/json' },
      });
    });
    return seen;
  }

  it('lists nothing again for a finished pipeline that is still the head', async () => {
    const seen = stubMergeRequest(7);
    const previous = discovery();

    const outcome = await rediscoverReports(page, DEFAULT_SETTINGS, previous);

    expect(outcome).toEqual({ status: 'found', discovery: previous });
    expect(seen.some((url) => url.includes('/jobs'))).toBe(false);
  });

  it('lists the jobs of a new head pipeline', async () => {
    const seen = stubMergeRequest(8);

    const outcome = await rediscoverReports(page, DEFAULT_SETTINGS, discovery());

    expect(outcome.status === 'found' && outcome.discovery.info.pipelineId).toBe(8);
    expect(seen.some((url) => url.includes('/pipelines/8/jobs'))).toBe(true);
  });

  it('lists the jobs again while the pipeline is running', async () => {
    const seen = stubMergeRequest(7);

    await rediscoverReports(page, DEFAULT_SETTINGS, discovery({ progress: { unfinishedJobs: ['iac-sast'] } }));

    expect(seen.some((url) => url.includes('/pipelines/7/jobs'))).toBe(true);
  });
});
