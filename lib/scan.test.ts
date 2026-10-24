import { describe, expect, it } from 'vitest';
import { HttpError } from './gitlab-api';
import { describeDownloadFailure } from './scan';
import type { ReportSource } from './types';

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
