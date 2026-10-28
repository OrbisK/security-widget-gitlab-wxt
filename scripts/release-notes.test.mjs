import { describe, expect, it } from 'vitest';
import { toReleaseNotes } from './release-notes.mjs';

const RELEASE_URL = 'https://github.com/OrbisK/security-widget-gitlab-wxt/releases/tag/v0.2.5';

describe('toReleaseNotes', () => {
  it('keeps only the changelog sections of an uppt release body, as plain text', () => {
    const body = [
      '> v0.2.5 is the next patch release.',
      '>',
      '> **Timetable**: to be announced.',
      '',
      '## 👉 Changelog',
      '',
      '[compare changes](https://github.com/OrbisK/security-widget-gitlab-wxt/compare/v0.2.4...release/v0.2.5)',
      '',
      '### 🩹 Fixes',
      '',
      '- set `data_collection_permissions` (#16)',
      '- link the [options page](https://example.com/options)',
      '',
      '### ❤️ Contributors',
      '',
      '- Robin (@OrbisK)',
    ].join('\n');

    expect(toReleaseNotes(body, RELEASE_URL)).toBe(
      [
        '🩹 Fixes',
        '',
        '- set data_collection_permissions (#16)',
        '- link the options page',
        '',
        `Full release notes: ${RELEASE_URL}`,
      ].join('\n'),
    );
  });

  it('handles the body `gh release create --generate-notes` writes', () => {
    const body = [
      "## What's Changed",
      '* fix: something by @OrbisK in https://github.com/OrbisK/security-widget-gitlab-wxt/pull/20',
      '',
      '',
      '**Full Changelog**: https://github.com/OrbisK/security-widget-gitlab-wxt/compare/v0.2.4...v0.2.5',
    ].join('\n');

    expect(toReleaseNotes(body)).toBe(
      [
        "What's Changed",
        '- fix: something by @OrbisK in https://github.com/OrbisK/security-widget-gitlab-wxt/pull/20',
      ].join('\n'),
    );
  });

  it('returns nothing when no changes are listed', () => {
    expect(toReleaseNotes('## 👉 Changelog\n\n[compare changes](https://example.com)\n', RELEASE_URL)).toBe('');
  });
});
