import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/**
 * Turns a GitHub release body into AMO release notes.
 *
 * AMO shows release notes as plain text (with a handful of inline HTML tags),
 * so the Markdown uppt writes would show up with its `###` and `[text](url)`
 * intact. Only the changelog sections are kept: the "next patch release"
 * preamble, the compare link (it points at the deleted `release/v*` branch) and
 * the contributor list mean nothing on the listing.
 *
 * @param {string} body the release body, as `gh release view --json body` returns it
 * @param {string} [releaseUrl] appended as a pointer to the full notes
 * @returns {string} empty when nothing is left
 */
export function toReleaseNotes(body, releaseUrl) {
  let lines = body.replace(/\r\n/g, '\n').split('\n');

  // uppt puts everything worth keeping under this heading.
  const changelog = lines.findIndex((line) => /^##\s.*changelog/i.test(line));
  if (changelog !== -1) lines = lines.slice(changelog + 1);

  const contributors = lines.findIndex((line) => /^#+\s.*contributors/i.test(line));
  if (contributors !== -1) lines = lines.slice(0, contributors);

  const notes = lines
    .filter((line) => !/^>/.test(line))
    .filter((line) => !/^\[compare changes\]/i.test(line))
    // `gh release create --generate-notes`, used when a tag is dispatched by hand.
    .filter((line) => !/^\*\*Full Changelog\*\*/.test(line))
    .map((line) =>
      line
        .replace(/^#+\s*/, '')
        .replace(/^[*-]\s+/, '- ')
        .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
        .replace(/\*\*|`/g, '')
        .trimEnd(),
    )
    .join('\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();

  if (!notes) return '';
  return releaseUrl ? `${notes}\n\nFull release notes: ${releaseUrl}` : notes;
}

// `node scripts/release-notes.mjs <body.md> [release-url]` prints the notes,
// which `release.yml` hands to `wxt submit` as FIREFOX_RELEASE_NOTES.
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [bodyFile, releaseUrl] = process.argv.slice(2);
  process.stdout.write(toReleaseNotes(readFileSync(bodyFile, 'utf8'), releaseUrl));
}
