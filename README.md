# Merge Request Security Widget for GitLab

> [!WARNING]
> Early work in progress. It works, and it is not settled: expect breaking changes, no upgrade path
> between versions, and rough edges on GitLab layouts it has not been tried against. It reads your
> reports and renders them — that part is safe by construction — but do not treat what it shows as a
> complete picture of your security posture yet. Bug reports with a `console.debug` trail are welcome.

> [!IMPORTANT]
> This extension is not affiliated, endorsed, sponsored, or approved with or by GitLab Inc.
> GitLab is a trademark of GitLab Inc.

A browser extension that summarizes the security report artifacts your **merge request** pipeline
already produces, on instances where those reports are otherwise reachable only as raw JSON
downloads.

It finds the security report artifacts attached to the merge request's head pipeline, downloads
them with your existing GitLab session, and renders a summary above the merge widget. It then reads
the target branch's own reports the same way, so the findings this merge request *introduces* are
told apart from the ones the branch already had.

## Why

On GitLab Free and Premium, two things are true at once: your pipeline finds vulnerabilities, and
your merge request never mentions them.

[SAST](https://docs.gitlab.com/user/application_security/sast/) and
[pipeline secret detection](https://docs.gitlab.com/user/application_security/secret_detection/pipeline/)
are available in every tier — the templates run, the analyzers report what they find, and the
findings land in a report artifact. Displaying those findings is the separately priced part.
GitLab's own comparison tables put the downloadable JSON report under Free and Premium, and "new
findings in merge request reports" under Ultimate.

So the data is already there and your session can already fetch it; reading it is what costs. A
reviewer has to notice that some job produced an artifact, open that job, download a JSON file, and
read it — once per scanner, on every merge request. At that price nobody does it, and a finding
nobody reads protects nothing. Scanning in CI is only worth the minutes it burns if the results
reach the review, which is exactly where they stop being free.

It shows you what your own pipeline wrote and your own session can already fetch — it adds no data
and unlocks no reports. Scanners whose CI templates are subscription-gated never run in the first
place, so there is nothing for the widget to read; where a scanner does run, its artifact is served
to you by the same route GitLab's own "Download results" button uses.

## Before and after

One Free-tier project, one merge request, one pipeline running SAST and secret detection. The only
difference between the two screenshots is whether the extension is installed — neither is Ultimate.

**Free tier, without the extension** — the pipeline is green and the page says nothing about what
the scanners found. The report artifacts exist, but reaching them means opening the job and
downloading the JSON.

![A merge request on a Free-tier GitLab project without the extension: the merge widget reports a
passed pipeline, and no security findings appear anywhere on the page](.github/assets/before.png)

**Free tier, with the extension** — same project, same pipeline, same session. The findings the
artifacts already contained, grouped by report type and severity, above the merge widget.

![The same Free-tier merge request with the extension installed: a security summary above the merge
widget listing findings by severity, grouped per report type](.github/assets/after.png)

## Install

> [!NOTE]
> No store listing yet, so there is no auto-update — you reinstall to upgrade.

Grab the zip for your browser from the [latest release](../../releases/latest) and load it unpacked:

- **Chrome** — unzip it, then `chrome://extensions` → Developer mode → **Load unpacked**
- **Firefox** — `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on**

`gitlab.com` works immediately. For a self-managed instance, open the extension icon on that
instance and choose **Enable on this instance**, then reload the tab.

## What it shows

Supported report types: SAST, secret detection, dependency scanning, container scanning, cluster
image scanning, DAST, API fuzzing, coverage fuzzing.

Several jobs can declare the same report type, and each gets its own section. GitLab's IaC scanning
(`iac-sast`, KICS) declares `artifacts:reports:sast` exactly as its code scanning (`semgrep-sast`)
does, so both appear, told apart by the analyzer name and job link in the section heading.

Findings can be filtered by severity, scanner-flagged likely false positives hidden, and the number
of findings each section lists before "show more" changed, from the options page.

### Searching findings

A search box above the findings narrows the list for as long as the page is open. It is not stored,
and it only filters the list: the header's summary, colour and counts keep describing every finding,
so a search cannot make a merge request look clean.

```
severity:>=high file:!*.test.ts -scanner:semgrep is:new xss
```

| Term | Matches |
| --- | --- |
| `xss`, `"sql injection"` | name, location, identifiers, scanner or dependency containing the text |
| `severity:high`, `sev:>=high`, `sev:<medium` | a severity, or a range of them (`>=high` is high or worse) |
| `type:sast`, `type:dependency` | report type |
| `file:*.ts`, `file:src/` (alias `path:`) | file, URL path or location label |
| `id:CWE-79`, `id:CVE-2024-*` | identifiers |
| `scanner:semgrep`, `dep:lodash`, `name:secret` | scanner, dependency/package/image, finding name |
| `is:new`, `is:existing`, `is:uncomparable`, `is:fixed`, `is:fp` | comparison status, or flagged as a likely false positive |

Every term has to match. Repeating a key or giving it a comma list (`sev:high,critical`) matches any
of the values. Prefix a term with `-` or its value with `!` to exclude it. Values with `*` or `?` are
globs over the whole field (`*` crosses `/`); anything else matches as a substring, ignoring case.
Terms it cannot use are named under the box and skipped. Keys, and the values of `severity`, `type`
and `is`, are suggested as you type: arrow keys pick one, Tab or Enter completes it, and Esc closes the
suggestions or, once they are closed, clears the search. The search box can be hidden from the options
page.

### New vs. existing findings

The headline is about what the merge request *adds*: `This merge request adds 2 potential
vulnerabilities`, with the pre-existing ones counted on their own row of severity pills and the
findings it removes listed under **Fixed by this merge request**. Each finding carries a `NEW` badge
or none.

The header's colour follows what you can act on, and green means only one thing:

| | |
| --- | --- |
| 🔴 red cross | this merge request introduces findings |
| 🟠 amber | findings are present but none of them are new — still in the code under review, just not this branch's doing |
| 🟢 green check | nothing was found at all |

The comparison names the pipeline it used and links its commit, so the base can be inspected
directly.

The comparison runs after the head pipeline's findings are already on screen, and it needs a
pipeline on the target branch to compare against:

1. the pipeline for the merge base — the commit this merge request branched from, which is what
   GitLab's own comparison uses;
2. failing that, the target branch's latest finished pipeline, which can contain commits this merge
   request never saw.

When neither exists, or its artifacts have expired, the widget says so and labels nothing — a missing
base would make every finding look newly introduced.

Findings are matched on report type, the scanner's own rule identifier, and location **without line
numbers**: a finding does not become new because the lines above it moved, or because the job that
reported it was renamed. Dependency findings ignore the package version and container findings the
image tag, so a bump that leaves the advisory unresolved stays existing. Where the target branch has
no readable report of a type — a scanner this merge request adds, or an expired artifact — its
findings are marked `not compared` rather than counted as new.

Turn the comparison off, hide everything except new findings, or change how far back on the target
branch it looks for a usable pipeline, from the options page.

## How it finds the reports

Report-type artifacts (`artifacts:reports:sast` and friends) are stored separately from the
artifacts archive, so the Job Artifacts API returns `404` for them and they do not appear under
`artifacts:paths`. They *are* served by the web download route, keyed by artifact type — the same
route GitLab's own "Download results" button uses:

```
GET /:namespace/:project/-/jobs/:job_id/artifacts/download?file_type=sast
```

The chain the content script walks:

1. `GET {project}/-/merge_requests/{iid}/cached_widget.json` → head pipeline id, `diff_head_sha`,
   target project id.
2. `GET {project}/-/merge_requests/{iid}.json?serializer=widget` → the project's full path. This
   is what lets us locate `/api/v4` on instances served under a relative URL root.
3. `GET /api/v4/projects/{id}/pipelines/{pipeline}/jobs` → jobs whose `artifacts[].file_type` is a
   security report type. Child pipelines are followed via `.../bridges`, one level deep by default
   and up to three from the options page.
4. `GET {job.web_url}/artifacts/download?file_type={type}` per report. Report artifacts are stored
   gzipped, so the response is gunzipped in the browser when the gzip magic bytes are present.

Then, for the target branch comparison:

5. `GET /api/v4/projects/{id}/merge_requests/{iid}` → `target_branch` and `diff_refs.base_sha`. The
   internal widget JSON does not carry the merge base, and this is the one step where a guess would
   mislabel findings instead of failing visibly.
6. `GET /api/v4/projects/{id}/pipelines?sha={base_sha}` and `?ref={target_branch}`, both newest
   first, keeping only finished pipelines.
7. Steps 3 and 4 again for the first of those candidate pipelines that has readable reports — three
   tried by default, up to ten from the options page, since each one costs a job listing plus a
   download per report it has.

While the page stays open, the widget keeps itself current, every 30 seconds by default (adjustable,
or off, in the options page). While the pipeline runs, steps 1–3 are repeated and only the reports
of jobs that have finished since are downloaded. Once it has finished, only step 1 is repeated, half
as often, to notice a push that starts a new pipeline. Background tabs are not checked. Findings
from a job that is still running are never listed as fixed. The refresh button in the widget does
all of the above at once and also re-reads the target branch.

All requests are same-origin from the content script, which is what makes the `_gitlab_session`
cookie ride along — a background-worker fetch would be cross-site and unauthenticated. Steps 5
onwards address the **target** project, which is where the target branch's pipelines live.

## Permissions and privacy

`gitlab.com` is granted at install time. Self-managed instances are opt-in: open the popup on your
instance and choose **Enable on this instance**, or add it from the options page. That requests an
optional host permission and registers the content script for it at runtime.

> [!NOTE]
> Nothing is sent anywhere — reports are read from your instance and rendered locally.

Request volume per merge request page view is bounded: two widget JSON reads, at most five pages of
100 jobs per pipeline (plus one level of child pipelines), and one download per report artifact
found. A report is downloaded once per job, and the periodic check described above costs two
requests per open merge request tab, plus a job listing while the pipeline is still running.

The target branch comparison adds one merge request read, two pipeline listings, and the same jobs
listing plus per-artifact downloads for the base pipeline it settles on — at most three candidates.
A base pipeline's reports are cached for as long as the tab stays on the instance, so every further
merge request targeting that branch reuses them.

## Troubleshooting

The decision-level trail is always logged at `console.debug`, which Chrome hides behind the
console's **Verbose** level — switch that on and reload. Look for:

| Console output | Meaning |
| --- | --- |
| *(nothing at all)* | The content script never ran. Check the popup's **Diagnostics** section, then **Repair registration**. |
| `content script active on …` | It ran. The next line says what it decided. |
| `inactive: not a merge request page` | The path is not `/-/merge_requests/:iid` — usually a redirect to the sign-in page. |
| `inactive: could not read the merge request widget data: …` | `cached_widget.json` or the widget serializer failed; the message says how. |
| `inactive: this merge request has no head pipeline` | Nothing to scan. |
| `inactive: pipeline N has no security report artifacts` | The preceding line lists every job and its artifact types, so an unrecognized type is visible. Fully erased artifacts drop out of the jobs API, so an old merge request whose artifacts expired lands here. |
| `could not read sast from job X#N: expired — …` | The job still lists the artifact but the download 404s, so the file itself is gone. That report's section says so and the others still render. |
| `inactive: found nothing on the page to attach the widget to` | Every selector in `lib/anchor.ts` missed. |
| `no comparison: …` | The findings render, unlabelled: no pipeline on the target branch could be read. The message says which step gave up, and the widget shows the same reason. |
| `compared with pipeline N (merge-base\|target-branch)` | The comparison succeeded, followed by the new / existing / uncomparable / fixed tally. |

> [!TIP]
> **Settings → Log each step to the page console** adds a line per HTTP request and per downloaded
> artifact on top of that.

## Known limits

- **New-vs-existing is a heuristic, not GitLab's vulnerability database.** GitLab Ultimate tracks a
  finding as a record with a history; this matches two reports against each other on rule identifier
  and location. An analyzer upgrade that renames a rule, or a file that moved, will read as newly
  introduced. It errs that way on purpose — over-reporting a finding as new is safer than passing a
  new one off as pre-existing — which is also why **show only new findings** is off by default.
- The comparison needs a *finished* pipeline on the target branch that still has its report
  artifacts. Projects that only build merge requests, or whose artifacts have expired, get no
  comparison rather than a wrong one.
- Merge-request pipelines on the target branch are not considered as a base; only pipelines for the
  merge base commit and for the branch ref itself.
- Requires the REST API to be reachable at `/api/v4` with your session.
- Only the first 500 jobs of a pipeline are scanned (5 pages of 100).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development setup, how the code is laid out, and the
release process.
