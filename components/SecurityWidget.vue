<script setup lang="ts">
import { computed, ref, shallowRef, useId, useTemplateRef, watch } from 'vue';
import FindingItem from './FindingItem.vue';
import SeverityPills from './SeverityPills.vue';
import {
  compileQuery,
  QUERY_HELP,
  selectedSeverities,
  selectedStatuses,
  suggest,
  toggleSeverity,
  toggleStatuses,
  type Suggestion,
} from '@/lib/query';
import { countBySeverity, severityRank } from '@/lib/severity';
import type { Settings } from '@/lib/storage';
import {
  isRunning,
  REPORT_TYPE_LABELS,
  type Comparison,
  type Finding,
  type FindingStatus,
  type ParsedReport,
  type Severity,
  type WidgetState,
} from '@/lib/types';

const props = defineProps<{
  state: WidgetState;
  settings: Settings;
  /** Prefills the search box; lets a server-rendered test see a filtered list. */
  initialQuery?: string;
  /** A refresh the user asked for is in flight. */
  refreshing?: boolean;
}>();

const emit = defineEmits<{
  /** Read the pipeline and the target branch again. */
  refresh: [];
}>();

const FIXED_KEY = 'fixed';
/** Enough of a commit sha to identify it, which is what GitLab itself shows. */
const SHORT_SHA_LENGTH = 8;

const pageSize = computed(() => props.settings.findingsPerPage);

const collapsed = shallowRef(props.settings.startCollapsed);
const shown = ref<Record<string, number>>({});
/** Lives only as long as the page: a search is a question, not a preference. */
const query = shallowRef(props.initialQuery ?? '');
const compiledQuery = computed(() => compileQuery(query.value));

/** What the pills highlight: the severities the search is narrowed to. */
const severitySelection = computed(() => selectedSeverities(query.value));
/** …and the row labels: the statuses it is narrowed to with `is:`. */
const statusSelection = computed(() => selectedStatuses(query.value));

/** A pill click edits the search, and opens the list so its effect is seen. */
function onToggleSeverity(severity: Severity): void {
  query.value = toggleSeverity(query.value, severity);
  collapsed.value = false;
}

function onToggleStatuses(statuses: FindingStatus[]): void {
  query.value = toggleStatuses(query.value, statuses);
  collapsed.value = false;
}

const searchInput = useTemplateRef<HTMLInputElement>('searchInput');
const suggestionsId = useId();
/** Where the cursor is, which decides which term is being completed. */
const cursor = shallowRef(0);
/** Closed by Esc or blur, reopened by typing. */
const suggesting = shallowRef(false);
const activeSuggestion = shallowRef(0);

const suggestions = computed(() =>
  suggesting.value ? suggest(query.value, cursor.value) : { from: 0, items: [] },
);

watch(suggestions, () => {
  activeSuggestion.value = 0;
});

function syncCursor(): void {
  cursor.value = searchInput.value?.selectionStart ?? query.value.length;
}

function onSearchInput(): void {
  syncCursor();
  suggesting.value = true;
}

/**
 * Edits the input in place, which also leaves the cursor after the insertion,
 * and then takes the model from it — so Vue finds nothing to write back and
 * the cursor stays put.
 */
function pickSuggestion(item: Suggestion): void {
  const input = searchInput.value;
  if (!input) return;
  input.setRangeText(item.insert, suggestions.value.from, cursor.value, 'end');
  query.value = input.value;
  syncCursor();
}

function onSearchKeydown(event: KeyboardEvent): void {
  const { items } = suggestions.value;
  if (event.key === 'Escape') {
    // First Esc closes the suggestions, the next one clears the search.
    if (items.length) suggesting.value = false;
    else query.value = '';
    return;
  }
  if (!items.length) return;
  if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
    event.preventDefault();
    const step = event.key === 'ArrowDown' ? 1 : -1;
    activeSuggestion.value = (activeSuggestion.value + step + items.length) % items.length;
  } else if (event.key === 'Enter' || event.key === 'Tab') {
    event.preventDefault();
    pickSuggestion(items[activeSuggestion.value]);
  }
}

/** Reports keep their own findings so each section can be filtered and paged. */
interface ReportSection {
  /** Per-job, not per-type: several jobs can report the same type. */
  key: string;
  report: ParsedReport;
  label: string;
  findings: Finding[];
  hiddenByFilter: number;
}

const result = computed(() => (props.state.status === 'ok' ? props.state.result : null));

/** The comparison, once it has one to show. Null in every other state. */
const comparison = computed<Comparison | null>(() =>
  result.value?.comparison.status === 'ready' ? result.value.comparison.comparison : null,
);

const targetBranch = computed(() => comparison.value?.base.targetBranch);

/**
 * The scan jobs still running, when that can be told: the comparison knows which
 * jobs reported on the target branch, and so which unfinished jobs here are
 * scans rather than a deploy. Manual ones are left out — they are not running,
 * and may never be. Null without a comparison to say.
 */
const runningScans = computed(() => {
  if (!comparison.value || !result.value) return null;
  const manual = new Set(result.value.progress.manualJobs);
  return comparison.value.pendingJobs.filter((name) => !manual.has(name));
});

/**
 * Some scan jobs may still report. What is on screen is real, but an empty list
 * is not yet a clean bill of health. Without a comparison, any job still running
 * might be a scan.
 */
const running = computed(() => {
  if (runningScans.value) return runningScans.value.length > 0;
  return result.value ? isRunning(result.value.progress) : false;
});

/**
 * A finding with no entry in the map reads as `uncomparable` rather than
 * `existing`, which keeps the failure mode on the side of overstating rather than
 * hiding. Keys are unique within a scan (see `lib/reports.ts`), so this is only
 * reachable if the comparison and the reports on screen came from different ones.
 */
function statusOf(finding: Finding): FindingStatus | undefined {
  if (!comparison.value) return undefined;
  return comparison.value.status[finding.key] ?? 'uncomparable';
}

function isNew(finding: Finding): boolean {
  return statusOf(finding) === 'new';
}

function passesSeverityFilter(finding: Finding): boolean {
  if (props.settings.hideLikelyFalsePositives && finding.likelyFalsePositive) return false;
  return severityRank(finding.severity) <= severityRank(props.settings.minSeverity);
}

function keepFinding(finding: Finding): boolean {
  if (!passesSeverityFilter(finding)) return false;
  // Findings that could not be compared stay visible: hiding them would pass
  // "unknown" off as "already on the target branch".
  if (props.settings.showOnlyNew && statusOf(finding) === 'existing') return false;
  return true;
}

/** New first, then the ones we could not compare, then the rest. */
const STATUS_ORDER: Record<FindingStatus, number> = {
  new: 0,
  uncomparable: 1,
  existing: 2,
  fixed: 3,
};

function byStatus(a: Finding, b: Finding): number {
  if (!comparison.value) return 0;
  return STATUS_ORDER[statusOf(a) ?? 'existing'] - STATUS_ORDER[statusOf(b) ?? 'existing'];
}

const sections = computed<ReportSection[]>(() =>
  (result.value?.reports ?? []).map((report) => {
    // The reports arrive sorted by severity, and Array#sort is stable, so this
    // groups by status while keeping worst-first inside each group.
    const findings = report.findings.filter(keepFinding).sort(byStatus);
    return {
      key: `${report.source.jobId}:${report.reportType}`,
      report,
      label: REPORT_TYPE_LABELS[report.reportType],
      findings,
      hiddenByFilter: report.findings.length - findings.length,
    };
  }),
);

/**
 * What the list shows: the sections above, narrowed by the search. Kept apart
 * from `sections` on purpose — everything in the header (summary, tone, pills,
 * the hidden-by-filters count) reads from those, so a search can narrow the list
 * but never talk the header into calling the merge request clean.
 */
const listedSections = computed(() =>
  sections.value.map((section) => ({
    ...section,
    listed: compiledQuery.value.isEmpty
      ? section.findings
      : section.findings.filter((finding) => compiledQuery.value.test(finding, statusOf(finding))),
  })),
);

const visibleFindings = computed(() => sections.value.flatMap((section) => section.findings));
const visibleCounts = computed(() => countBySeverity(visibleFindings.value));

const newVisible = computed(() => visibleFindings.value.filter(isNew));
const uncomparableVisible = computed(
  () => visibleFindings.value.filter((finding) => statusOf(finding) === 'uncomparable').length,
);

/** Report types the base had nothing readable for, named on the summary line. */
const uncomparableLabels = computed(() => [
  ...new Set(
    visibleFindings.value
      .filter((finding) => statusOf(finding) === 'uncomparable')
      .map((finding) => REPORT_TYPE_LABELS[finding.reportType]),
  ),
]);

/**
 * What the pills count once a comparison exists: everything this merge request
 * might have introduced. That is the new findings plus the ones nothing could be
 * read to compare against — the same set the header's tone is based on.
 */
const attentionCounts = computed(() =>
  countBySeverity(
    visibleFindings.value.filter((finding) => {
      const status = statusOf(finding);
      return status === 'new' || status === 'uncomparable';
    }),
  ),
);

const attentionLabel = computed(() => {
  if (!comparison.value) return undefined;
  if (!uncomparableVisible.value) return 'new:';
  return newVisible.value.length ? 'new or not compared:' : 'not compared:';
});

/** What clicking the label filters by: the statuses it names. */
const attentionStatuses = computed<FindingStatus[] | undefined>(() => {
  if (!comparison.value || !showSearch.value) return undefined;
  if (!uncomparableVisible.value) return ['new'];
  return newVisible.value.length ? ['new', 'uncomparable'] : ['uncomparable'];
});

/**
 * Pre-existing findings get their own row rather than being dropped: they are not
 * this merge request's doing, but they are still in the code being reviewed. Read
 * from the reports rather than from what is on screen, so the count survives
 * show-only-new hiding the findings themselves — a summary of what is there is
 * exactly what still has to be said when the list is not showing it.
 */
const existingFindings = computed(() =>
  (result.value?.reports ?? [])
    .flatMap((report) => report.findings)
    .filter((finding) => passesSeverityFilter(finding) && statusOf(finding) === 'existing'),
);

/**
 * Show-only-new keeps these out of the list before the search sees them, so
 * `is:existing` could only ever come back empty there.
 */
const existingStatuses = computed<FindingStatus[] | undefined>(() =>
  showSearch.value && !props.settings.showOnlyNew ? ['existing'] : undefined,
);

const existingCounts = computed(() => countBySeverity(existingFindings.value));

/**
 * Pre-existing findings show-only-new is holding back. They are why a zero
 * visible total is not the same thing as a clean scan: nothing is on screen, but
 * the code under review still contains them.
 */
const hiddenAsExisting = computed(() =>
  props.settings.showOnlyNew ? existingFindings.value.length : 0,
);

/** Fixed findings obey the severity filter, but not the show-only-new one. */
const fixedFindings = computed(() =>
  (comparison.value?.fixed ?? []).filter(passesSeverityFilter),
);

const listedFixed = computed(() =>
  compiledQuery.value.isEmpty
    ? fixedFindings.value
    : fixedFindings.value.filter((finding) => compiledQuery.value.test(finding, 'fixed')),
);

/** Only offered when there is a list to narrow. */
const showSearch = computed(
  () =>
    props.settings.showSearch &&
    (visibleFindings.value.length > 0 || fixedFindings.value.length > 0),
);

const searchable = computed(() => visibleFindings.value.length + fixedFindings.value.length);
const searchMatches = computed(
  () =>
    listedSections.value.reduce((sum, section) => sum + section.listed.length, 0) +
    listedFixed.value.length,
);

const failedReports = computed(() => (result.value?.reports ?? []).filter((report) => report.error));

/** Every discovered report failed, so nothing was actually read. */
const allFailed = computed(() => {
  const reports = result.value?.reports ?? [];
  return reports.length > 0 && failedReports.value.length === reports.length;
});

/** …and every one of those failures was just an expired artifact. */
const allExpired = computed(
  () => allFailed.value && failedReports.value.every((report) => report.error?.kind === 'expired'),
);

const unreadableLabel = computed(() => {
  const failed = failedReports.value.length;
  if (!failed) return '';
  const total = (result.value?.reports ?? []).length;
  const expired = failedReports.value.filter((report) => report.error?.kind === 'expired').length;
  const why = expired === failed ? 'expired' : 'could not be read';
  return `${failed} of ${total} ${total === 1 ? 'report' : 'reports'} ${why}`;
});

const totalHiddenByFilter = computed(() =>
  sections.value.reduce((sum, section) => sum + section.hiddenByFilter, 0),
);

function vulnerabilities(count: number): string {
  return count === 1 ? 'vulnerability' : 'vulnerabilities';
}

const summary = computed(() => {
  if (props.state.status === 'loading') return 'Reading security scan results…';
  if (props.state.status === 'error') return 'Could not read security scan results';

  // Nothing was read, so no claim about vulnerabilities would be honest.
  if (allExpired.value) return 'Security scan results are no longer available';
  if (allFailed.value) return 'Could not read security scan results';

  const total = visibleCounts.value.total;
  if (total === 0) {
    // Same reason, narrower: the reports we did read were clean, but saying
    // "no vulnerabilities" would speak for the ones we could not read too.
    if (failedReports.value.length) return 'No vulnerabilities in the reports that could be read';
    // Nothing is on screen because show-only-new is holding the pre-existing
    // findings back, which is not the same claim as having found nothing.
    if (hiddenAsExisting.value > 0) {
      return `No new vulnerabilities, ${existingFindings.value.length} already on ${targetBranch.value}`;
    }
    if (running.value) return 'No vulnerabilities so far, security scanning is still running';
    return totalHiddenByFilter.value > 0
      ? 'Security scanning detected no vulnerabilities above your severity filter'
      : 'Security scanning detected no vulnerabilities';
  }

  // With a comparison in hand the interesting number is what this merge request
  // adds — but the ones already there are still named, because they are still in
  // the code under review and the header's colour reflects them.
  if (comparison.value) {
    const added = newVisible.value.length;
    if (added > 0) {
      return `This merge request adds ${added} potential ${vulnerabilities(added)}`;
    }
    if (uncomparableVisible.value > 0) {
      const count = uncomparableVisible.value;
      return `${count} potential ${vulnerabilities(count)} could not be compared with ${targetBranch.value}`;
    }
    return `No new vulnerabilities, ${existingFindings.value.length} already on ${targetBranch.value}`;
  }

  return `Security scanning detected ${total} potential ${vulnerabilities(total)}`;
});

/**
 * The header's colour. Green is reserved for "there is nothing here": findings
 * this merge request did not introduce are still findings in the code being
 * reviewed, so they stay amber rather than being waved through.
 */
const tone = computed(() => {
  if (props.state.status === 'loading') return 'neutral';
  if (props.state.status === 'error') return 'danger';
  // An expired artifact is not a security signal and not something the user can
  // act on, so it stays neutral rather than dressing up as a warning.
  if (allExpired.value) return 'neutral';
  // An empty list is only a clean bill of health if it is empty because there was
  // nothing to show — not because a filter is holding findings back.
  if (visibleCounts.value.total === 0) {
    if (failedReports.value.length || hiddenAsExisting.value > 0) return 'warning';
    return running.value ? 'neutral' : 'success';
  }
  // Introducing a vulnerability is the one case this merge request can fix by
  // being changed, so it is the one that gets the strongest signal.
  return newVisible.value.length > 0 ? 'danger' : 'warning';
});

/**
 * Kept separate from the tone: an unreadable report is a `danger` colour but
 * not a failed check, and there is nothing to cross out.
 */
const icon = computed(() => {
  if (props.state.status === 'loading') return 'spinner';
  if (props.state.status !== 'ok' || allFailed.value) return 'alert';
  if (newVisible.value.length > 0) return 'cross';
  const nothingToShow =
    visibleCounts.value.total === 0 && !failedReports.value.length && !hiddenAsExisting.value;
  if (nothingToShow && running.value) return 'spinner';
  return nothingToShow ? 'check' : 'alert';
});

// Two jobs of the same type (semgrep-sast and iac-sast) would otherwise read as
// "SAST, SAST" here; the per-section headings below tell them apart instead.
const scannedLabel = computed(() => {
  const labels =
    props.state.status === 'loading'
      ? props.state.reportTypes.map((type) => REPORT_TYPE_LABELS[type])
      : sections.value.map((section) => section.label);
  return [...new Set(labels)].join(', ');
});

const shortSha = computed(() => comparison.value?.base.sha?.slice(0, SHORT_SHA_LENGTH) ?? '');

/** Names the base, because the two strategies support different claims. */
const comparedWith = computed(() => {
  const base = comparison.value?.base;
  if (!base) return '';
  const where =
    base.strategy === 'merge-base'
      ? `Compared with ${base.targetBranch}`
      : `Compared with the latest finished pipeline on ${base.targetBranch}`;
  return shortSha.value ? `${where} at` : where;
});

function shownCount(key: string): number {
  return shown.value[key] ?? pageSize.value;
}

function showMore(key: string): void {
  shown.value = { ...shown.value, [key]: shownCount(key) + pageSize.value };
}

// Reset paging when a filter changes so "show more" state cannot outlive it —
// and when the page size changes, which is otherwise pinned by whatever the
// previous size expanded to.
watch(
  () => [
    props.settings.minSeverity,
    props.settings.hideLikelyFalsePositives,
    props.settings.showOnlyNew,
    props.settings.findingsPerPage,
    query.value,
  ],
  () => {
    shown.value = {};
  },
);

const isCollapsible = computed(
  () =>
    props.state.status === 'ok' &&
    (visibleFindings.value.length > 0 ||
      failedReports.value.length > 0 ||
      fixedFindings.value.length > 0),
);
</script>

<template>
  <section class="glsw" :class="`glsw-tone-${tone}`" data-testid="gitlab-security-widget">
    <div class="glsw-head">
      <span class="glsw-status" aria-hidden="true">
        <svg v-if="icon === 'spinner'" class="glsw-spin" viewBox="0 0 16 16" width="16" height="16">
          <circle cx="8" cy="8" r="6.5" fill="none" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-dasharray="28 12" />
        </svg>
        <svg v-else-if="icon === 'check'" viewBox="0 0 16 16" width="16" height="16">
          <path
            fill="currentColor"
            d="M8 0a8 8 0 1 0 0 16A8 8 0 0 0 8 0Zm3.7 6.1-4.2 4.2a1 1 0 0 1-1.4 0L4.3 8.5a1 1 0 0 1 1.4-1.4l1.1 1.1 3.5-3.5a1 1 0 0 1 1.4 1.4Z"
          />
        </svg>
        <!-- The strokes are knocked out in the widget's own background colour,
             which follows GitLab's light and dark themes. -->
        <svg v-else-if="icon === 'cross'" viewBox="0 0 16 16" width="16" height="16">
          <circle cx="8" cy="8" r="8" fill="currentColor" />
          <path
            d="M5.4 5.4l5.2 5.2M10.6 5.4l-5.2 5.2"
            fill="none"
            stroke="var(--glsw-bg)"
            stroke-width="2"
            stroke-linecap="round"
          />
        </svg>
        <svg v-else viewBox="0 0 16 16" width="16" height="16">
          <path
            fill="currentColor"
            d="M8 0a8 8 0 1 0 0 16A8 8 0 0 0 8 0Zm1 11.5a1 1 0 1 1-2 0 1 1 0 0 1 2 0ZM7 4a1 1 0 0 1 2 0v4.5a1 1 0 0 1-2 0V4Z"
          />
        </svg>
      </span>

      <div class="glsw-head-body">
        <p class="glsw-summary">{{ summary }}</p>

        <p v-if="state.status === 'error'" class="glsw-sub glsw-danger-text">
          {{ state.message }}
        </p>

        <!-- All-zero pills would read as a clean scan when in fact nothing was read. -->
        <template v-else-if="state.status === 'ok' && !allFailed">
          <SeverityPills
            :counts="comparison ? attentionCounts : visibleCounts"
            :label="attentionLabel"
            :selected="severitySelection"
            :interactive="showSearch"
            :label-statuses="attentionStatuses"
            :selected-statuses="statusSelection"
            @toggle="onToggleSeverity"
            @toggle-statuses="onToggleStatuses"
          />
          <SeverityPills
            v-if="comparison"
            :counts="existingCounts"
            label="already there:"
            :selected="severitySelection"
            :interactive="showSearch"
            :label-statuses="existingStatuses"
            :selected-statuses="statusSelection"
            @toggle="onToggleSeverity"
            @toggle-statuses="onToggleStatuses"
          />
        </template>

        <p class="glsw-sub">
          <span v-if="scannedLabel">{{ scannedLabel }}</span>
          <template v-if="result?.pipelineWebUrl">
            <span v-if="scannedLabel"> · </span>
            <a class="glsw-link" :href="result.pipelineWebUrl">pipeline #{{ result.pipelineId }}</a>
          </template>
          <template v-if="running">
            · <span class="glsw-muted">
              {{ runningScans?.length ? runningScans.join(', ') : 'pipeline' }} still running,
              {{ settings.autoRefresh ? 'updates as jobs finish' : 'refresh once jobs finish' }}
            </span>
          </template>
          <template v-if="unreadableLabel">
            · <span class="glsw-muted">{{ unreadableLabel }}</span>
          </template>
          <template v-if="totalHiddenByFilter > 0">
            · <span class="glsw-muted">{{ totalHiddenByFilter }} hidden by filters</span>
          </template>
        </p>

        <!-- The comparison lands after the findings, so it has its own line. -->
        <p v-if="result && result.comparison.status !== 'off'" class="glsw-sub glsw-muted">
          <template v-if="result.comparison.status === 'loading'">
            Comparing with the target branch…
          </template>

          <template v-else-if="result.comparison.status === 'unavailable'">
            Not compared with the target branch — {{ result.comparison.reason }}
          </template>

          <template v-else-if="comparison">
            {{ comparedWith }}
            <a
              v-if="comparison.base.commitWebUrl"
              class="glsw-link glsw-mono"
              :href="comparison.base.commitWebUrl"
              >{{ shortSha }}</a
            >
            <span v-else-if="shortSha" class="glsw-mono">{{ shortSha }}</span>
            ·
            <a
              v-if="comparison.base.pipelineWebUrl"
              class="glsw-link"
              :href="comparison.base.pipelineWebUrl"
              >pipeline #{{ comparison.base.pipelineId }}</a
            >
            <span v-else>pipeline #{{ comparison.base.pipelineId }}</span>
            <template v-if="fixedFindings.length > 0">
              · {{ fixedFindings.length }} fixed here
            </template>
            <!-- Their reports are not in yet, so nothing they found can be called fixed. -->
            <template v-if="comparison.pendingJobs.length > 0">
              · fixes not checked for {{ comparison.pendingJobs.join(', ') }} until
              {{ comparison.pendingJobs.length === 1 ? 'it finishes' : 'they finish' }}
            </template>
            <!-- Naming the types says which scanner the base was missing. -->
            <template v-if="uncomparableVisible > 0">
              · {{ uncomparableVisible }} not compared ({{ uncomparableLabels.join(', ') }})
            </template>
            <!-- A partly-read base can only make findings look new, so say so. -->
            <template v-if="comparison.baseUnreadableCount > 0">
              · {{ comparison.baseUnreadableCount }} of {{ comparison.baseReportCount }} of its
              reports could not be read
            </template>
          </template>
        </p>
      </div>

      <button
        v-if="state.status === 'ok'"
        type="button"
        class="glsw-toggle glsw-refresh"
        aria-label="Refresh"
        title="Read the pipeline and the target branch again"
        :disabled="refreshing"
        @click="emit('refresh')"
      >
        <svg
          :class="{ 'glsw-spin': refreshing }"
          viewBox="0 0 16 16"
          width="14"
          height="14"
          aria-hidden="true"
        >
          <path
            d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9M13.5 2.5v3h-3"
            fill="none"
            stroke="currentColor"
            stroke-width="1.6"
            stroke-linecap="round"
            stroke-linejoin="round"
          />
        </svg>
      </button>
      <button
        v-if="isCollapsible"
        type="button"
        class="glsw-toggle"
        :aria-expanded="!collapsed"
        @click="collapsed = !collapsed"
      >
        {{ collapsed ? 'Show details' : 'Hide details' }}
      </button>
    </div>

    <div v-if="state.status === 'ok' && !collapsed" class="glsw-body">
      <div v-if="showSearch" class="glsw-search">
        <div class="glsw-search-row">
          <input
            ref="searchInput"
            v-model="query"
            class="glsw-search-input"
            type="search"
            role="combobox"
            placeholder="Filter, e.g. severity:>=high file:!*.test.ts"
            aria-label="Filter findings"
            aria-autocomplete="list"
            :aria-expanded="suggestions.items.length > 0"
            :aria-controls="suggestionsId"
            :aria-activedescendant="
              suggestions.items.length ? `${suggestionsId}-${activeSuggestion}` : undefined
            "
            :title="QUERY_HELP"
            spellcheck="false"
            autocomplete="off"
            @input="onSearchInput"
            @click="syncCursor"
            @keyup.left.right.home.end="syncCursor"
            @keydown="onSearchKeydown"
            @blur="suggesting = false"
          />
          <span v-if="!compiledQuery.isEmpty" class="glsw-muted glsw-search-count">
            {{ searchMatches }} of {{ searchable }} match
          </span>
        </div>
        <!-- In the flow rather than floating: the widget clips overflow, and a
             dropdown would be cut off when the list below it is short. -->
        <ul
          v-show="suggestions.items.length"
          :id="suggestionsId"
          class="glsw-suggestions"
          role="listbox"
          aria-label="Suggestions"
        >
          <li
            v-for="(item, index) in suggestions.items"
            :id="`${suggestionsId}-${index}`"
            :key="item.label"
            class="glsw-suggestion"
            :class="{ 'glsw-suggestion-active': index === activeSuggestion }"
            role="option"
            :aria-selected="index === activeSuggestion"
            @mousedown.prevent="pickSuggestion(item)"
          >
            {{ item.label }}
          </li>
          <li class="glsw-muted glsw-suggestions-hint" aria-hidden="true">Tab to complete</li>
        </ul>

        <p v-for="error in compiledQuery.errors" :key="error.term" class="glsw-sub glsw-danger-text">
          Ignoring <span class="glsw-mono">{{ error.term }}</span>: {{ error.message }}
        </p>
      </div>

      <div v-for="section in listedSections" :key="section.key" class="glsw-section">
        <div class="glsw-section-head">
          <span class="glsw-section-title">{{ section.label }}</span>
          <span v-if="section.report.scanners.length" class="glsw-muted">
            {{ section.report.scanners.join(', ') }}
          </span>
          <span class="glsw-spacer" />
          <a class="glsw-link" :href="section.report.source.jobWebUrl">
            {{ section.report.source.jobName }}
          </a>
          <!-- The artifact is gone, so this would just be a link to another 404. -->
          <a
            v-if="section.report.error?.kind !== 'expired'"
            class="glsw-link"
            :href="section.report.source.downloadUrl"
            download
            >raw JSON</a
          >
        </div>

        <p
          v-if="section.report.error"
          class="glsw-sub"
          :class="section.report.error.kind === 'expired' ? 'glsw-muted' : 'glsw-danger-text'"
        >
          {{ section.report.error.message }}
        </p>

        <p v-else-if="!section.findings.length" class="glsw-sub glsw-muted">
          No findings{{ section.hiddenByFilter ? ' above your filters' : '' }}.
        </p>

        <p v-else-if="!section.listed.length" class="glsw-sub glsw-muted">
          No findings match the search.
        </p>

        <ul v-else class="glsw-findings">
          <FindingItem
            v-for="finding in section.listed.slice(0, shownCount(section.key))"
            :key="finding.key"
            :finding="finding"
            :status="statusOf(finding)"
            :target-branch="targetBranch"
          />
        </ul>

        <button
          v-if="section.listed.length > shownCount(section.key)"
          type="button"
          class="glsw-more"
          @click="showMore(section.key)"
        >
          Show {{ Math.min(pageSize, section.listed.length - shownCount(section.key)) }} more of
          {{ section.listed.length }}
        </button>
      </div>

      <div v-if="listedFixed.length" class="glsw-section">
        <div class="glsw-section-head">
          <span class="glsw-section-title">Fixed by this merge request</span>
          <span class="glsw-muted">
            on {{ targetBranch }}, not reported by this pipeline
          </span>
        </div>

        <ul class="glsw-findings">
          <FindingItem
            v-for="finding in listedFixed.slice(0, shownCount(FIXED_KEY))"
            :key="finding.key"
            :finding="finding"
            status="fixed"
            :target-branch="targetBranch"
          />
        </ul>

        <button
          v-if="listedFixed.length > shownCount(FIXED_KEY)"
          type="button"
          class="glsw-more"
          @click="showMore(FIXED_KEY)"
        >
          Show {{ Math.min(pageSize, listedFixed.length - shownCount(FIXED_KEY)) }} more of
          {{ listedFixed.length }}
        </button>
      </div>
    </div>
  </section>
</template>
