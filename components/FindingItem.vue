<script setup lang="ts">
import { computed, ref } from 'vue';
import { suppressionFor } from '@/lib/suppress';
import { SEVERITY_LABELS, type Finding, type FindingStatus } from '@/lib/types';

const props = defineProps<{
  finding: Finding;
  /** Absent when no comparison with the target branch was made. */
  status?: FindingStatus;
  /** The branch the status is relative to, for the tooltips. */
  targetBranch?: string;
}>();

const expanded = ref(false);

/**
 * Only the statuses that tell the reader something get a badge. "Existing" is
 * the unremarkable case and its absence is quieter than a label on every row.
 */
const badge = computed(() => {
  const branch = props.targetBranch ?? 'the target branch';
  switch (props.status) {
    case 'new':
      return { label: 'new', class: 'glsw-badge-new', title: `Not present on ${branch}` };
    case 'fixed':
      return { label: 'fixed', class: 'glsw-badge-fixed', title: `Present on ${branch}, gone here` };
    case 'uncomparable':
      return {
        label: 'not compared',
        class: 'glsw-flag',
        title: `${branch} has no readable report of this type, so this finding could not be compared`,
      };
    default:
      return null;
  }
});

const location = computed(() => {
  const { file, startLine, dependency, locationLabel } = props.finding;
  if (file) return startLine ? `${file}:${startLine}` : file;
  return dependency ?? locationLabel;
});

const suppression = computed(() => suppressionFor(props.finding));

const suppressionTitle = computed(() => {
  const value = suppression.value;
  if (!value) return '';
  const where = {
    'same-line': 'at the end of the reported line',
    'line-above': 'on its own line above the reported line',
    'file-start': 'among the comments that open the file, before any code',
  }[value.placement];
  return `Copy "${value.comment}" — paste it ${where}. Silences ${value.scope}.`;
});

const copyState = ref<'idle' | 'copied' | 'failed'>('idle');
let copyReset: ReturnType<typeof setTimeout> | undefined;

async function copySuppression() {
  if (!suppression.value) return;
  try {
    await navigator.clipboard.writeText(suppression.value.comment);
    copyState.value = 'copied';
  } catch {
    copyState.value = 'failed';
  }
  clearTimeout(copyReset);
  copyReset = setTimeout(() => (copyState.value = 'idle'), 1500);
}

const hasDetail = computed(() =>
  Boolean(
    props.finding.description ||
      props.finding.solution ||
      props.finding.links.length ||
      props.finding.identifiers.length,
  ),
);
</script>

<template>
  <li class="glsw-finding">
    <div class="glsw-finding-head">
      <span
        :class="`glsw-sev-tag glsw-sev-${finding.severity}`"
        :title="`Severity: ${SEVERITY_LABELS[finding.severity]}`"
      >
        {{ SEVERITY_LABELS[finding.severity] }}
      </span>

      <div class="glsw-finding-main">
        <button
          v-if="hasDetail"
          type="button"
          class="glsw-finding-name glsw-linkish"
          :aria-expanded="expanded"
          @click="expanded = !expanded"
        >
          {{ finding.name }}
        </button>
        <span v-else class="glsw-finding-name">{{ finding.name }}</span>

        <span v-if="badge" :class="['glsw-badge', badge.class]" :title="badge.title">
          {{ badge.label }}
        </span>

        <span v-if="finding.likelyFalsePositive" class="glsw-flag" title="Flagged by the scanner">
          likely false positive
        </span>

        <div v-if="location" class="glsw-finding-location">
          <a v-if="finding.blobUrl" :href="finding.blobUrl" class="glsw-link">{{ location }}</a>
          <span v-else>{{ location }}</span>
          <span v-if="finding.scanner" class="glsw-muted"> · {{ finding.scanner }}</span>
          <template v-if="suppression">
            <span class="glsw-muted"> · </span>
            <button
              type="button"
              class="glsw-linkish glsw-copy"
              :title="suppressionTitle"
              @click="copySuppression"
            >
              {{
                copyState === 'copied'
                  ? 'copied'
                  : copyState === 'failed'
                    ? 'copy failed'
                    : 'copy ignore comment'
              }}
            </button>
          </template>
        </div>
      </div>
    </div>

    <div v-if="expanded" class="glsw-finding-detail">
      <p v-if="finding.description" class="glsw-detail-text">{{ finding.description }}</p>

      <p v-if="finding.solution" class="glsw-detail-text">
        <strong>Solution:</strong> {{ finding.solution }}
      </p>

      <ul v-if="finding.identifiers.length" class="glsw-ident-list">
        <li v-for="identifier in finding.identifiers" :key="identifier" class="glsw-ident">
          {{ identifier }}
        </li>
      </ul>

      <ul v-if="finding.links.length" class="glsw-link-list">
        <li v-for="link in finding.links" :key="link.url">
          <a :href="link.url" class="glsw-link" target="_blank" rel="noreferrer noopener">
            {{ link.name || link.url }}
          </a>
        </li>
      </ul>
    </div>
  </li>
</template>
