<script setup lang="ts">
import { computed } from 'vue';
import {
  SEVERITIES,
  SEVERITY_LABELS,
  type FindingStatus,
  type Severity,
  type SeverityCounts,
} from '@/lib/types';

const props = defineProps<{
  counts: SeverityCounts;
  /** What the counts are of, when they are not simply every finding. */
  label?: string;
  /** Severities the search narrows to; null or absent when it does not. */
  selected?: Set<Severity> | null;
  /** Makes each pill a button that toggles its severity in the search. */
  interactive?: boolean;
  /** The statuses the label stands for, which makes it a button toggling them. */
  labelStatuses?: FindingStatus[];
  /** Statuses the search narrows to with `is:`; null or absent when it does not. */
  selectedStatuses?: Set<FindingStatus> | null;
}>();

defineEmits<{ toggle: [severity: Severity]; toggleStatuses: [statuses: FindingStatus[]] }>();

/** On when the search picks every status the label stands for, off when none. */
const labelState = computed(() => {
  if (!props.selectedStatuses || !props.labelStatuses) return 'neutral';
  const picked = props.labelStatuses.filter((status) => props.selectedStatuses!.has(status));
  if (picked.length === props.labelStatuses.length) return 'on';
  return picked.length ? 'neutral' : 'off';
});

const present = computed(() =>
  SEVERITIES.filter((severity) => props.counts[severity] > 0).map((severity) => ({
    severity,
    label: SEVERITY_LABELS[severity],
    count: props.counts[severity],
    // With nothing selected every pill reads as on, not off.
    active: !props.selected || props.selected.has(severity),
  })),
);
</script>

<template>
  <ul v-if="present.length" class="glsw-pills">
    <li v-if="label" class="glsw-pill-lead" :class="{ 'glsw-pill-off': labelState === 'off' }">
      <button
        v-if="labelStatuses"
        type="button"
        class="glsw-pill-button"
        :class="{ 'glsw-pill-on': labelState === 'on' }"
        :aria-pressed="labelState === 'on'"
        :title="`Filter by is:${labelStatuses.join(',')}`"
        @click="$emit('toggleStatuses', labelStatuses)"
      >
        {{ label }}
      </button>
      <template v-else>{{ label }}</template>
    </li>
    <li
      v-for="pill in present"
      :key="pill.severity"
      :class="[`glsw-pill glsw-sev-${pill.severity}`, { 'glsw-pill-off': !pill.active }]"
    >
      <button
        v-if="interactive"
        type="button"
        class="glsw-pill-button"
        :class="{ 'glsw-pill-on': selected && pill.active }"
        :aria-pressed="!!selected && pill.active"
        :title="`Filter by ${pill.label.toLowerCase()} severity`"
        @click="$emit('toggle', pill.severity)"
      >
        <span class="glsw-pill-dot" aria-hidden="true" />
        <span class="glsw-pill-count">{{ pill.count }}</span>
        <span class="glsw-pill-label">{{ pill.label }}</span>
      </button>
      <template v-else>
        <span class="glsw-pill-dot" aria-hidden="true" />
        <span class="glsw-pill-count">{{ pill.count }}</span>
        <span class="glsw-pill-label">{{ pill.label }}</span>
      </template>
    </li>
  </ul>
</template>
