<script setup lang="ts">
import { onMounted, ref, watch } from 'vue';
import { browser } from 'wxt/browser';
import {
  DEFAULT_SETTINGS,
  GITLAB_COM_ORIGIN,
  SETTING_LIMITS,
  addOrigin,
  clampSetting,
  getSettings,
  instanceOrigins,
  originToMatchPattern,
  removeOrigin,
  settings,
  toOrigin,
  type NumericSetting,
  type Settings,
} from '@/lib/storage';
import { SEVERITIES, SEVERITY_LABELS } from '@/lib/types';

const origins = ref<string[]>([]);
const input = ref('');
const error = ref<string | null>(null);
const busy = ref(false);
const current = ref<Settings>({ ...DEFAULT_SETTINGS });
const loaded = ref(false);

onMounted(async () => {
  origins.value = await instanceOrigins.getValue();
  current.value = await getSettings();
  loaded.value = true;
});

// Persist as the user changes controls; the content script watches this key and
// re-filters an already-rendered widget in place.
watch(
  current,
  (value) => {
    if (loaded.value) void settings.setValue({ ...value });
  },
  { deep: true },
);

/**
 * Number inputs are committed on change rather than bound with `v-model`, so a
 * half-typed or emptied field is left alone while it is being typed and only the
 * value the user settles on is clamped and stored.
 */
function commitNumber(setting: NumericSetting, event: Event): void {
  const input = event.target as HTMLInputElement;
  const value = clampSetting(input.valueAsNumber, setting);
  current.value[setting] = value;
  // The clamp may have moved it, and the field would otherwise keep showing what
  // was typed.
  input.value = String(value);
}

async function add(): Promise<void> {
  error.value = null;
  const origin = toOrigin(input.value);

  if (!origin) {
    error.value = 'Enter a URL such as https://gitlab.example.com';
    return;
  }
  if (origin === GITLAB_COM_ORIGIN) {
    error.value = 'gitlab.com is always enabled.';
    return;
  }
  if (origins.value.includes(origin)) {
    error.value = `${origin} is already added.`;
    return;
  }

  busy.value = true;
  try {
    const granted = await browser.permissions.request({
      origins: [originToMatchPattern(origin)],
    });
    if (!granted) {
      error.value = 'Permission was not granted, so this instance was not added.';
      return;
    }
    origins.value = await addOrigin(origin);
    input.value = '';
  } catch (cause) {
    error.value = cause instanceof Error ? cause.message : String(cause);
  } finally {
    busy.value = false;
  }
}

async function remove(origin: string): Promise<void> {
  error.value = null;
  origins.value = await removeOrigin(origin);
  // Best effort: Chrome refuses to revoke a permission that another granted
  // pattern still covers, which is not a failure worth reporting.
  await browser.permissions
    .remove({ origins: [originToMatchPattern(origin)] })
    .catch(() => undefined);
}
</script>

<template>
  <main class="page">
    <h1>Merge Request Security Widget for GitLab</h1>
    <p class="ui-muted">
      Summarizes the security report artifacts already attached to a merge request's pipeline, so you
      can read them on the merge request instead of downloading raw JSON.
    </p>

    <section>
      <h2>GitLab instances</h2>
      <p class="ui-muted">
        The extension reads merge request pages only on the instances listed here. Reports are
        fetched with your existing GitLab session and never leave the browser.
      </p>

      <ul class="list">
        <li class="list-item">
          <span class="ui-mono">{{ GITLAB_COM_ORIGIN }}</span>
          <span class="ui-muted">always enabled</span>
        </li>
        <li v-for="origin in origins" :key="origin" class="list-item">
          <span class="ui-mono">{{ origin }}</span>
          <button type="button" class="ui-button" @click="remove(origin)">Remove</button>
        </li>
      </ul>

      <form class="add-row" @submit.prevent="add">
        <input
          v-model="input"
          class="ui-input"
          type="text"
          placeholder="https://gitlab.example.com"
          spellcheck="false"
          autocomplete="off"
        />
        <button type="submit" class="ui-button ui-button-primary" :disabled="busy">
          {{ busy ? 'Requesting…' : 'Add' }}
        </button>
      </form>

      <p v-if="error" class="ui-danger">{{ error }}</p>
    </section>

    <section>
      <h2>Report discovery</h2>
      <p class="ui-muted">
        Security reports are read from the merge request's own pipeline. Projects that split their
        scanning into downstream pipelines keep them one or more levels below it, at the cost of a
        job listing per child pipeline. Takes effect on the next page load.
      </p>

      <label class="ui-field field-block">
        <span>Levels of child pipelines to follow</span>
        <input
          class="ui-input ui-number"
          type="number"
          :min="SETTING_LIMITS.childPipelineDepth.min"
          :max="SETTING_LIMITS.childPipelineDepth.max"
          step="1"
          :value="current.childPipelineDepth"
          @change="commitNumber('childPipelineDepth', $event)"
        />
        <span class="ui-muted hint">
          0 reads only the merge request's own pipeline. Up to
          {{ SETTING_LIMITS.childPipelineDepth.max }}.
        </span>
      </label>
    </section>

    <section>
      <h2>Target branch comparison</h2>
      <p class="ui-muted">
        Reads the target branch's own security reports as well, so findings this merge request
        introduces can be told from ones the branch already had. It runs after the findings are on
        screen and costs a second pipeline's worth of requests. Findings the target branch has no
        readable report for are marked <em>not compared</em> rather than counted as new.
      </p>

      <label class="ui-field">
        <input v-model="current.compareWithTargetBranch" type="checkbox" />
        <span>Compare findings with the target branch</span>
      </label>

      <label class="ui-field">
        <input
          v-model="current.showOnlyNew"
          type="checkbox"
          :disabled="!current.compareWithTargetBranch"
        />
        <span>Show only findings this merge request introduces</span>
      </label>

      <label class="ui-field field-block">
        <span>Base pipelines to try</span>
        <input
          class="ui-input ui-number"
          type="number"
          :min="SETTING_LIMITS.maxBasePipelines.min"
          :max="SETTING_LIMITS.maxBasePipelines.max"
          step="1"
          :value="current.maxBasePipelines"
          :disabled="!current.compareWithTargetBranch"
          @change="commitNumber('maxBasePipelines', $event)"
        />
        <span class="ui-muted hint">
          How far back on the target branch to look for a pipeline whose reports can be read. Each
          one tried costs a job listing plus a download per report it has. Up to
          {{ SETTING_LIMITS.maxBasePipelines.max }}.
        </span>
      </label>
    </section>

    <section>
      <h2>Display</h2>

      <label class="ui-field">
        <input v-model="current.startCollapsed" type="checkbox" />
        <span>Start the widget collapsed</span>
      </label>

      <label class="ui-field">
        <input v-model="current.showSearch" type="checkbox" />
        <span>Show a search box above the findings</span>
      </label>

      <label class="ui-field">
        <input v-model="current.hideLikelyFalsePositives" type="checkbox" />
        <span>Hide findings the scanner flagged as likely false positives</span>
      </label>

      <label class="ui-field">
        <input v-model="current.verboseLogging" type="checkbox" />
        <span>Log each step to the page console (for troubleshooting)</span>
      </label>

      <label class="ui-field field-block">
        <span>Lowest severity to show</span>
        <select v-model="current.minSeverity" class="ui-select">
          <option v-for="severity in SEVERITIES" :key="severity" :value="severity">
            {{ SEVERITY_LABELS[severity] }}
          </option>
        </select>
      </label>

      <label class="ui-field field-block">
        <span>Findings shown per report</span>
        <input
          class="ui-input ui-number"
          type="number"
          :min="SETTING_LIMITS.findingsPerPage.min"
          :max="SETTING_LIMITS.findingsPerPage.max"
          step="5"
          :value="current.findingsPerPage"
          @change="commitNumber('findingsPerPage', $event)"
        />
        <span class="ui-muted hint">
          The rest stay behind a "show more" button, in steps of the same size.
          {{ SETTING_LIMITS.findingsPerPage.min }} to {{ SETTING_LIMITS.findingsPerPage.max }}.
        </span>
      </label>
    </section>

    <footer class="footer ui-muted">
      This extension is not affiliated, endorsed, sponsored, or approved with or by GitLab Inc.
      GitLab is a trademark of GitLab Inc.
    </footer>
  </main>
</template>

<style scoped>
.page {
  max-width: 640px;
  margin: 0 auto;
  padding: 24px 20px 48px;
}

section {
  margin-top: 28px;
}

.footer {
  margin-top: 32px;
  padding-top: 16px;
  border-top: 1px solid var(--ui-border);
  font-size: 12px;
}

.list {
  margin: 12px 0;
  padding: 0;
  list-style: none;
  border: 1px solid var(--ui-border);
  border-radius: 6px;
}

.list-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 8px 12px;
}

.list-item + .list-item {
  border-top: 1px solid var(--ui-border);
}

.add-row {
  display: flex;
  gap: 8px;
}

.field-block {
  display: block;
}

.field-block .ui-select {
  margin-top: 4px;
  max-width: 220px;
}

.field-block .ui-number {
  margin-top: 4px;
  max-width: 96px;
}

.hint {
  display: block;
  margin-top: 4px;
  font-size: 12px;
}
</style>
