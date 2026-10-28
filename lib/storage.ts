import { storage } from 'wxt/utils/storage';
import type { Severity } from './types';

/**
 * Extra GitLab origins the user has added (e.g. "https://gitlab.example.com").
 * gitlab.com is always enabled and is not stored here.
 */
export const instanceOrigins = storage.defineItem<string[]>('sync:instanceOrigins', {
  fallback: [],
});

export interface Settings {
  /** Start the widget collapsed rather than expanded. */
  startCollapsed: boolean;
  /** Hide findings below this severity. */
  minSeverity: Severity;
  /** Hide findings the scanner flagged as likely false positives. */
  hideLikelyFalsePositives: boolean;
  /**
   * Compare the head pipeline's findings against the target branch's, so new
   * findings can be told from ones the branch already had. Costs a second
   * pipeline's worth of requests, after the findings are already on screen.
   */
  compareWithTargetBranch: boolean;
  /**
   * Show only findings this merge request introduces. Findings that could not be
   * compared stay visible either way — hiding them would pass off "unknown" as
   * "already there".
   */
  showOnlyNew: boolean;
  /**
   * Log each step to the page console. Always on in dev builds; this only
   * affects production builds.
   */
  verboseLogging: boolean;
  /** How many findings a report section lists before "show more". */
  findingsPerPage: number;
  /** Show a search box above the findings. What is typed into it is not stored. */
  showSearch: boolean;
  /**
   * How many base pipeline candidates the comparison tries before giving up.
   *
   * Each attempt costs a jobs listing plus a download per report it finds, so
   * this is the knob that keeps the comparison from multiplying request volume
   * on projects where the target branch's recent pipelines carry no reports.
   */
  maxBasePipelines: number;
  /**
   * How many levels of child (downstream) pipelines to follow when looking for
   * report artifacts. Zero stays within the pipeline itself; each level costs a
   * bridges listing plus a jobs listing per child pipeline found.
   */
  childPipelineDepth: number;
  /**
   * Keep an open merge request's widget current: pick up scan jobs as they
   * finish and a new pipeline after a push, without reloading the page.
   */
  autoRefresh: boolean;
  /**
   * How often a running pipeline is checked, in seconds. A finished one is
   * checked half as often, since only a push can change it then.
   */
  refreshIntervalSeconds: number;
}

export const DEFAULT_SETTINGS: Settings = {
  startCollapsed: true,
  minSeverity: 'unknown',
  hideLikelyFalsePositives: false,
  compareWithTargetBranch: true,
  showOnlyNew: false,
  verboseLogging: false,
  findingsPerPage: 20,
  showSearch: true,
  maxBasePipelines: 3,
  childPipelineDepth: 1,
  autoRefresh: true,
  refreshIntervalSeconds: 30,
};

/**
 * What each numeric setting is allowed to be, enforced on every read rather
 * than only where it is written. The stored value can come from an older
 * version, from another device via sync, or from a hand-edited storage entry,
 * and a page size of zero or a child depth of fifty is a broken widget rather
 * than an unusual preference.
 */
export const SETTING_LIMITS = {
  findingsPerPage: { min: 5, max: 500 },
  /**
   * The cap is `PIPELINE_LOOKUP_PAGE_SIZE` in lib/gitlab-api.ts: asking to try
   * more pipelines than a lookup returns would not reach any further back.
   */
  maxBasePipelines: { min: 1, max: 10 },
  childPipelineDepth: { min: 0, max: 3 },
  /** Each check is at least one request per open merge request tab. */
  refreshIntervalSeconds: { min: 10, max: 600 },
} as const satisfies Record<string, { min: number; max: number }>;

export type NumericSetting = keyof typeof SETTING_LIMITS;

export const settings = storage.defineItem<Settings>('sync:settings', {
  fallback: DEFAULT_SETTINGS,
});

/**
 * The stored object predates whichever setting was added last, and a `fallback`
 * only covers the case where nothing is stored at all — so a key added in a
 * later version reads back as `undefined` for everyone who already has settings.
 * Every read goes through here, which is also where the numeric settings are
 * brought back inside their limits.
 */
export function withDefaults(value: Partial<Settings> | null | undefined): Settings {
  const merged = { ...DEFAULT_SETTINGS, ...(value ?? {}) };
  return {
    ...merged,
    findingsPerPage: clampSetting(merged.findingsPerPage, 'findingsPerPage'),
    maxBasePipelines: clampSetting(merged.maxBasePipelines, 'maxBasePipelines'),
    childPipelineDepth: clampSetting(merged.childPipelineDepth, 'childPipelineDepth'),
    refreshIntervalSeconds: clampSetting(merged.refreshIntervalSeconds, 'refreshIntervalSeconds'),
  };
}

/**
 * Brings one numeric setting inside its limits, falling back to the default for
 * anything that is not a number at all — which is what an emptied number input
 * hands over.
 */
export function clampSetting(value: unknown, setting: NumericSetting): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) return DEFAULT_SETTINGS[setting];
  const { min, max } = SETTING_LIMITS[setting];
  return Math.min(max, Math.max(min, Math.round(value)));
}

export async function getSettings(): Promise<Settings> {
  return withDefaults(await settings.getValue());
}

/** Normalizes user input like "gitlab.example.com/" into an origin. */
export function toOrigin(input: string): string | null {
  const trimmed = input.trim();
  if (!trimmed) return null;

  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const url = new URL(withScheme);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return null;
    if (!url.hostname) return null;
    return url.origin;
  } catch {
    return null;
  }
}

/** Match pattern covering a whole origin, for permissions and script registration. */
export function originToMatchPattern(origin: string): string {
  return `${origin}/*`;
}

export const GITLAB_COM_ORIGIN = 'https://gitlab.com';

export async function addOrigin(origin: string): Promise<string[]> {
  const current = await instanceOrigins.getValue();
  if (current.includes(origin) || origin === GITLAB_COM_ORIGIN) return current;

  const next = [...current, origin].sort();
  await instanceOrigins.setValue(next);
  return next;
}

export async function removeOrigin(origin: string): Promise<string[]> {
  const current = await instanceOrigins.getValue();
  const next = current.filter((o) => o !== origin);
  await instanceOrigins.setValue(next);
  return next;
}
