import { describe, expect, it } from 'vitest';
import { DEFAULT_SETTINGS, SETTING_LIMITS, clampSetting, toOrigin, withDefaults } from './storage';

describe('withDefaults', () => {
  it('fills in settings the stored object predates', () => {
    expect(withDefaults({ startCollapsed: false })).toEqual({
      ...DEFAULT_SETTINGS,
      startCollapsed: false,
    });
  });

  it('falls back to the defaults when nothing is stored', () => {
    expect(withDefaults(null)).toEqual(DEFAULT_SETTINGS);
  });

  it('brings out-of-range numbers back inside their limits', () => {
    const settings = withDefaults({
      findingsPerPage: 0,
      maxBasePipelines: 99,
      childPipelineDepth: -1,
      refreshIntervalSeconds: 1,
    });

    expect(settings.findingsPerPage).toBe(SETTING_LIMITS.findingsPerPage.min);
    expect(settings.maxBasePipelines).toBe(SETTING_LIMITS.maxBasePipelines.max);
    expect(settings.childPipelineDepth).toBe(SETTING_LIMITS.childPipelineDepth.min);
    expect(settings.refreshIntervalSeconds).toBe(SETTING_LIMITS.refreshIntervalSeconds.min);
  });

  it('replaces a value that is not a number at all', () => {
    // What an emptied number input, or a hand-edited storage entry, hands over.
    const settings = withDefaults({ findingsPerPage: NaN } as never);

    expect(settings.findingsPerPage).toBe(DEFAULT_SETTINGS.findingsPerPage);
  });
});

describe('clampSetting', () => {
  it('rounds a fractional value', () => {
    expect(clampSetting(20.6, 'findingsPerPage')).toBe(21);
  });

  it('leaves a value inside the limits alone', () => {
    expect(clampSetting(2, 'childPipelineDepth')).toBe(2);
  });

  it('treats a missing value as the default', () => {
    expect(clampSetting(undefined, 'maxBasePipelines')).toBe(DEFAULT_SETTINGS.maxBasePipelines);
  });
});

describe('toOrigin', () => {
  it('normalizes user input into an origin', () => {
    expect(toOrigin('gitlab.example.com/')).toBe('https://gitlab.example.com');
    expect(toOrigin('  https://gitlab.example.com/group  ')).toBe('https://gitlab.example.com');
  });

  it('rejects input that is not a usable origin', () => {
    expect(toOrigin('')).toBeNull();
    expect(toOrigin('javascript:alert(1)')).toBeNull();
  });
});
