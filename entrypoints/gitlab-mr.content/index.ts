import { createApp, h, reactive, type App } from 'vue';
import { defineContentScript } from 'wxt/utils/define-content-script';
import { createIntegratedUi } from 'wxt/utils/content-script-ui/integrated';
import type { ContentScriptContext } from 'wxt/utils/content-script-context';
import type { IntegratedContentScriptUi } from 'wxt/utils/content-script-ui/integrated';
import SecurityWidget from '@/components/SecurityWidget.vue';
import { fitHost, waitForAnchor } from '@/lib/anchor';
import { bail, error as logError, log, setVerbose } from '@/lib/debug';
import type { MrInfo } from '@/lib/gitlab-api';
import { looksLikeGitLab, parseMrPath, type MrPageContext } from '@/lib/gitlab-page';
import {
  clearBaseReportCache,
  discoverReports,
  discoveryChanged,
  loadComparison,
  loadReports,
  rediscoverReports,
  type Discovery,
  type ReportCache,
} from '@/lib/scan';
import { getSettings, settings, withDefaults, type Settings } from '@/lib/storage';
import { isRunning, type WidgetState } from '@/lib/types';
import './widget.css';

interface Store {
  state: WidgetState;
  settings: Settings;
  /** A refresh the user asked for is in flight. */
  refreshing: boolean;
}

/**
 * How long until an open merge request is checked for changes again. A running
 * pipeline is worth watching closely, since its scan jobs finish one by one; a
 * finished one only changes when a push starts another, so it is checked half
 * as often.
 */
function pollDelay(settings: Settings, running: boolean): number {
  return settings.refreshIntervalSeconds * 1000 * (running ? 1 : 2);
}

/** One merge request's worth of work, so a soft navigation can cancel it. */
interface Session {
  page: MrPageContext;
  abort: AbortController;
  store: Store;
  ui: IntegratedContentScriptUi<App<Element>> | null;
  /** Set once the reports are in, so the comparison can start or be retried. */
  info: MrInfo | null;
  /** What the rendered reports were read from, for a refresh to compare against. */
  discovery: Discovery | null;
  reportCache: ReportCache;
  /**
   * Bumped whenever the rendered reports are replaced, so a comparison that was
   * started against the old ones knows not to land on the new.
   */
  generation: number;
  comparing: boolean;
  /** A refresh replaced the reports while a comparison was in flight. */
  compareAgain: boolean;
  refreshing: boolean;
}

export default defineContentScript({
  // gitlab.com is declared here; self-managed instances are registered at
  // runtime by the background script once the user grants access to them.
  matches: ['*://gitlab.com/*'],
  runAt: 'document_idle',

  async main(ctx) {
    const initial = await getSettings();
    setVerbose(initial.verboseLogging);

    // Proof of life: if this line is absent from the console, the content script
    // itself never ran and the problem is registration, not detection.
    log('content script active on', location.href);

    let session: Session | null = null;

    const teardown = () => {
      session?.abort.abort();
      session?.ui?.remove();
      session = null;
    };

    const sync = async () => {
      const page = parseMrPath(location.pathname);
      if (!page) {
        bail('not a merge request page', location.pathname);
        teardown();
        return;
      }
      if (!looksLikeGitLab()) {
        bail('page does not look like GitLab (no GitLab meta tags or layout found)');
        teardown();
        return;
      }

      // Switching between the Overview and Changes tabs fires a location change
      // but stays on the same merge request; there is nothing to re-fetch.
      if (session?.page.iid === page.iid) {
        log('already handling merge request', page.iid);
        return;
      }

      teardown();
      log('handling merge request', page.iid, 'in', page.pathPrefix);

      const active: Session = {
        page,
        abort: new AbortController(),
        store: reactive<Store>({
          state: { status: 'loading', reportTypes: [] },
          settings: await getSettings(),
          refreshing: false,
        }) as Store,
        ui: null,
        info: null,
        discovery: null,
        reportCache: new Map(),
        generation: 0,
        comparing: false,
        compareAgain: false,
        refreshing: false,
      };
      session = active;

      try {
        await run(ctx, page, active);
      } catch (cause) {
        logError('failed to render the widget', cause);
      }

      // A navigation during the fetch above already tore this session down.
      if (active.abort.signal.aborted) active.ui?.remove();
    };

    await sync();

    ctx.addEventListener(window, 'wxt:locationchange', () => {
      void sync();
    });

    // Keep an already-rendered widget's filters in step with the options page.
    let applied = initial;
    settings.watch((value) => {
      const next = withDefaults(value);
      const previous = applied;
      applied = next;

      setVerbose(next.verboseLogging);
      if (!session) return;
      session.store.settings = next;

      // Turning the comparison on or off should not require a reload, and nor
      // should raising how many base pipelines it may try — that is a request to
      // have another go. Every other setting is a pure re-filter of what is
      // already rendered and must not re-issue the comparison's requests:
      // without this an unrelated tweak retries a comparison that already
      // concluded it had no base to use. (`childPipelineDepth` is left out
      // deliberately — it also governs the head pipeline's discovery, which has
      // already happened, so it takes effect on the next page load.)
      const affectsComparison =
        next.compareWithTargetBranch !== previous.compareWithTargetBranch ||
        next.maxBasePipelines !== previous.maxBasePipelines;
      if (!affectsComparison) return;
      if (next.compareWithTargetBranch) void compare(session);
      else dropComparison(session);
    });

    ctx.onInvalidated(teardown);
  },
});

async function run(
  ctx: ContentScriptContext,
  page: MrPageContext,
  session: Session,
): Promise<void> {
  const { signal } = session.abort;
  const outcome = await discoverReports(page, session.store.settings);
  if (signal.aborted || ctx.isInvalid) return;

  // No pipeline, or a merge request page we cannot read: stay invisible.
  if (outcome.status === 'not-applicable') {
    bail(outcome.reason);
    return;
  }

  if (outcome.status === 'error') {
    logError(outcome.message);
    session.store.state = { status: 'error', message: outcome.message };
    session.ui = await mountWidget(ctx, signal, session);
    return;
  }

  let { discovery } = outcome;

  // A pipeline that has only just started has uploaded no reports yet, which is
  // not the same as having no security scanning. Wait, invisibly, for the first
  // report or for the pipeline to finish before deciding which it is.
  while (
    discovery.sources.length === 0 &&
    isRunning(discovery.progress) &&
    session.store.settings.autoRefresh
  ) {
    await new Promise<void>((resolve) =>
      ctx.setTimeout(resolve, pollDelay(session.store.settings, true)),
    );
    if (signal.aborted || ctx.isInvalid) return;
    if (document.visibilityState !== 'visible') continue;

    const next = await discoverReports(page, session.store.settings);
    if (signal.aborted) return;
    if (next.status === 'found') discovery = next.discovery;
  }

  session.info = discovery.info;
  session.discovery = discovery;

  // Stay invisible on merge requests that simply have no security scanning.
  if (discovery.sources.length === 0) {
    bail(
      `pipeline ${discovery.info.pipelineId} has no security report artifacts ` +
        '(the jobs and their artifact types are logged above)',
    );
    return;
  }

  session.store.state = {
    status: 'loading',
    reportTypes: discovery.sources.map((source) => source.reportType),
  };
  session.ui = await mountWidget(ctx, signal, session);
  if (!session.ui) return;

  // From here on the widget is on screen, so keep it current — including when
  // the download below fails, which a later attempt may well get past.
  schedulePoll(ctx, session);

  try {
    const result = await loadReports(page, discovery, session.reportCache);
    if (signal.aborted) return;

    log(`rendered ${result.findings.length} finding(s)`, result.counts);
    session.store.state = {
      status: 'ok',
      result: {
        ...result,
        comparison: session.store.settings.compareWithTargetBranch
          ? { status: 'loading' }
          : { status: 'off' },
      },
    };
  } catch (cause) {
    logError('failed to download the reports', cause);
    if (!signal.aborted) {
      session.store.state = {
        status: 'error',
        message: cause instanceof Error ? cause.message : String(cause),
      };
    }
    return;
  }

  // Phase three, unawaited: the findings are on screen and the comparison costs
  // a second pipeline's worth of requests, so nothing waits for it.
  void compare(session);
}

function schedulePoll(ctx: ContentScriptContext, session: Session): void {
  if (session.abort.signal.aborted || !session.discovery) return;
  const delay = pollDelay(session.store.settings, isRunning(session.discovery.progress));
  ctx.setTimeout(() => void poll(ctx, session), delay);
}

/**
 * Keeps ticking with automatic updates turned off, doing nothing, so that
 * turning them back on in the options takes effect without a reload.
 */
async function poll(ctx: ContentScriptContext, session: Session): Promise<void> {
  if (session.abort.signal.aborted || ctx.isInvalid) return;
  // Nobody is looking at a background tab; it catches up on the next tick
  // after it is shown again.
  if (session.store.settings.autoRefresh && document.visibilityState === 'visible') {
    await refresh(session, { manual: false });
  }
  schedulePoll(ctx, session);
}

/**
 * Re-reads the merge request and re-renders it in place if anything changed: a
 * scan job finished, or a push started a new pipeline.
 *
 * A manual refresh is the user asking to look again, so it skips the shortcut
 * for a finished pipeline, re-renders even if nothing seems to have changed,
 * and forgets the cached base reports so the target branch is read afresh too.
 */
async function refresh(session: Session, { manual }: { manual: boolean }): Promise<void> {
  const previous = session.discovery;
  if (!previous || session.refreshing) return;

  const { signal } = session.abort;
  session.refreshing = true;
  session.store.refreshing = manual;

  try {
    if (manual) clearBaseReportCache();
    const outcome = manual
      ? await discoverReports(session.page, session.store.settings)
      : await rediscoverReports(session.page, session.store.settings, previous);
    if (signal.aborted) return;

    // A failed check leaves what is on screen alone; the next one may succeed.
    if (outcome.status !== 'found') {
      log('refresh skipped:', outcome.status === 'error' ? outcome.message : outcome.reason);
      return;
    }

    const { discovery } = outcome;
    if (!manual && !discoveryChanged(previous, discovery) && session.store.state.status === 'ok') {
      return;
    }
    log(`refreshing pipeline ${discovery.info.pipelineId}`);

    if (discovery.info.pipelineId !== previous.info.pipelineId) session.reportCache.clear();
    const result = await loadReports(session.page, discovery, session.reportCache);
    if (signal.aborted) return;

    // The previous comparison stays up until the new one lands, rather than the
    // line flashing back to "Comparing…" every time a job finishes.
    const { state } = session.store;
    const enabled = session.store.settings.compareWithTargetBranch;
    const comparison =
      state.status === 'ok' && enabled
        ? state.result.comparison
        : ({ status: enabled ? 'loading' : 'off' } as const);

    session.discovery = discovery;
    session.info = discovery.info;
    session.generation += 1;
    session.store.state = { status: 'ok', result: { ...result, comparison } };
    log(`rendered ${result.findings.length} finding(s)`, result.counts);

    await compare(session, { refresh: true });
  } catch (cause) {
    logError('failed to refresh the widget', cause);
  } finally {
    session.refreshing = false;
    session.store.refreshing = false;
  }
}

/** Clears the labels when the user turns the comparison off. */
function dropComparison(session: Session): void {
  const { state } = session.store;
  if (state.status !== 'ok' || state.result.comparison.status === 'off') return;
  session.store.state = { status: 'ok', result: { ...state.result, comparison: { status: 'off' } } };
}

/**
 * Compares the rendered findings against the target branch, in place.
 *
 * Safe to call more than once — it returns early unless there is a rendered
 * result without a comparison, which is what lets the settings watcher start one
 * when the user turns the feature on. A previous `unavailable` is retried on that
 * path, since switching the feature back on is a request to try again; the
 * watcher is what keeps unrelated settings changes off it.
 *
 * `refresh` is for reports that have just been replaced: a comparison already
 * on screen is redone in place, and one already in flight is redone once it
 * returns, since it was started against the reports that are gone.
 */
async function compare(session: Session, { refresh = false } = {}): Promise<void> {
  const { state } = session.store;
  if (session.comparing) {
    if (refresh) session.compareAgain = true;
    return;
  }
  if (!session.info) return;
  if (!session.store.settings.compareWithTargetBranch) return;
  if (state.status !== 'ok') return;
  if (!refresh && state.result.comparison.status === 'ready') return;

  session.comparing = true;
  session.compareAgain = false;
  const { signal } = session.abort;
  const result = state.result;
  const generation = session.generation;
  const stale = () => {
    if (session.generation === generation) return false;
    session.compareAgain = true;
    return true;
  };

  try {
    if (result.comparison.status === 'off' || result.comparison.status === 'unavailable') {
      session.store.state = { status: 'ok', result: { ...result, comparison: { status: 'loading' } } };
    }

    const comparison = await loadComparison(
      session.page,
      session.info,
      result,
      session.store.settings,
    );
    // The user may have turned the comparison off while it was in flight.
    if (signal.aborted || !session.store.settings.compareWithTargetBranch) return;
    if (stale()) return;

    if (comparison.status === 'unavailable') log('no comparison:', comparison.reason);
    session.store.state = { status: 'ok', result: { ...result, comparison } };
  } catch (cause) {
    logError('failed to compare with the target branch', cause);
    if (!signal.aborted && !stale()) {
      session.store.state = {
        status: 'ok',
        result: {
          ...result,
          comparison: {
            status: 'unavailable',
            reason: cause instanceof Error ? cause.message : String(cause),
          },
        },
      };
    }
  } finally {
    session.comparing = false;
    if (session.compareAgain && !signal.aborted) void compare(session, { refresh: true });
  }
}

async function mountWidget(
  ctx: ContentScriptContext,
  signal: AbortSignal,
  session: Session,
): Promise<IntegratedContentScriptUi<App<Element>> | null> {
  const { store } = session;
  const anchor = await waitForAnchor(signal);
  if (!anchor) {
    bail('found nothing on the page to attach the widget to');
    return null;
  }
  if (signal.aborted || ctx.isInvalid) return null;

  const ui = createIntegratedUi(ctx, {
    position: 'inline',
    anchor: anchor.element,
    append: anchor.append,
    onMount(container) {
      // A render function rather than a static props object, so the reactive
      // store drives updates as the reports finish downloading.
      const app = createApp(() =>
        h(SecurityWidget, {
          state: store.state,
          settings: store.settings,
          refreshing: store.refreshing,
          onRefresh: () => void refresh(session, { manual: true }),
        }),
      );
      app.mount(container);
      return app;
    },
    onRemove(app) {
      app?.unmount();
    },
  });

  ui.mount();
  fitHost(ui.wrapper);
  log('widget mounted', anchor.append, anchor.selector);
  return ui;
}
