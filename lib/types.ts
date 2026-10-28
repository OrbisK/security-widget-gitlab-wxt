/**
 * GitLab CI artifact `file_type` values that hold a security report, in the
 * order we want to present them. These map 1:1 onto `artifacts:reports:<type>`
 * keys in .gitlab-ci.yml and onto `?file_type=` on the artifact download route.
 */
export const SECURITY_REPORT_TYPES = [
  'sast',
  'secret_detection',
  'dependency_scanning',
  'container_scanning',
  'cluster_image_scanning',
  'dast',
  'api_fuzzing',
  'coverage_fuzzing',
] as const;

export type ReportType = (typeof SECURITY_REPORT_TYPES)[number];

export const REPORT_TYPE_LABELS: Record<ReportType, string> = {
  sast: 'SAST',
  secret_detection: 'Secret detection',
  dependency_scanning: 'Dependency scanning',
  container_scanning: 'Container scanning',
  cluster_image_scanning: 'Cluster image scanning',
  dast: 'DAST',
  api_fuzzing: 'API fuzzing',
  coverage_fuzzing: 'Coverage fuzzing',
};

export function isSecurityReportType(value: string): value is ReportType {
  return (SECURITY_REPORT_TYPES as readonly string[]).includes(value);
}

/** Severity levels as used by the GitLab security report schema, worst first. */
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'unknown'] as const;

export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  info: 'Info',
  unknown: 'Unknown',
};

/** A single job artifact that we can download a security report from. */
export interface ReportSource {
  reportType: ReportType;
  jobId: number;
  jobName: string;
  /** Absolute URL of the job, e.g. https://gitlab.example/group/proj/-/jobs/42 */
  jobWebUrl: string;
  /** Absolute URL the raw report JSON is downloaded from. */
  downloadUrl: string;
  /**
   * `artifacts_expire_at` for the owning job, when the jobs API reported one.
   * Only used to tell a definitely-expired artifact from one that 404s for some
   * other reason.
   */
  artifactsExpireAt?: string;
}

/**
 * Why an artifact we discovered could not be read.
 *
 * `expired` is the benign case: the job listed the artifact but the file is
 * gone, so there is nothing to show and nothing for the user to fix.
 * `unavailable` is anything else and is worth surfacing as a fault.
 */
export interface ReportError {
  kind: 'expired' | 'unavailable';
  message: string;
}

/** One normalized vulnerability, flattened out of a report's own schema. */
export interface Finding {
  reportType: ReportType;
  severity: Severity;
  name: string;
  description?: string;
  scanner?: string;
  /**
   * The scanner's machine id, e.g. "semgrep" or "gitleaks". Unlike the display
   * name it is stable between analyzer versions, so it is what decides how a
   * finding can be suppressed in source.
   */
  scannerId?: string;
  file?: string;
  startLine?: number;
  endLine?: number;
  /** Link into the repository at the reported file/line, when resolvable. */
  blobUrl?: string;
  /** e.g. "CWE-79", "CVE-2021-1234", "A03:2021" */
  identifiers: string[];
  /**
   * The same identifiers with their type kept, e.g. `semgrep_id: bandit.B101`
   * or `kics_id: <query uuid>` — the scanner's own rule id is what an inline
   * suppression has to name. Only identifiers that carry both are listed.
   */
  typedIdentifiers?: { type: string; value: string }[];
  solution?: string;
  links: { name?: string; url: string }[];
  /** Dependency scanning / container scanning only. */
  dependency?: string;
  /** Fallback location text for report types with no file, such as DAST. */
  locationLabel?: string;
  /**
   * Discrete location parts the branch comparison fingerprints on. They overlap
   * with `dependency` and `locationLabel`, which are formatted for display and
   * fold several fields into one string.
   */
  packageName?: string;
  image?: string;
  path?: string;
  param?: string;
  /** True when the scanner flagged this as a likely false positive. */
  likelyFalsePositive: boolean;
  /**
   * The report's own `vulnerabilities[].id`, when it supplied one. Only ever
   * used as a match hint: two findings sharing an id are the same finding, but
   * analyzers hash line numbers into it, so a mismatch means nothing.
   */
  reportId?: string;
  /** Unique within one scan, used for list rendering and status lookup. */
  key: string;
}

/** Everything one report artifact contributed. */
export interface ParsedReport {
  reportType: ReportType;
  source: ReportSource;
  scanners: string[];
  findings: Finding[];
  /** Set when the artifact was found but could not be read. */
  error?: ReportError;
}

export interface SeverityCounts extends Record<Severity, number> {
  total: number;
}

/**
 * Where a finding stands relative to the target branch.
 *
 * `uncomparable` is the honest answer when the target branch has no readable
 * report of that type: the finding may well be new, but nothing was read that
 * could rule it out. `fixed` only ever describes a finding from the base
 * report — one the target branch has and this merge request does not.
 */
export type FindingStatus = 'new' | 'existing' | 'uncomparable' | 'fixed';

/**
 * The pipeline the comparison was made against, and how it was chosen — the two
 * strategies support different claims, so the widget names the one it used.
 *
 * `merge-base` is the pipeline for the commit this merge request branched from,
 * which is what GitLab's own comparison uses. `target-branch` is the target
 * branch's latest finished pipeline, used when the merge base has none; it can
 * include commits this merge request never saw.
 */
export interface BasePipeline {
  strategy: 'merge-base' | 'target-branch';
  pipelineId: number;
  pipelineWebUrl?: string;
  targetBranch: string;
  sha?: string;
  /** The commit the comparison was made against, so it can be inspected. */
  commitWebUrl?: string;
}

export interface Comparison {
  base: BasePipeline;
  /** `Finding.key` of a head finding -> its status. Never holds `fixed`. */
  status: Record<string, FindingStatus>;
  /** Findings the target branch has that this merge request no longer reports. */
  fixed: Finding[];
  newFindings: Finding[];
  newCounts: SeverityCounts;
  existingCount: number;
  uncomparableCount: number;
  /**
   * How much of the base we actually read. A type stays comparable as long as
   * one job reported it, so a second job of that type whose artifact expired
   * leaves a partial base — which can only over-report findings as new. Shown
   * rather than acted on, since the alternative is discarding a comparison that
   * is mostly sound.
   */
  baseReportCount: number;
  baseUnreadableCount: number;
}

/**
 * The comparison is fetched after the head reports are already on screen, so it
 * has its own lifecycle. `off` means the user turned it off; `unavailable`
 * means we could not establish a base and therefore label nothing.
 */
export type ComparisonState =
  | { status: 'off' }
  | { status: 'loading' }
  | { status: 'unavailable'; reason: string }
  | { status: 'ready'; comparison: Comparison };

export interface ScanResult {
  reports: ParsedReport[];
  findings: Finding[];
  counts: SeverityCounts;
  pipelineId: number;
  pipelineWebUrl?: string;
  comparison: ComparisonState;
}

/** What the injected widget is currently displaying. */
export type WidgetState =
  | { status: 'loading'; reportTypes: ReportType[] }
  | { status: 'error'; message: string }
  | { status: 'ok'; result: ScanResult };
