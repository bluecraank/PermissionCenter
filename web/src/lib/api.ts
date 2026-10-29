// Typisierter Zugriff auf die REST-API des PermissionCenter-Servers.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type SeverityCounts = Record<Severity, number>

export interface Score {
  score: number
  grade: string
  penalty: number
}

export interface SystemSummary {
  id: number
  hostname: string
  domain: string | null
  os_name: string | null
  os_version: string | null
  os_build: number | null
  is_dc: boolean
  client_version: string | null
  first_seen: string
  last_seen: string
  last_scan_at: string | null
  folders_scanned: number | null
  folders_reported: number | null
  folders_excluded: number | null
  errors: number | null
  orphaned_aces: number | null
  duration_ms: number | null
  explicit_folders: number | null
  protected_folders: number | null
  report_mode: string | null
  shares: number
  score: Score
  findings: SeverityCounts
}

export interface ScanRoot {
  path: string
  kind: 'local_drive' | 'share' | 'remote'
  folder_id: number | null
  folders_scanned: number
  folders_excluded: number
  errors: number
}

export interface SystemDetail extends SystemSummary {
  scan: {
    uuid: string
    report_mode: string
    started_at: string
    finished_at: string
    roots: ScanRoot[]
    errors: { path: string; code: number | null; message: string }[] | null
  } | null
}

export interface AdInfo {
  loaded: boolean
  domain: string | null
  domain_sid: string | null
  synced_at: string | null
  source: string | null
  users: number
  computers: number
  groups: number
}

export interface RuleStat {
  rule: string
  title: string
  severity: Severity
  findings: number
  affected: number
}

export interface Dashboard {
  score: Score
  infrastructure_score: Score
  ad_score: Score
  totals: {
    systems: number
    folders_scanned: number
    folders_reported: number
    explicit_folders: number
    scan_errors: number
    shares: number
    principals: number
  }
  findings: SeverityCounts
  top_rules: RuleStat[]
  systems: SystemSummary[]
  recent_scans: { system_id: number; hostname: string; received_at: string; folders_scanned: number; errors: number }[]
  ad: AdInfo
  analysis_at: string | null
}

export interface Principal {
  sid: string
  name: string
  kind: 'user' | 'group' | 'computer' | 'well_known' | 'unknown'
  status: 'active' | 'disabled' | 'inactive' | 'orphaned' | 'system' | 'unknown'
  in_ad: boolean
  description: string | null
}

export interface Ace {
  principal: Principal
  ace_type: 'allow' | 'deny' | 'audit' | 'other'
  mask: string
  rights: string
  rights_label: string
  inherited: boolean | null
  flags: number | null
  applies_to: string | null
}

export interface Folder {
  local_id: number
  parent_local_id: number | null
  name: string
  path: string
  depth: number
  owner_sid: string | null
  protected: boolean
  explicit: boolean
  acl_source_local_id: number | null
  subfolder_total: number
  file_count: number
  file_bytes: number
  is_root: boolean
  error: string | null
  children: number
  explicit_aces: number
  findings: number
}

export interface FolderDetail extends Folder {
  aces: Ace[]
  owner?: Principal
  breadcrumbs: { local_id: number; name: string }[]
  acl_source_path: string | null
  shares: string[]
  finding_list: { id: number; rule: string; severity: Severity; title: string }[]
}

export interface Share {
  id: number
  name: string
  path: string
  remark: string | null
  share_type: number
  is_special: boolean
  has_sd: boolean
  folder_local_id: number | null
  permissions: Ace[]
}

export interface Finding {
  id: number
  system_id: number | null
  hostname: string | null
  rule: string
  rule_title: string | null
  severity: Severity
  title: string
  detail: string | null
  path: string | null
  sid: string | null
  affected: number
  created_at: string
  recommendation: string | null
}

export interface Recommendation {
  priority: number
  rule: string
  severity: Severity
  scope: 'system' | 'ad'
  title: string
  description: string
  recommendation: string
  findings: number
  affected: number
  systems: string[]
  effort: string
}

export interface AuditCheck {
  rule: string
  title: string
  description: string
  recommendation: string
  severity: Severity
  scope: 'system' | 'ad'
  passed: boolean
  findings: number
  affected: number
  systems_failed: number
  systems_total: number
}

export interface Audit {
  score: Score
  ad_score: Score
  ad: AdInfo
  systems: SystemSummary[]
  checks: AuditCheck[]
  analysis_at: string | null
}

export interface PrincipalRow extends Principal {
  explicit_aces: number
  systems: number
  share_aces: number
}

export interface AccessEntry {
  kind: 'folder' | 'share'
  system_id: number
  hostname: string
  local_id: number | null
  path: string
  share: string | null
  ace_type: string
  rights: string
  rights_label: string
  via: Principal | null
}

export interface PrincipalDetail {
  principal: Principal
  ad: Record<string, unknown> | null
  direct_access: AccessEntry[]
  indirect_access: AccessEntry[]
  member_of: { group: Principal; direct: boolean; path: string[] }[]
  members: Principal[]
  findings: { id: number; rule: string; severity: Severity; title: string; path: string | null; hostname: string | null }[]
}

export interface AdSummary extends AdInfo {
  disabled_users: number
  inactive_users: number
  empty_groups: number
  ldap_configured: boolean
  score: Score
  findings: SeverityCounts
}

export interface AdUserRow {
  sid: string
  name: string
  sam: string
  display_name: string | null
  upn: string | null
  enabled: boolean
  status: Principal['status']
  last_logon: string | null
  created: string | null
  groups: number
  explicit_aces: number
}

export interface AdGroupRow {
  sid: string
  name: string
  sam: string
  description: string | null
  scope: string | null
  is_security: boolean
  members: number
  transitive_users: number
  explicit_aces: number
  status: 'ok' | 'empty' | 'orphaned' | 'unused'
}

export interface GraphNode {
  id: string
  label: string
  type: string
  status?: string
  system_id?: number
  local_id?: number
  sid?: string
  grade?: string
  score?: number
  path?: string
  protected?: boolean
  error?: boolean
}

export interface GraphEdge {
  id: string
  source: string
  target: string
  type: string
  label: string | null
}

export interface GraphData {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export interface Settings {
  version: string
  listen: string
  database: string
  upload_token_required: boolean
  auth_mode: string
  ldap: { configured: boolean; url: string | null; base_dn: string | null; bind_dn: string | null; sync_interval_minutes: number }
  analysis: { inactive_days: number; stale_scan_days: number; deep_explicit_depth: number; max_findings_per_rule: number }
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(method: string, path: string, body?: BodyInit, headers?: HeadersInit): Promise<T> {
  const res = await fetch(`/api/v1${path}`, { method, body, headers })
  if (!res.ok) {
    let msg = res.statusText
    try {
      const j = await res.json()
      msg = j.error ?? msg
    } catch {
      /* keine JSON-Antwort */
    }
    throw new ApiError(res.status, msg)
  }
  return res.json() as Promise<T>
}

export function qs(params: Record<string, string | number | undefined | null>): string {
  const p = new URLSearchParams()
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '' && v !== 'all') p.set(k, String(v))
  }
  const s = p.toString()
  return s ? `?${s}` : ''
}

export const api = {
  get: <T>(path: string) => request<T>('GET', path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(
      'POST',
      path,
      body === undefined ? undefined : body instanceof Blob ? body : JSON.stringify(body),
      { 'Content-Type': 'application/json' },
    ),
  delete: <T>(path: string) => request<T>('DELETE', path),
}

export interface ClientRelease {
  version: string
  sha256: string
  size: number
  signature: string | null
  published_at: string
  notes: string | null
  download_url: string
}

export interface ClientReleases {
  releases: ClientRelease[]
  latest: string | null
  signature_required: boolean
  public_key: string | null
  systems: { id: number; hostname: string; client_version: string | null; last_seen: string; outdated: boolean }[]
}
