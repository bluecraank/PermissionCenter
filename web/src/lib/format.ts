import type { Principal, Severity } from './api'

const nf = new Intl.NumberFormat('de-DE')

export function num(n: number | null | undefined): string {
  return n === null || n === undefined ? '–' : nf.format(n)
}

export function bytes(n: number | null | undefined): string {
  if (!n) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toLocaleString('de-DE', { maximumFractionDigits: v < 10 ? 1 : 0 })} ${units[i]}`
}

export function dateTime(s: string | null | undefined): string {
  if (!s) return '–'
  const d = new Date(s)
  return isNaN(d.getTime())
    ? s
    : d.toLocaleString('de-DE', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' })
}

export function date(s: string | null | undefined): string {
  if (!s) return '–'
  const d = new Date(s)
  return isNaN(d.getTime()) ? s : d.toLocaleDateString('de-DE')
}

export function relative(s: string | null | undefined): string {
  if (!s) return 'nie'
  const diff = (Date.now() - new Date(s).getTime()) / 1000
  if (diff < 60) return 'gerade eben'
  if (diff < 3600) return `vor ${Math.round(diff / 60)} Min.`
  if (diff < 86400) return `vor ${Math.round(diff / 3600)} Std.`
  return `vor ${Math.round(diff / 86400)} Tagen`
}

export function duration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return '–'
  if (ms < 1000) return `${ms} ms`
  const s = ms / 1000
  if (s < 60) return `${s.toFixed(1)} s`
  return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`
}

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export const severityLabel: Record<Severity, string> = {
  critical: 'Kritisch',
  high: 'Hoch',
  medium: 'Mittel',
  low: 'Niedrig',
  info: 'Info',
}

export const severityColor: Record<Severity, string> = {
  critical: 'var(--sev-critical)',
  high: 'var(--sev-high)',
  medium: 'var(--sev-medium)',
  low: 'var(--sev-low)',
  info: 'var(--sev-info)',
}

export const statusLabel: Record<Principal['status'], string> = {
  active: 'Aktiv',
  disabled: 'Deaktiviert',
  inactive: 'Inaktiv',
  orphaned: 'Verwaist',
  system: 'System',
  unknown: 'Unbekannt',
}

export const kindLabel: Record<string, string> = {
  user: 'Benutzer',
  group: 'Gruppe',
  computer: 'Computer',
  well_known: 'Integriert',
  unknown: 'Unbekannt',
}

export const rootKindLabel: Record<string, string> = {
  local_drive: 'Laufwerk',
  share: 'Freigabe',
  remote: 'Netzlaufwerk',
}

export function gradeColor(grade: string): string {
  switch (grade) {
    case 'A':
      return 'var(--ok)'
    case 'B':
      return 'oklch(0.72 0.15 130)'
    case 'C':
      return 'var(--sev-medium)'
    case 'D':
    case 'E':
      return 'var(--sev-high)'
    default:
      return 'var(--sev-critical)'
  }
}
