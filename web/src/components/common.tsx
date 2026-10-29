import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, Ban, Bot, Inbox, Loader2, Monitor, ShieldQuestion, User, Users } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import type { Principal, Score, Severity, SeverityCounts } from '@/lib/api'
import { gradeColor, kindLabel, num, SEVERITIES, severityColor, severityLabel, statusLabel } from '@/lib/format'
import { cn } from '@/lib/utils'

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-col gap-3 md:flex-row md:items-end md:justify-between">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {description && <p className="text-muted-foreground mt-1 text-sm">{description}</p>}
      </div>
      {actions && <div className="flex flex-wrap gap-2">{actions}</div>}
    </div>
  )
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <Badge
      variant="outline"
      className={cn('gap-1.5 font-medium', className)}
      style={{ borderColor: severityColor[severity], color: severityColor[severity] }}
    >
      <span className="size-1.5 rounded-full" style={{ background: severityColor[severity] }} />
      {severityLabel[severity]}
    </Badge>
  )
}

export function SeverityDots({ counts, hideZero = true }: { counts: SeverityCounts; hideZero?: boolean }) {
  const items = SEVERITIES.filter((s) => s !== 'info' && (!hideZero || counts[s] > 0))
  if (items.length === 0) return <span className="text-muted-foreground text-xs">keine</span>
  return (
    <div className="flex items-center gap-2">
      {items.map((s) => (
        <span key={s} className="flex items-center gap-1 text-xs tabular-nums" title={severityLabel[s]}>
          <span className="size-2 rounded-full" style={{ background: severityColor[s] }} />
          {num(counts[s])}
        </span>
      ))}
    </div>
  )
}

const statusVariant: Record<Principal['status'], string> = {
  active: 'text-ok border-ok/40',
  disabled: 'text-sev-medium border-sev-medium/50',
  inactive: 'text-sev-low border-sev-low/50',
  orphaned: 'text-sev-high border-sev-high/50 bg-sev-high/10',
  system: 'text-muted-foreground',
  unknown: 'text-muted-foreground',
}

export function StatusBadge({ status }: { status: Principal['status'] }) {
  return (
    <Badge variant="outline" className={cn('font-normal', statusVariant[status])}>
      {statusLabel[status]}
    </Badge>
  )
}

export function PrincipalIcon({ kind, status, className }: { kind: string; status?: string; className?: string }) {
  const cls = cn('size-4 shrink-0', status === 'orphaned' && 'text-sev-high', className)
  if (status === 'orphaned') return <ShieldQuestion className={cls} />
  switch (kind) {
    case 'user':
      return <User className={cls} />
    case 'group':
      return <Users className={cls} />
    case 'computer':
      return <Monitor className={cls} />
    case 'well_known':
      return <Bot className={cls} />
    default:
      return <Ban className={cls} />
  }
}

export function PrincipalLink({ p, showSid = false }: { p: Principal; showSid?: boolean }) {
  return (
    <Link
      to={`/principals/${encodeURIComponent(p.sid)}`}
      className="group inline-flex min-w-0 items-center gap-2 hover:underline"
      title={`${kindLabel[p.kind] ?? p.kind} · ${p.sid}`}
    >
      <PrincipalIcon kind={p.kind} status={p.status} />
      <span className={cn('truncate', p.status === 'orphaned' && 'text-sev-high font-medium')}>{p.name}</span>
      {showSid && p.name !== p.sid && <span className="text-muted-foreground truncate font-mono text-xs">{p.sid}</span>}
    </Link>
  )
}

export function GradeBadge({ score, size = 'md' }: { score: Score; size?: 'sm' | 'md' }) {
  return (
    <span
      className={cn(
        'inline-flex items-center justify-center rounded-md font-bold text-white',
        size === 'sm' ? 'size-6 text-xs' : 'size-8 text-sm',
      )}
      style={{ background: gradeColor(score.grade) }}
      title={`${score.score} von 100 Punkten`}
    >
      {score.grade}
    </span>
  )
}

/** Halbkreis-Anzeige der Bewertung (0–100). */
export function ScoreGauge({ score, label }: { score: Score; label: string }) {
  const r = 52
  const c = Math.PI * r
  const offset = c * (1 - score.score / 100)
  const color = gradeColor(score.grade)
  return (
    <div className="flex flex-col items-center">
      <svg viewBox="0 0 120 70" className="w-40">
        <path d="M8 62 A52 52 0 0 1 112 62" fill="none" stroke="var(--muted)" strokeWidth="10" strokeLinecap="round" />
        <path
          d="M8 62 A52 52 0 0 1 112 62"
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset .6s ease' }}
        />
        <text x="60" y="52" textAnchor="middle" className="fill-foreground text-[22px] font-bold">
          {score.score}
        </text>
        <text x="60" y="66" textAnchor="middle" className="fill-muted-foreground text-[9px]">
          Note {score.grade}
        </text>
      </svg>
      <span className="text-muted-foreground -mt-1 text-xs">{label}</span>
    </div>
  )
}

export function StatCard({
  title,
  value,
  icon,
  hint,
  to,
  tone,
}: {
  title: string
  value: ReactNode
  icon?: ReactNode
  hint?: ReactNode
  to?: string
  tone?: 'warn' | 'bad'
}) {
  const body = (
    <Card className={cn('gap-2 py-4 transition-colors', to && 'hover:bg-accent/50')}>
      <CardHeader className="flex flex-row items-center justify-between px-4 pb-0">
        <CardTitle className="text-muted-foreground text-sm font-medium">{title}</CardTitle>
        <span className="text-muted-foreground">{icon}</span>
      </CardHeader>
      <CardContent className="px-4">
        <div
          className={cn(
            'text-2xl font-semibold tabular-nums',
            tone === 'warn' && 'text-sev-medium',
            tone === 'bad' && 'text-sev-high',
          )}
        >
          {value}
        </div>
        {hint && <p className="text-muted-foreground mt-1 text-xs">{hint}</p>}
      </CardContent>
    </Card>
  )
  return to ? <Link to={to}>{body}</Link> : body
}

export function Loading({ rows = 4 }: { rows?: number }) {
  return (
    <div className="space-y-3">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-10 w-full" />
      ))}
    </div>
  )
}

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cn('size-4 animate-spin', className)} />
}

export function ErrorState({ error }: { error: unknown }) {
  return (
    <Alert variant="destructive">
      <AlertTriangle />
      <AlertTitle>Daten konnten nicht geladen werden</AlertTitle>
      <AlertDescription>{error instanceof Error ? error.message : String(error)}</AlertDescription>
    </Alert>
  )
}

export function EmptyState({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="text-muted-foreground flex flex-col items-center justify-center gap-2 rounded-lg border border-dashed p-10 text-center">
      <Inbox className="size-8 opacity-60" />
      <p className="text-foreground font-medium">{title}</p>
      {children && <div className="max-w-md text-sm">{children}</div>}
    </div>
  )
}

export function RightsBadge({ label, deny }: { label: string; deny?: boolean }) {
  return (
    <Badge variant={deny ? 'destructive' : 'secondary'} className="font-normal">
      {deny ? 'Verweigern: ' : ''}
      {label}
    </Badge>
  )
}
