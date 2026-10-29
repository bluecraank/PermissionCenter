import { useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { ArrowRight, ChevronLeft, ChevronRight } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { EmptyState, ErrorState, Loading, PrincipalLink } from '@/components/common'
import { api, qs, type ChangeItem, type ChangesResponse, type HistoryRow } from '@/lib/api'
import { date, dateTime, num } from '@/lib/format'
import { cn } from '@/lib/utils'

const SERIES: { key: 'total' | 'infra' | 'ad' | 'system'; label: string; color: string }[] = [
  { key: 'total', label: 'Gesamt', color: 'var(--series-1)' },
  { key: 'infra', label: 'Dateisysteme', color: 'var(--series-2)' },
  { key: 'ad', label: 'Active Directory', color: 'var(--series-3)' },
]

const tooltipStyle = { background: 'var(--popover)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }

/** Verlauf der Punktzahl (0–100) – gesamt, Dateisysteme und AD bzw. ein System. */
export function ScoreTrend({ systemId, days = 90, height = 220 }: { systemId?: number; days?: number; height?: number }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['history', systemId ?? null, days],
    queryFn: () => api.get<HistoryRow[]>(`/history${qs({ system_id: systemId, days })}`),
  })
  if (error) return <ErrorState error={error} />
  if (isLoading || !data) return <Loading rows={3} />
  const series = systemId ? [{ key: 'system' as const, label: 'Punktzahl', color: 'var(--series-1)' }] : SERIES
  const byDay = new Map<string, Record<string, number | string>>()
  for (const r of data) {
    const row = byDay.get(r.day) ?? { day: r.day }
    row[r.scope] = r.score
    byDay.set(r.day, row)
  }
  const rows = [...byDay.values()]
  if (rows.length < 2)
    return (
      <p className="text-muted-foreground py-6 text-center text-sm">
        Der Verlauf erscheint, sobald Bewertungen von mindestens zwei Tagen vorliegen.
      </p>
    )
  return (
    <div style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={rows} margin={{ left: -20, right: 8, top: 8 }}>
          <CartesianGrid vertical={false} stroke="var(--border)" strokeDasharray="3 3" />
          <XAxis dataKey="day" tickFormatter={(d) => date(d)} tickLine={false} axisLine={false} fontSize={12} minTickGap={24} />
          <YAxis domain={[0, 100]} tickLine={false} axisLine={false} fontSize={12} />
          <Tooltip contentStyle={tooltipStyle} labelFormatter={(d) => date(String(d))} />
          {series.length > 1 && <Legend iconType="plainline" wrapperStyle={{ fontSize: 12 }} />}
          {series.map((s) => (
            <Line
              key={s.key}
              dataKey={s.key}
              name={s.label}
              stroke={s.color}
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 4 }}
              connectNulls
              isAnimationActive={false}
              type="monotone"
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  )
}

const changeTone: Record<string, string> = {
  ace_added: 'text-sev-medium border-sev-medium/50',
  ace_changed: 'text-sev-low border-sev-low/50',
  ace_removed: 'text-ok border-ok/40',
  inheritance_disabled: 'text-sev-medium border-sev-medium/50',
  share_added: 'text-sev-medium border-sev-medium/50',
}

export function ChangeBadge({ c }: { c: ChangeItem }) {
  return (
    <Badge variant="outline" className={cn('font-normal whitespace-nowrap', changeTone[c.change])}>
      {c.change_label}
    </Badge>
  )
}

function ChangeValue({ c }: { c: ChangeItem }) {
  if (c.old_value && c.new_value)
    return (
      <span>
        <span className="text-muted-foreground line-through">{c.old_value}</span> → {c.new_value}
      </span>
    )
  return <span>{c.new_value ?? c.old_value ?? ''}</span>
}

export interface ChangeFilter {
  system_id?: number | string
  sid?: string
  change?: string
  q?: string
  days?: number
}

const PAGE = 50

export function ChangesTable({ filter, showSystem = true }: { filter: ChangeFilter; showSystem?: boolean }) {
  const [page, setPage] = useState(0)
  const key = JSON.stringify(filter)
  const [lastKey, setLastKey] = useState(key)
  if (key !== lastKey) {
    setLastKey(key)
    setPage(0)
  }
  const { data, isLoading, error } = useQuery({
    queryKey: ['changes', filter, page],
    queryFn: () => api.get<ChangesResponse>(`/changes${qs({ ...filter, limit: PAGE, offset: page * PAGE })}`),
    placeholderData: (p) => p,
  })
  if (error) return <ErrorState error={error} />
  if (isLoading || !data) return <Loading />
  if (data.total === 0)
    return (
      <EmptyState title="Keine Änderungen">
        Im gewählten Zeitraum hat sich an expliziten Berechtigungen, Vererbung, Besitzern und Freigaben nichts geändert.
        Änderungen werden ab dem zweiten Scan eines Systems erkannt.
      </EmptyState>
    )
  const pages = Math.ceil(data.total / PAGE)
  return (
    <div className="space-y-3">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-36">Erkannt</TableHead>
            {showSystem && <TableHead className="hidden md:table-cell">System</TableHead>}
            <TableHead>Änderung</TableHead>
            <TableHead>Objekt</TableHead>
            <TableHead className="hidden lg:table-cell">Prinzipal</TableHead>
            <TableHead className="hidden lg:table-cell">Wert</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.items.map((c) => (
            <TableRow key={c.id}>
              <TableCell className="text-muted-foreground text-xs">{dateTime(c.detected_at)}</TableCell>
              {showSystem && (
                <TableCell className="hidden md:table-cell">
                  <Link to={`/systems/${c.system_id}`} className="hover:underline">
                    {c.hostname}
                  </Link>
                </TableCell>
              )}
              <TableCell>
                <ChangeBadge c={c} />
              </TableCell>
              <TableCell className="max-w-md">
                <div className="truncate font-mono text-xs" title={c.path}>
                  {c.path}
                </div>
                <div className="text-muted-foreground text-xs lg:hidden">
                  {c.principal?.name} <ChangeValue c={c} />
                </div>
              </TableCell>
              <TableCell className="hidden max-w-56 lg:table-cell">
                {c.principal && <PrincipalLink p={c.principal} />}
              </TableCell>
              <TableCell className="hidden text-xs lg:table-cell">
                <ChangeValue c={c} />
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {pages > 1 && (
        <div className="flex items-center justify-end gap-2 text-sm">
          <span className="text-muted-foreground">
            {num(page * PAGE + 1)}–{num(Math.min((page + 1) * PAGE, data.total))} von {num(data.total)}
          </span>
          <Button size="icon" variant="outline" disabled={page === 0} onClick={() => setPage(page - 1)}>
            <ChevronLeft className="size-4" />
          </Button>
          <Button size="icon" variant="outline" disabled={page + 1 >= pages} onClick={() => setPage(page + 1)}>
            <ChevronRight className="size-4" />
          </Button>
        </div>
      )}
    </div>
  )
}

/** Kompakte Liste der letzten Änderungen (Dashboard). */
export function RecentChanges({ systemId, limit = 6 }: { systemId?: number; limit?: number }) {
  const { data } = useQuery({
    queryKey: ['changes', 'recent', systemId ?? null],
    queryFn: () => api.get<ChangesResponse>(`/changes${qs({ system_id: systemId, days: 14, limit })}`),
  })
  if (!data) return <Loading rows={3} />
  if (data.total === 0) return <p className="text-muted-foreground text-sm">Keine Änderungen in den letzten 14 Tagen.</p>
  return (
    <div className="space-y-2">
      {data.items.map((c) => (
        <div key={c.id} className="text-sm">
          <div className="flex items-center gap-2">
            <ChangeBadge c={c} />
            <span className="text-muted-foreground ml-auto shrink-0 text-xs">{dateTime(c.detected_at)}</span>
          </div>
          <div className="mt-0.5 truncate font-mono text-xs" title={c.path}>
            {c.path}
          </div>
          {c.principal && (
            <div className="text-muted-foreground truncate text-xs">
              {c.principal.name} · <ChangeValue c={c} />
            </div>
          )}
        </div>
      ))}
      <Button variant="ghost" size="sm" asChild className="px-0">
        <Link to={systemId ? `/changes?system_id=${systemId}` : '/changes'}>
          Alle {num(data.total)} Änderungen <ArrowRight className="size-4" />
        </Link>
      </Button>
    </div>
  )
}
