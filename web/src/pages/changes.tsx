import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { Download, Search, X } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { PageHeader } from '@/components/common'
import { ChangesTable } from '@/components/insights'
import { api, qs, type ChangesResponse, type SystemSummary } from '@/lib/api'
import { date } from '@/lib/format'

const RANGES = [
  { v: '7', l: 'Letzte 7 Tage' },
  { v: '30', l: 'Letzte 30 Tage' },
  { v: '90', l: 'Letzte 90 Tage' },
  { v: '365', l: 'Letztes Jahr' },
]

export default function ChangesPage() {
  const [params, setParams] = useSearchParams()
  const { data: systems } = useQuery({ queryKey: ['systems'], queryFn: () => api.get<SystemSummary[]>('/systems') })
  const get = (k: string, d = 'all') => params.get(k) ?? d
  const set = (k: string, v: string) => {
    const p = new URLSearchParams(params)
    if (!v || v === 'all') p.delete(k)
    else p.set(k, v)
    setParams(p, { replace: true })
  }
  const filter = {
    system_id: params.get('system_id') ?? undefined,
    change: params.get('change') ?? undefined,
    sid: params.get('sid') ?? undefined,
    q: params.get('q') ?? undefined,
    days: Number(get('days', '30')),
  }
  const { data } = useQuery({
    queryKey: ['changes', 'chart', filter.system_id ?? null, filter.days],
    queryFn: () => api.get<ChangesResponse>(`/changes${qs({ system_id: filter.system_id, days: filter.days, limit: 1 })}`),
  })
  const active = [...params.keys()].some((k) => k !== 'days')

  return (
    <>
      <PageHeader
        title="Änderungen"
        description="Was sich zwischen zwei Scans an expliziten Berechtigungen, Vererbung, Besitzern und Freigaben geändert hat"
        actions={
          <Button variant="outline" asChild>
            <a href={`/api/v1/export/changes.csv${qs(filter)}`}>
              <Download className="size-4" /> CSV
            </a>
          </Button>
        }
      />
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-64">
          <Search className="text-muted-foreground absolute top-2.5 left-2.5 size-4" />
          <Input
            placeholder="Pfad oder System…"
            className="pl-8"
            defaultValue={params.get('q') ?? ''}
            onKeyDown={(e) => e.key === 'Enter' && set('q', (e.target as HTMLInputElement).value)}
            onBlur={(e) => set('q', e.target.value)}
          />
        </div>
        <Select value={get('days', '30')} onValueChange={(v) => set('days', v)}>
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {RANGES.map((r) => (
              <SelectItem key={r.v} value={r.v}>
                {r.l}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={get('system_id')} onValueChange={(v) => set('system_id', v)}>
          <SelectTrigger className="w-44">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Alle Systeme</SelectItem>
            {systems?.map((s) => (
              <SelectItem key={s.id} value={String(s.id)}>
                {s.hostname}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={get('change')} onValueChange={(v) => set('change', v)}>
          <SelectTrigger className="w-60">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Alle Arten</SelectItem>
            {Object.entries(data?.labels ?? {}).map(([k, l]) => (
              <SelectItem key={k} value={k}>
                {l}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {active && (
          <Button variant="ghost" size="sm" onClick={() => setParams({}, { replace: true })}>
            <X className="size-4" /> Filter zurücksetzen
          </Button>
        )}
      </div>

      {data && data.per_day.length > 0 && (
        <Card className="gap-2">
          <CardHeader>
            <CardTitle className="text-base">Änderungen pro Tag</CardTitle>
            <CardDescription>Alle Arten, gewählter Zeitraum</CardDescription>
          </CardHeader>
          <CardContent className="h-40">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.per_day} margin={{ left: -20 }}>
                <XAxis dataKey="day" tickFormatter={(d) => date(d)} tickLine={false} axisLine={false} fontSize={12} minTickGap={24} />
                <YAxis allowDecimals={false} tickLine={false} axisLine={false} fontSize={12} />
                <Tooltip
                  cursor={{ fill: 'var(--muted)' }}
                  labelFormatter={(d) => date(String(d))}
                  contentStyle={{ background: 'var(--popover)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }}
                />
                <Bar dataKey="changes" name="Änderungen" fill="var(--series-1)" radius={[4, 4, 0, 0]} maxBarSize={28} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      )}

      <Card>
        <CardContent>
          <ChangesTable filter={filter} />
        </CardContent>
      </Card>
    </>
  )
}
