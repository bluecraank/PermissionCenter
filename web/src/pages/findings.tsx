import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { Search, X } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Card, CardContent } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { PageHeader } from '@/components/common'
import { FindingsTable } from '@/components/findings-table'
import { api, type SystemSummary } from '@/lib/api'
import { SEVERITIES, severityLabel } from '@/lib/format'

interface RuleDef {
  id: string
  title: string
  scope: string
}

export default function FindingsPage() {
  const [params, setParams] = useSearchParams()
  const { data: rules } = useQuery({ queryKey: ['rules'], queryFn: () => api.get<RuleDef[]>('/rules') })
  const { data: systems } = useQuery({ queryKey: ['systems'], queryFn: () => api.get<SystemSummary[]>('/systems') })

  const get = (k: string) => params.get(k) ?? 'all'
  const set = (k: string, v: string) => {
    const p = new URLSearchParams(params)
    if (!v || v === 'all') p.delete(k)
    else p.set(k, v)
    setParams(p, { replace: true })
  }
  const filter = {
    severity: params.get('severity') ?? undefined,
    rule: params.get('rule') ?? undefined,
    scope: params.get('scope') ?? undefined,
    system_id: params.get('system_id') ? Number(params.get('system_id')) : undefined,
    sid: params.get('sid') ?? undefined,
    q: params.get('q') ?? undefined,
  }
  const active = [...params.keys()].length > 0

  return (
    <>
      <PageHeader title="Befunde" description="Alle erkannten Probleme in Dateisystemen und Active Directory" />
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-64">
          <Search className="text-muted-foreground absolute top-2.5 left-2.5 size-4" />
          <Input
            placeholder="Pfad, Titel, System…"
            className="pl-8"
            defaultValue={params.get('q') ?? ''}
            onKeyDown={(e) => e.key === 'Enter' && set('q', (e.target as HTMLInputElement).value)}
            onBlur={(e) => set('q', e.target.value)}
          />
        </div>
        <Select value={get('severity')} onValueChange={(v) => set('severity', v)}>
          <SelectTrigger className="w-36">
            <SelectValue placeholder="Schwere" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Alle Schweregrade</SelectItem>
            {SEVERITIES.map((s) => (
              <SelectItem key={s} value={s}>
                {severityLabel[s]}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={get('scope')} onValueChange={(v) => set('scope', v)}>
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Alle Bereiche</SelectItem>
            <SelectItem value="system">Dateisysteme</SelectItem>
            <SelectItem value="ad">Active Directory</SelectItem>
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
        <Select value={get('rule')} onValueChange={(v) => set('rule', v)}>
          <SelectTrigger className="w-64">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Alle Regeln</SelectItem>
            {rules?.map((r) => (
              <SelectItem key={r.id} value={r.id}>
                {r.title}
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
      <Card>
        <CardContent>
          <FindingsTable filter={filter} />
        </CardContent>
      </Card>
    </>
  )
}
