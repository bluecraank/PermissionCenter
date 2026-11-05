import { useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ChevronDown, ChevronRight, CircleCheck, CircleHelp, ShieldAlert, UserCheck, Wrench } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { EmptyState, ErrorState, Loading, PageHeader, SeverityBadge, StatCard } from '@/components/common'
import { api, type WeaknessItem, type WeaknessOverview } from '@/lib/api'
import { num } from '@/lib/format'

const STATUS: Record<WeaknessItem['status'], { label: string; cls: string }> = {
  found: { label: 'Gefunden', cls: 'text-sev-high border-sev-high/50' },
  ok: { label: 'Unauffällig', cls: 'text-ok border-ok/40' },
  unchecked: { label: 'Nicht geprüft', cls: 'text-muted-foreground' },
  manual: { label: 'Selbst prüfen', cls: 'text-muted-foreground' },
}

function Row({ w }: { w: WeaknessItem }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="border-t first:border-t-0">
      <button onClick={() => setOpen(!open)} className="hover:bg-accent/50 flex w-full flex-wrap items-center gap-2 px-2 py-2 text-left text-sm">
        {open ? <ChevronDown className="size-4 shrink-0" /> : <ChevronRight className="size-4 shrink-0" />}
        <SeverityBadge severity={w.severity} />
        <span className="min-w-0 flex-1 font-medium">{w.title}</span>
        {w.findings.length > 0 && <span className="text-muted-foreground text-xs">{num(w.findings.length)} {w.findings.length === 1 ? 'Befund' : 'Befunde'}</span>}
        <Badge variant="outline" className={STATUS[w.status].cls}>
          {STATUS[w.status].label}
        </Badge>
      </button>
      {open && (
        <div className="space-y-3 px-8 pb-3 text-sm">
          <p>{w.why}</p>
          <p>
            <span className="font-medium">Empfehlung: </span>
            {w.fix}
          </p>
          {w.sources.length > 0 && <p className="text-muted-foreground text-xs">Geprüft über: {w.sources.join(', ')}</p>}
          {w.status === 'unchecked' && (
            <p className="text-muted-foreground text-xs">
              Dafür liegen noch keine Daten vor. Das heißt nicht, dass die Schwachstelle fehlt. Registry-Werte liefert der Client ab dieser Version.
            </p>
          )}
          {w.findings.map((f, i) => (
            <div key={i} className="bg-muted space-y-1 rounded-md p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="font-medium">{f.hostname ?? 'Active Directory / GPO'}</span>
                {f.fingerprint && (
                  <Button size="sm" variant="outline" asChild>
                    <Link to={`/assist?f=${f.fingerprint}`}>
                      <Wrench className="size-4" /> Beheben
                    </Link>
                  </Button>
                )}
              </div>
              {f.detail && <pre className="font-mono text-xs break-words whitespace-pre-wrap">{f.detail}</pre>}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default function WeaknessesPage() {
  const [filter, setFilter] = useState('found')
  const { data, isLoading, error } = useQuery({
    queryKey: ['weaknesses'],
    queryFn: () => api.get<WeaknessOverview>('/weaknesses'),
  })
  const groups = useMemo(() => {
    const m = new Map<string, WeaknessItem[]>()
    for (const w of data?.items ?? []) {
      if (filter !== 'all' && w.status !== filter) continue
      m.set(w.category, [...(m.get(w.category) ?? []), w])
    }
    return [...m.entries()]
  }, [data, filter])
  const count = (s: WeaknessItem['status']) => data?.items.filter((w) => w.status === s).length ?? 0

  return (
    <>
      <PageHeader
        title="Typische Schwachstellen"
        description="Katalog der 50 häufigsten Schwachstellen in Windows- und AD-Umgebungen, abgeglichen mit Registry-Werten, GPOs und dem AD"
      />
      {error && <ErrorState error={error} />}
      {(isLoading || !data) && !error && <Loading />}
      {data && (
        <>
          <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard title="Gefunden" value={num(count('found'))} icon={<ShieldAlert className="size-4" />} hint="Muster mit mindestens einem Befund" />
            <StatCard title="Unauffällig" value={num(count('ok'))} icon={<CircleCheck className="size-4" />} hint="Geprüft, kein Treffer" />
            <StatCard
              title="Nicht geprüft"
              value={num(count('unchecked'))}
              icon={<CircleHelp className="size-4" />}
              hint={`Registry-Werte von ${num(data.systems_reported)} von ${num(data.systems_total)} Systemen`}
            />
            <StatCard title="Selbst prüfen" value={num(count('manual'))} icon={<UserCheck className="size-4" />} hint="Aus den Daten nicht zuverlässig erkennbar" />
          </div>
          <div className="flex items-center gap-3">
            <Select value={filter} onValueChange={setFilter}>
              <SelectTrigger className="w-52">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="found">Gefunden</SelectItem>
                <SelectItem value="all">Alle</SelectItem>
                <SelectItem value="ok">Unauffällig</SelectItem>
                <SelectItem value="unchecked">Nicht geprüft</SelectItem>
                <SelectItem value="manual">Selbst prüfen</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {groups.length === 0 && <EmptyState title="Keine Einträge für diese Auswahl" />}
          {groups.map(([cat, items]) => (
            <Card key={cat} className="gap-2 py-3">
              <CardHeader className="px-4">
                <CardTitle className="text-base">{cat}</CardTitle>
              </CardHeader>
              <CardContent className="px-2">
                {items.map((w) => (
                  <Row key={w.id} w={w} />
                ))}
              </CardContent>
            </Card>
          ))}
        </>
      )}
    </>
  )
}
