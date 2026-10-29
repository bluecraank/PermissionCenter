import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { CheckCircle2, ListChecks, Printer, RefreshCw, XCircle } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { ErrorState, GradeBadge, Loading, PageHeader, ScoreGauge, SeverityBadge, SeverityDots } from '@/components/common'
import { api, type Audit } from '@/lib/api'
import { dateTime, num } from '@/lib/format'
import { cn } from '@/lib/utils'

export default function AuditPage() {
  const qc = useQueryClient()
  const { data, isLoading, error } = useQuery({ queryKey: ['audit'], queryFn: () => api.get<Audit>('/audit') })
  const run = useMutation({
    mutationFn: () => api.post<{ findings: number }>('/analyze'),
    onSuccess: (r) => {
      toast.success(`Analyse abgeschlossen: ${r.findings} Befunde`)
      qc.invalidateQueries()
    },
    onError: (e) => toast.error(String(e)),
  })
  if (error) return <ErrorState error={error} />
  if (isLoading || !data) return <Loading rows={8} />

  const passed = data.checks.filter((c) => c.passed).length
  const groups = [
    { scope: 'system', title: 'Dateisysteme und Freigaben' },
    { scope: 'ad', title: 'Active Directory' },
  ] as const

  return (
    <>
      <PageHeader
        title="Audit"
        description={`Bewertung der Systeme anhand von ${data.checks.length} Prüfregeln · Stand ${dateTime(data.analysis_at)}`}
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => window.print()}>
              <Printer className="size-4" /> Drucken
            </Button>
            <Button variant="outline" size="sm" onClick={() => run.mutate()} disabled={run.isPending}>
              <RefreshCw className={cn('size-4', run.isPending && 'animate-spin')} /> Neu bewerten
            </Button>
            <Button size="sm" asChild>
              <Link to="/assist">
                <ListChecks className="size-4" /> Audit-Assist starten
              </Link>
            </Button>
          </>
        }
      />

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardContent className="flex justify-center">
            <ScoreGauge score={data.score} label="Gesamtbewertung" />
          </CardContent>
        </Card>
        <Card>
          <CardContent className="flex justify-center">
            <ScoreGauge score={data.ad_score} label={data.ad.loaded ? `AD ${data.ad.domain ?? ''}` : 'AD (keine Daten)'} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Prüfungen bestanden</CardTitle>
            <CardDescription>
              {passed} von {data.checks.length}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Progress value={(passed / Math.max(1, data.checks.length)) * 100} />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Bewertung je System</CardTitle>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-14">Note</TableHead>
                <TableHead>System</TableHead>
                <TableHead className="w-48">Punkte</TableHead>
                <TableHead>Befunde</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.systems.map((s) => (
                <TableRow key={s.id}>
                  <TableCell>
                    <GradeBadge score={s.score} />
                  </TableCell>
                  <TableCell>
                    <Link to={`/systems/${s.id}`} className="font-medium hover:underline">
                      {s.hostname}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Progress value={s.score.score} className="h-2" />
                      <span className="w-8 text-right tabular-nums">{s.score.score}</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <SeverityDots counts={s.findings} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {groups.map((g) => (
        <Card key={g.scope}>
          <CardHeader>
            <CardTitle>{g.title}</CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-10" />
                  <TableHead>Prüfung</TableHead>
                  <TableHead className="w-24">Schwere</TableHead>
                  <TableHead className="text-right">Befunde</TableHead>
                  <TableHead className="hidden text-right md:table-cell">Objekte</TableHead>
                  {g.scope === 'system' && <TableHead className="hidden text-right md:table-cell">Systeme</TableHead>}
                </TableRow>
              </TableHeader>
              <TableBody>
                {data.checks
                  .filter((c) => c.scope === g.scope)
                  .map((c) => (
                    <TableRow key={c.rule}>
                      <TableCell>
                        {c.passed ? <CheckCircle2 className="text-ok size-5" /> : <XCircle className="text-sev-high size-5" />}
                      </TableCell>
                      <TableCell className="max-w-xl whitespace-normal">
                        <Link to={`/findings?rule=${c.rule}`} className="font-medium hover:underline">
                          {c.title}
                        </Link>
                        <div className="text-muted-foreground text-xs">{c.description}</div>
                        {c.accepted > 0 && (
                          <div className="text-muted-foreground mt-1 text-xs italic">
                            {num(c.accepted)} als Ausnahme akzeptiert
                          </div>
                        )}
                      </TableCell>
                      <TableCell>
                        <SeverityBadge severity={c.severity} />
                      </TableCell>
                      <TableCell className="text-right tabular-nums">{num(c.findings)}</TableCell>
                      <TableCell className="hidden text-right tabular-nums md:table-cell">{num(c.affected)}</TableCell>
                      {g.scope === 'system' && (
                        <TableCell className="hidden text-right tabular-nums md:table-cell">
                          {c.systems_failed}/{c.systems_total}
                        </TableCell>
                      )}
                    </TableRow>
                  ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      ))}
    </>
  )
}
