import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowRight, CheckCircle2, Lightbulb } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { EmptyState, ErrorState, Loading, PageHeader, SeverityBadge } from '@/components/common'
import { api, type Recommendation } from '@/lib/api'
import { num } from '@/lib/format'

export default function RecommendationsPage() {
  const { data, isLoading, error } = useQuery({
    queryKey: ['recommendations'],
    queryFn: () => api.get<Recommendation[]>('/recommendations'),
  })
  if (error) return <ErrorState error={error} />
  if (isLoading || !data) return <Loading rows={6} />
  return (
    <>
      <PageHeader
        title="Empfehlungen"
        description="Priorisierte Maßnahmen – oben beginnen: höchste Schwere und größter Hebel zuerst"
      />
      {data.length === 0 ? (
        <EmptyState title="Keine offenen Empfehlungen">
          <CheckCircle2 className="text-ok mx-auto mb-2 size-6" />
          Alle Prüfungen sind bestanden.
        </EmptyState>
      ) : (
        <div className="space-y-4">
          {data.map((r) => (
            <Card key={r.rule} className="gap-3">
              <CardHeader>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="bg-primary text-primary-foreground flex size-7 items-center justify-center rounded-full text-sm font-semibold">
                    {r.priority}
                  </span>
                  <CardTitle className="text-lg">{r.title}</CardTitle>
                  <SeverityBadge severity={r.severity} />
                  <Badge variant="outline">{r.scope === 'ad' ? 'Active Directory' : 'Dateisystem'}</Badge>
                  <Badge variant="secondary">Aufwand {r.effort}</Badge>
                </div>
                <CardDescription>{r.description}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="bg-muted/60 flex gap-3 rounded-lg p-3 text-sm">
                  <Lightbulb className="text-sev-medium mt-0.5 size-4 shrink-0" />
                  <span>{r.recommendation}</span>
                </div>
                <div className="text-muted-foreground flex flex-wrap gap-x-6 gap-y-1 text-sm">
                  <span>
                    <strong className="text-foreground">{num(r.findings)}</strong> Befunde
                  </span>
                  <span>
                    <strong className="text-foreground">{num(r.affected)}</strong> betroffene Objekte
                  </span>
                  {r.systems.length > 0 && (
                    <span>
                      Systeme: <span className="text-foreground">{r.systems.join(', ')}</span>
                    </span>
                  )}
                </div>
              </CardContent>
              <CardFooter>
                <Button variant="outline" size="sm" asChild>
                  <Link to={`/findings?rule=${r.rule}`}>
                    Befunde anzeigen <ArrowRight className="size-4" />
                  </Link>
                </Button>
              </CardFooter>
            </Card>
          ))}
        </div>
      )}
    </>
  )
}
