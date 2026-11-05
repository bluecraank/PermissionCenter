import { Fragment, useState } from 'react'
import { Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowDown, Crown, ListChecks, Route, ShieldAlert, Users } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { EmptyState, ErrorState, Loading, PageHeader, PrincipalLink, SeverityBadge, StatCard } from '@/components/common'
import { api, type AttackPathOverview, type AttackPathStep, type AttackNode } from '@/lib/api'
import { num } from '@/lib/format'

const KIND_LABEL: Record<string, string> = {
  ou: 'OU',
  container: 'Container',
  gpo: 'GPO',
}

export function AttackNodeLabel({ node }: { node: AttackNode }) {
  if (node.principal) return <PrincipalLink p={node.principal} />
  return (
    <span className="inline-flex flex-wrap items-center gap-1.5" title={node.dn ?? undefined}>
      {node.kind !== 'domain' && (
        <Badge variant="secondary" className="font-normal">
          {KIND_LABEL[node.kind] ?? node.kind}
        </Badge>
      )}
      <span className="break-all">{node.name}</span>
    </span>
  )
}

/** Weg als senkrechte Kette: jedes Glied nennt das Recht, das zum nächsten Objekt führt. */
export function AttackPathChain({ steps }: { steps: AttackPathStep[] }) {
  if (steps.length === 0) return null
  return (
    <ol className="space-y-1 text-sm">
      <li>
        <AttackNodeLabel node={steps[0].from} />
      </li>
      {steps.map((s, i) => (
        <li key={i} className="space-y-1">
          <div className="text-muted-foreground flex items-center gap-1.5 pl-1 text-xs">
            <ArrowDown className="size-3.5 shrink-0" />
            {s.label}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <AttackNodeLabel node={s.to} />
            {s.to.tier0 && (
              <Badge variant="outline" className="text-sev-critical border-sev-critical/50">
                <Crown className="size-3" /> Tier 0
              </Badge>
            )}
          </div>
        </li>
      ))}
    </ol>
  )
}

export default function AttackPathsPage() {
  const [filter, setFilter] = useState('all')
  const [open, setOpen] = useState<number | null>(null)
  const { data, isLoading, error } = useQuery({
    queryKey: ['attack-paths'],
    queryFn: () => api.get<AttackPathOverview>('/attack-paths'),
  })

  const header = (
    <PageHeader
      title="Angriffspfade"
      description="Wege, auf denen Konten außerhalb der Domänen-Administration über Gruppen und AD-Rechte die Domäne übernehmen könnten"
      actions={
        <Button asChild variant="outline">
          <Link to="/assist">
            <ListChecks className="size-4" /> Im Audit-Assist beheben
          </Link>
        </Button>
      }
    />
  )
  if (error)
    return (
      <>
        {header}
        <ErrorState error={error} />
      </>
    )
  if (isLoading || !data)
    return (
      <>
        {header}
        <Loading />
      </>
    )
  if (!data.collected)
    return (
      <>
        {header}
        <EmptyState title="Noch keine AD-Berechtigungen erfasst">
          Das bedeutet nicht, dass es keine Angriffspfade gibt. Führe{' '}
          <code>tools\Export-ADData.ps1</code> in der aktuellen Version aus oder starte unter{' '}
          <Link to="/ad" className="underline">
            Active Directory
          </Link>{' '}
          den LDAP-Abgleich.
        </EmptyState>
      </>
    )

  const entries = data.entries.filter(
    (e) => filter === 'all' || (filter === 'broad' ? e.broad : filter === 'dcsync' ? e.rule === 'AD_DCSYNC_RIGHT' : !e.broad),
  )
  const s = data.stats
  return (
    <>
      {header}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard title="Einstiegspunkte" value={num(s.entries)} icon={<Route className="size-4" />} hint="AD-Rechte, die behoben werden können" />
        <StatCard
          title="Betroffene Benutzer"
          value={`${num(s.exposed_users)} von ${num(s.total_users)}`}
          icon={<Users className="size-4" />}
          hint="Aktive Benutzer außerhalb von Tier 0 mit einem Weg"
        />
        <StatCard title="Breite Gruppen" value={num(s.broad)} icon={<ShieldAlert className="size-4" />} hint="Einstiegspunkte für z. B. Domänen-Benutzer" />
        <StatCard title="DCSync-Rechte" value={num(s.dcsync)} icon={<Crown className="size-4" />} hint="Dürfen Kennwort-Hashes replizieren" />
      </div>

      <Card>
        <CardHeader className="flex flex-row flex-wrap items-center justify-between gap-2">
          <CardTitle className="text-base">Einstiegspunkte ({num(entries.length)})</CardTitle>
          <Select value={filter} onValueChange={setFilter}>
            <SelectTrigger className="w-52">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">Alle</SelectItem>
              <SelectItem value="dcsync">DCSync</SelectItem>
              <SelectItem value="broad">Breite Gruppen</SelectItem>
              <SelectItem value="other">Einzelne Konten und Gruppen</SelectItem>
            </SelectContent>
          </Select>
        </CardHeader>
        <CardContent>
          {entries.length === 0 ? (
            <EmptyState title={s.entries === 0 ? 'Keine Angriffspfade gefunden' : 'Keine Treffer'}>
              {s.entries === 0 && `Geprüft wurden ${num(data.objects)} AD-Objekte. Verweigern-Einträge bleiben dabei unberücksichtigt.`}
            </EmptyState>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Schwere</TableHead>
                  <TableHead>Wer</TableHead>
                  <TableHead>Recht</TableHead>
                  <TableHead>Auf</TableHead>
                  <TableHead className="text-right">Schritte</TableHead>
                  <TableHead className="text-right">Benutzer</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {entries.map((e, i) => (
                  <Fragment key={i}>
                    <TableRow className="cursor-pointer" onClick={() => setOpen(open === i ? null : i)}>
                      <TableCell>{e.severity && <SeverityBadge severity={e.severity} />}</TableCell>
                      <TableCell>
                        <AttackNodeLabel node={e.trustee} />
                      </TableCell>
                      <TableCell className="whitespace-normal">{e.rights.map((r) => r.label).join(', ')}</TableCell>
                      <TableCell className="whitespace-normal">
                        <AttackNodeLabel node={e.target} />
                      </TableCell>
                      <TableCell className="text-right">{num(e.hops)}</TableCell>
                      <TableCell className="text-right">{num(e.exposed_users)}</TableCell>
                    </TableRow>
                    {open === i && (
                      <TableRow>
                        <TableCell colSpan={6} className="bg-muted/40 whitespace-normal">
                          <AttackPathChain steps={e.path} />
                        </TableCell>
                      </TableRow>
                    )}
                  </Fragment>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Als Tier 0 gewertet ({num(data.tier0.length)})</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-x-4 gap-y-2 text-sm">
          {data.tier0.map((n) => (
            <AttackNodeLabel key={n.id} node={n} />
          ))}
        </CardContent>
      </Card>

      <p className="text-muted-foreground text-xs">
        Nicht ausgewertet werden Verweigern-Einträge, GPO-Sicherheitsfilter, SYSVOL-Rechte, andere Domänen und die meisten
        Eigenschaftssätze. Ein Weg zeigt eine mögliche Rechtekette, keinen nachgewiesenen Angriff.
      </p>
    </>
  )
}
