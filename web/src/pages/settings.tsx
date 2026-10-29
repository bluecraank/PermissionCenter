import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Lock, PackageCheck, ShieldCheck, ShieldOff } from 'lucide-react'

import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { ErrorState, Loading, PageHeader } from '@/components/common'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { api, type ClientReleases, type Settings } from '@/lib/api'
import { bytes, dateTime, relative } from '@/lib/format'

export default function SettingsPage() {
  const { data, isLoading, error } = useQuery({ queryKey: ['settings'], queryFn: () => api.get<Settings>('/settings') })
  if (error) return <ErrorState error={error} />
  if (isLoading || !data) return <Loading />
  return (
    <>
      <PageHeader
        title="Einstellungen"
        description="Wirksame Server-Konfiguration (pc-server.toml bzw. Umgebungsvariablen PC_*). Änderungen erfordern einen Neustart."
      />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Server</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <Row k="Version" v={data.version} />
            <Row k="Adresse" v={data.listen} />
            <Row k="Datenbank" v={data.database} mono />
            <Row k="Client-Token erforderlich" v={data.upload_token_required ? 'ja' : 'nein (nicht empfohlen)'} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Lock className="size-4" /> Anmeldung
            </CardTitle>
            <CardDescription>AD-Authentifizierung ist vorbereitet, aber noch nicht aktiviert.</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <Row k="Modus" v={<Badge variant="outline">{data.auth_mode === 'none' ? 'Kein Login' : data.auth_mode}</Badge>} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Active Directory (LDAP)</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <Row k="Konfiguriert" v={data.ldap.configured ? 'ja' : 'nein'} />
            <Row k="URL" v={data.ldap.url ?? '–'} mono />
            <Row k="Basis-DN" v={data.ldap.base_dn ?? '–'} mono />
            <Row k="Bind-Benutzer" v={data.ldap.bind_dn ?? '–'} mono />
            <Row k="Automatischer Abgleich" v={data.ldap.sync_interval_minutes ? `alle ${data.ldap.sync_interval_minutes} Min.` : 'aus'} />
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Analyse</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <Row k="Inaktiv nach" v={`${data.analysis.inactive_days} Tagen`} />
            <Row k="System veraltet nach" v={`${data.analysis.stale_scan_days} Tagen`} />
            <Row k="Zu tiefe Rechte ab Ebene" v={String(data.analysis.deep_explicit_depth)} />
            <Row k="Max. Befunde je Regel" v={String(data.analysis.max_findings_per_rule)} />
          </CardContent>
        </Card>
      </div>
      <ClientUpdates />
    </>
  )
}

function ClientUpdates() {
  const { data } = useQuery({ queryKey: ['client-releases'], queryFn: () => api.get<ClientReleases>('/client/releases') })
  if (!data) return null
  const outdated = data.systems.filter((s) => s.outdated)
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <PackageCheck className="size-4" /> Client-Updates (OTA)
        </CardTitle>
        <CardDescription>
          Clients prüfen vor jedem Scan bzw. im Dienst regelmäßig auf neue Versionen. Veröffentlichen mit{' '}
          <code>pc-server publish-client --file pc-client.exe --version x.y.z --signing-key …</code>
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        <div className="flex flex-wrap gap-2">
          <Badge variant="outline">Aktuell veröffentlicht: {data.latest ?? 'keine'}</Badge>
          {data.signature_required ? (
            <Badge variant="outline" className="text-ok border-ok/40 gap-1">
              <ShieldCheck className="size-3" /> Nur signierte Releases
            </Badge>
          ) : (
            <Badge variant="outline" className="text-sev-medium border-sev-medium/50 gap-1">
              <ShieldOff className="size-3" /> Kein öffentlicher Schlüssel gesetzt
            </Badge>
          )}
          {data.latest && (
            <Badge variant={outdated.length ? 'destructive' : 'secondary'}>
              {outdated.length} von {data.systems.length} Systemen veraltet
            </Badge>
          )}
        </div>
        {data.public_key && (
          <div>
            <div className="text-muted-foreground text-xs">Öffentlicher Schlüssel (für [update] public_key der Clients)</div>
            <code className="bg-muted block rounded p-2 text-xs break-all">{data.public_key}</code>
          </div>
        )}
        {data.releases.length > 0 && (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Version</TableHead>
                <TableHead>Veröffentlicht</TableHead>
                <TableHead className="hidden md:table-cell">Größe</TableHead>
                <TableHead>Signatur</TableHead>
                <TableHead className="hidden lg:table-cell">SHA-256</TableHead>
                <TableHead className="hidden md:table-cell">Hinweis</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.releases.map((r) => (
                <TableRow key={r.version}>
                  <TableCell className="font-medium">{r.version}</TableCell>
                  <TableCell title={dateTime(r.published_at)}>{relative(r.published_at)}</TableCell>
                  <TableCell className="hidden md:table-cell">{bytes(r.size)}</TableCell>
                  <TableCell>{r.signature ? 'signiert' : <span className="text-sev-medium">unsigniert</span>}</TableCell>
                  <TableCell className="text-muted-foreground hidden font-mono text-xs lg:table-cell">
                    {r.sha256.slice(0, 16)}…
                  </TableCell>
                  <TableCell className="hidden md:table-cell">{r.notes}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        {outdated.length > 0 && (
          <div>
            <div className="text-muted-foreground mb-1 text-xs">Systeme mit älterem Client</div>
            <div className="flex flex-wrap gap-2">
              {outdated.map((s) => (
                <Link key={s.id} to={`/systems/${s.id}`}>
                  <Badge variant="outline">
                    {s.hostname} · {s.client_version ?? '?'}
                  </Badge>
                </Link>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

function Row({ k, v, mono }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-4">
      <span className="text-muted-foreground">{k}</span>
      <span className={mono ? 'truncate font-mono text-xs' : 'truncate'}>{v}</span>
    </div>
  )
}
