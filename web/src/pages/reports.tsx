import { useState, type ReactNode } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, Printer, ShieldCheck } from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { GradeBadge, Loading, ErrorState, SeverityBadge, SeverityDots } from '@/components/common'
import { ScoreTrend } from '@/components/insights'
import {
  api,
  type AssistOverview,
  type Audit,
  type ChangesResponse,
  type Finding,
  type PrincipalDetail,
} from '@/lib/api'
import { date, dateTime, kindLabel, num, statusLabel } from '@/lib/format'

/** Rahmen eines Druckberichts (A4, ohne Navigation). */
function ReportShell({ title, subtitle, back, children }: { title: string; subtitle?: ReactNode; back: string; children: ReactNode }) {
  const [created] = useState(() => new Date().toISOString())
  return (
    <div className="bg-background min-h-svh">
      <div className="no-print bg-muted/60 sticky top-0 z-10 border-b">
        <div className="mx-auto flex max-w-4xl items-center gap-2 px-4 py-2">
          <Button variant="ghost" size="sm" asChild>
            <Link to={back}>
              <ArrowLeft className="size-4" /> Zurück
            </Link>
          </Button>
          <span className="text-muted-foreground ml-auto hidden text-xs sm:inline">
            Tipp: Im Druckdialog „Als PDF speichern“ wählen
          </span>
          <Button size="sm" onClick={() => window.print()}>
            <Printer className="size-4" /> Drucken / PDF
          </Button>
        </div>
      </div>
      <article className="mx-auto max-w-4xl space-y-8 px-4 py-8 text-sm print:max-w-none print:p-0">
        <header className="flex items-start justify-between gap-4 border-b pb-4">
          <div>
            <h1 className="text-2xl font-semibold">{title}</h1>
            {subtitle && <div className="text-muted-foreground mt-1">{subtitle}</div>}
          </div>
          <div className="text-muted-foreground flex items-center gap-2 text-right text-xs">
            <div>
              <div className="text-foreground font-semibold">PermissionCenter</div>
              <div>Erstellt {dateTime(created)}</div>
            </div>
            <ShieldCheck className="size-6" />
          </div>
        </header>
        {children}
      </article>
    </div>
  )
}

function Section({ title, children, breakBefore }: { title: string; children: ReactNode; breakBefore?: boolean }) {
  return (
    <section className={breakBefore ? 'print-break space-y-3' : 'space-y-3'}>
      <h2 className="border-b pb-1 text-lg font-semibold">{title}</h2>
      {children}
    </section>
  )
}

export function AuditReportPage() {
  const audit = useQuery({ queryKey: ['audit'], queryFn: () => api.get<Audit>('/audit') })
  const findings = useQuery({
    queryKey: ['report', 'findings'],
    queryFn: () => api.get<{ total: number; items: Finding[] }>('/findings?limit=1000'),
  })
  const assist = useQuery({ queryKey: ['assist', 'overview', {}], queryFn: () => api.get<AssistOverview>('/assist') })
  const changes = useQuery({
    queryKey: ['report', 'changes'],
    queryFn: () => api.get<ChangesResponse>('/changes?days=30&limit=40'),
  })
  if (audit.error) return <ErrorState error={audit.error} />
  if (!audit.data || !findings.data || !assist.data || !changes.data) return <Loading rows={10} />
  const a = audit.data
  const open = findings.data.items.filter((f) => f.assist_status !== 'accepted' && f.severity !== 'info' && f.severity !== 'low')
  const accepted = assist.data.items.filter((i) => i.assist_status === 'accepted')
  const failed = a.checks.filter((c) => !c.passed)

  return (
    <ReportShell
      title="Berechtigungsaudit"
      subtitle={
        <>
          {a.ad.domain ?? 'Ohne AD-Daten'} · {a.systems.length} Systeme · Analyse vom {dateTime(a.analysis_at)}
        </>
      }
      back="/audit"
    >
      <Section title="Zusammenfassung">
        <div className="grid grid-cols-3 gap-4">
          {[
            { l: 'Gesamt', s: a.score },
            { l: 'Active Directory', s: a.ad_score },
          ].map((x) => (
            <div key={x.l} className="flex items-center gap-3 rounded-lg border p-3">
              <GradeBadge score={x.s} />
              <div>
                <div className="font-semibold">{x.s.score} / 100 Punkte</div>
                <div className="text-muted-foreground text-xs">{x.l}</div>
              </div>
            </div>
          ))}
          <div className="rounded-lg border p-3">
            <div className="font-semibold">
              {a.checks.length - failed.length} von {a.checks.length} Prüfungen bestanden
            </div>
            <div className="text-muted-foreground text-xs">
              {num(assist.data.summary.resolved)} behoben · {num(assist.data.summary.accepted)} Ausnahmen
            </div>
          </div>
        </div>
        <div className="avoid-break">
          <h3 className="mb-1 font-medium">Entwicklung (90 Tage)</h3>
          <ScoreTrend height={180} />
        </div>
      </Section>

      <Section title="Systeme">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-12">Note</TableHead>
              <TableHead>System</TableHead>
              <TableHead>Betriebssystem</TableHead>
              <TableHead>Letzter Scan</TableHead>
              <TableHead>Befunde</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {a.systems.map((s) => (
              <TableRow key={s.id}>
                <TableCell>
                  <GradeBadge score={s.score} size="sm" />
                </TableCell>
                <TableCell className="font-medium">{s.hostname}</TableCell>
                <TableCell>{s.os_name}</TableCell>
                <TableCell>{date(s.last_scan_at)}</TableCell>
                <TableCell>
                  <SeverityDots counts={s.findings} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Section>

      <Section title="Prüfungen" breakBefore>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-28">Ergebnis</TableHead>
              <TableHead>Prüfung</TableHead>
              <TableHead>Schwere</TableHead>
              <TableHead className="text-right">Befunde</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {a.checks.map((c) => (
              <TableRow key={c.rule}>
                <TableCell className={c.passed ? 'text-ok' : 'text-sev-high font-medium'}>
                  {c.passed ? 'bestanden' : 'nicht bestanden'}
                </TableCell>
                <TableCell className="whitespace-normal">
                  <div className="font-medium">{c.title}</div>
                  {!c.passed && <div className="text-muted-foreground text-xs">{c.recommendation}</div>}
                  {c.accepted > 0 && <div className="text-muted-foreground text-xs italic">{c.accepted} als Ausnahme akzeptiert</div>}
                </TableCell>
                <TableCell>
                  <SeverityBadge severity={c.severity} />
                </TableCell>
                <TableCell className="text-right tabular-nums">{num(c.findings)}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </Section>

      <Section title={`Offene Befunde (kritisch bis mittel: ${num(open.length)})`} breakBefore>
        {open.length === 0 ? (
          <p className="text-muted-foreground">Keine.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-24">Schwere</TableHead>
                <TableHead>Befund</TableHead>
                <TableHead>System</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {open.slice(0, 300).map((f) => (
                <TableRow key={f.id}>
                  <TableCell>
                    <SeverityBadge severity={f.severity} />
                  </TableCell>
                  <TableCell className="whitespace-normal">
                    <div>{f.title}</div>
                    {f.path && <div className="text-muted-foreground font-mono text-xs break-all">{f.path}</div>}
                  </TableCell>
                  <TableCell>{f.hostname ?? 'Active Directory'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Section>

      <Section title={`Akzeptierte Ausnahmen (${num(accepted.length)})`}>
        {accepted.length === 0 ? (
          <p className="text-muted-foreground">Keine.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Befund</TableHead>
                <TableHead>Begründung</TableHead>
                <TableHead>Seit</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {accepted.map((i) => (
                <TableRow key={i.fingerprint}>
                  <TableCell className="whitespace-normal">
                    {i.title}
                    <div className="text-muted-foreground text-xs">{i.hostname ?? 'Active Directory'}</div>
                  </TableCell>
                  <TableCell className="whitespace-normal">{i.note}</TableCell>
                  <TableCell>{date(i.updated_at)}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Section>

      <Section title={`Berechtigungsänderungen der letzten 30 Tage (${num(changes.data.total)})`}>
        {changes.data.total === 0 ? (
          <p className="text-muted-foreground">Keine Änderungen erkannt.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Datum</TableHead>
                <TableHead>Änderung</TableHead>
                <TableHead>Objekt</TableHead>
                <TableHead>Prinzipal</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {changes.data.items.map((c) => (
                <TableRow key={c.id}>
                  <TableCell>{date(c.detected_at)}</TableCell>
                  <TableCell>{c.change_label}</TableCell>
                  <TableCell className="font-mono text-xs break-all whitespace-normal">
                    {c.hostname}: {c.path}
                  </TableCell>
                  <TableCell>{c.principal?.name}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        {changes.data.total > changes.data.items.length && (
          <p className="text-muted-foreground text-xs">Vollständige Liste: Export „Änderungen“ (CSV).</p>
        )}
      </Section>
    </ReportShell>
  )
}

export function PrincipalReportPage() {
  const sid = decodeURIComponent(useParams().sid ?? '')
  const { data, error } = useQuery({
    queryKey: ['principal', sid],
    queryFn: () => api.get<PrincipalDetail>(`/principals/${encodeURIComponent(sid)}`),
  })
  if (error) return <ErrorState error={error} />
  if (!data) return <Loading rows={8} />
  const p = data.principal
  const access = [
    ...data.direct_access.map((a) => ({ ...a, how: 'direkt' })),
    ...data.indirect_access.map((a) => ({ ...a, how: a.via ? `über ${a.via.name}` : 'über Gruppe' })),
  ].sort((x, y) => x.hostname.localeCompare(y.hostname) || x.path.localeCompare(y.path))
  return (
    <ReportShell
      title={`Zugriffsbericht: ${p.name}`}
      subtitle={
        <>
          {kindLabel[p.kind] ?? p.kind} · {statusLabel[p.status]} · <span className="font-mono">{p.sid}</span>
        </>
      }
      back={`/principals/${encodeURIComponent(sid)}`}
    >
      {data.member_of.length > 0 && (
        <Section title={`Gruppenmitgliedschaften (${data.member_of.length})`}>
          <ul className="columns-2 gap-6">
            {data.member_of.map((m) => (
              <li key={m.group.sid} className="avoid-break">
                {m.group.name}
                {!m.direct && <span className="text-muted-foreground text-xs"> (über {m.path.slice(0, -1).join(' → ')})</span>}
              </li>
            ))}
          </ul>
        </Section>
      )}
      <Section title={`Zugriffe (${access.length})`}>
        {access.length === 0 ? (
          <p className="text-muted-foreground">Keine Zugriffe in den gescannten Systemen.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>System</TableHead>
                <TableHead>Pfad</TableHead>
                <TableHead>Rechte</TableHead>
                <TableHead>Herkunft</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {access.map((a, i) => (
                <TableRow key={i}>
                  <TableCell>{a.hostname}</TableCell>
                  <TableCell className="font-mono text-xs break-all whitespace-normal">
                    {a.kind === 'share' ? `Freigabe ${a.share ?? a.path}` : a.path}
                  </TableCell>
                  <TableCell>
                    {a.ace_type === 'deny' ? 'Verweigern: ' : ''}
                    {a.rights_label}
                  </TableCell>
                  <TableCell className="whitespace-normal">{a.how}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Section>
      {data.findings.length > 0 && (
        <Section title={`Befunde (${data.findings.length})`}>
          <ul className="space-y-1">
            {data.findings.map((f) => (
              <li key={f.id} className="flex items-center gap-2">
                <SeverityBadge severity={f.severity} /> {f.title}
              </li>
            ))}
          </ul>
        </Section>
      )}
    </ReportShell>
  )
}
