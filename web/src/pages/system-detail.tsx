import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Download,
  FolderLock,
  FolderTree,
  Link2Off,
  ShieldQuestion,
  Trash2,
  TriangleAlert,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  EmptyState,
  ErrorState,
  Loading,
  PageHeader,
  PrincipalLink,
  RightsBadge,
  ScoreGauge,
  SeverityDots,
  StatCard,
} from "@/components/common";
import { FindingsTable } from "@/components/findings-table";
import { ChangesTable, ScoreTrend } from "@/components/insights";
import { FolderBrowser } from "@/components/folder-tree";
import { GraphLegend, GraphView } from "@/components/graph-view";
import {
  api,
  type GraphData,
  type GraphNode,
  type Share,
  type SystemDetail,
} from "@/lib/api";
import { dateTime, duration, num, rootKindLabel } from "@/lib/format";

export default function SystemDetailPage() {
  const id = Number(useParams().id);
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [tab, setTab] = useState("overview");
  const { data, isLoading, error } = useQuery({
    queryKey: ["system", id],
    queryFn: () => api.get<SystemDetail>(`/systems/${id}`),
  });
  const del = useMutation({
    mutationFn: () => api.delete(`/systems/${id}`),
    onSuccess: () => {
      toast.success("System gelöscht");
      qc.invalidateQueries();
      navigate("/systems");
    },
    onError: (e) => toast.error(String(e)),
  });
  if (error) return <ErrorState error={error} />;
  if (isLoading || !data) return <Loading rows={8} />;

  return (
    <>
      <PageHeader
        title={data.hostname}
        description={
          <>
            {data.os_name} · {data.os_version} ·{" "}
            {data.domain ?? "Arbeitsgruppe"}
            {data.is_dc && " · Domänencontroller"} · Client{" "}
            {data.client_version}
          </>
        }
        actions={
          <>
            <Button variant="outline" size="sm" asChild>
              <a href={`/api/v1/export/permissions.csv?system_id=${id}`}>
                <Download className="size-4" /> Berechtigungen (CSV)
              </a>
            </Button>
            <Dialog>
              <DialogTrigger asChild>
                <Button variant="outline" size="sm">
                  <Trash2 className="size-4" /> Entfernen
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>System {data.hostname} entfernen?</DialogTitle>
                  <DialogDescription>
                    Alle Scan-Daten und Befunde dieses Systems werden gelöscht.
                    Sendet der Client erneut einen Report, wird das System
                    wieder angelegt.
                  </DialogDescription>
                </DialogHeader>
                <DialogFooter>
                  <DialogClose asChild>
                    <Button variant="outline">Abbrechen</Button>
                  </DialogClose>
                  <Button
                    variant="destructive"
                    onClick={() => del.mutate()}
                    disabled={del.isPending}
                  >
                    Endgültig entfernen
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          </>
        }
      />

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList className="flex-wrap">
          <TabsTrigger value="overview">Übersicht</TabsTrigger>
          <TabsTrigger value="tree">Verzeichnisbaum</TabsTrigger>
          <TabsTrigger value="shares">Freigaben ({data.shares})</TabsTrigger>
          <TabsTrigger value="findings">Befunde</TabsTrigger>
          <TabsTrigger value="graph">Strukturgraph</TabsTrigger>
          <TabsTrigger value="changes">Änderungen</TabsTrigger>
          <TabsTrigger value="scans">Scan-Historie</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <div className="grid gap-4 lg:grid-cols-4">
            <Card className="justify-center">
              <CardContent className="flex flex-col items-center gap-2">
                <ScoreGauge score={data.score} label="Systembewertung" />
                <SeverityDots counts={data.findings} />
              </CardContent>
            </Card>
            <div className="grid grid-cols-2 gap-4 lg:col-span-3 lg:grid-cols-3">
              <StatCard
                title="Gescannte Ordner"
                value={num(data.folders_scanned)}
                icon={<FolderTree className="size-4" />}
                hint={`${num(data.folders_excluded)} ausgeschlossen`}
              />
              <StatCard
                title="Eigene Berechtigungen"
                value={num(data.explicit_folders)}
                icon={<FolderLock className="size-4" />}
              />
              <StatCard
                title="Vererbung unterbrochen"
                value={num(data.protected_folders)}
                icon={<Link2Off className="size-4" />}
              />
              <StatCard
                title="Verwaiste ACEs"
                value={num(data.orphaned_aces)}
                icon={<ShieldQuestion className="size-4" />}
                tone={data.orphaned_aces ? "bad" : undefined}
              />
              <StatCard
                title="Lesefehler"
                value={num(data.errors)}
                icon={<TriangleAlert className="size-4" />}
                tone={data.errors ? "warn" : undefined}
              />
              <StatCard
                title="Scan-Dauer"
                value={duration(data.duration_ms)}
                hint={dateTime(data.last_scan_at)}
              />
            </div>
          </div>
          {data.scan && (
            <Card>
              <CardHeader>
                <CardTitle>Gescannte Wurzeln</CardTitle>
                <CardDescription>
                  Modus „
                  {data.scan.report_mode === "full"
                    ? "vollständig"
                    : "relevant"}
                  “
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Pfad</TableHead>
                      <TableHead>Art</TableHead>
                      <TableHead className="text-right">Ordner</TableHead>
                      <TableHead className="text-right">
                        Ausgeschlossen
                      </TableHead>
                      <TableHead className="text-right">Fehler</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {data.scan.roots.map((r) => (
                      <TableRow key={r.path}>
                        <TableCell className="font-mono text-xs">
                          {r.path}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">
                            {rootKindLabel[r.kind] ?? r.kind}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right tabular-nums">
                          {num(r.folders_scanned)}
                        </TableCell>
                        <TableCell className="text-right tabular-nums">
                          {num(r.folders_excluded)}
                        </TableCell>
                        <TableCell className="text-right tabular-nums">
                          {num(r.errors)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
          {data.scan?.errors && data.scan.errors.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Lesefehler</CardTitle>
                <CardDescription>
                  Ordner, deren Berechtigungen nicht gelesen werden konnten
                </CardDescription>
              </CardHeader>
              <CardContent className="max-h-80 space-y-1 overflow-auto font-mono text-xs">
                {data.scan.errors.map((e, i) => (
                  <div key={i} className="flex gap-2">
                    <span className="text-sev-high shrink-0">{e.message}</span>
                    <span className="truncate">{e.path}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {tab === "overview" && (
          <TabsContent value="overview">
            <Card>
              <CardHeader>
                <CardTitle>Entwicklung der Bewertung</CardTitle>
              </CardHeader>
              <CardContent>
                <ScoreTrend systemId={id} height={180} />
              </CardContent>
            </Card>
          </TabsContent>
        )}

        <TabsContent value="tree">
          {tab === "tree" && <FolderBrowser systemId={id} />}
        </TabsContent>
        <TabsContent value="shares">
          {tab === "shares" && <SharesTab systemId={id} />}
        </TabsContent>
        <TabsContent value="findings">
          <Card>
            <CardContent>
              {tab === "findings" && (
                <FindingsTable filter={{ system_id: id }} showSystem={false} />
              )}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="graph">
          {tab === "graph" && <SystemGraph systemId={id} />}
        </TabsContent>
        <TabsContent value="changes">
          <Card>
            <CardContent>
              {tab === "changes" && (
                <ChangesTable
                  filter={{ system_id: id, days: 365 }}
                  showSystem={false}
                />
              )}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="scans">
          {tab === "scans" && <ScansTab systemId={id} />}
        </TabsContent>
      </Tabs>
    </>
  );
}

function SharesTab({ systemId }: { systemId: number }) {
  const { data, isLoading } = useQuery({
    queryKey: ["shares", systemId],
    queryFn: () => api.get<Share[]>(`/systems/${systemId}/shares`),
  });
  if (isLoading || !data) return <Loading />;
  if (data.length === 0) return <EmptyState title="Keine Freigaben" />;
  return (
    <div className="grid gap-4 md:grid-cols-2">
      {data.map((s) => (
        <Card key={s.id} className={s.is_special ? "opacity-70" : ""}>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 font-mono text-base">
              \\{s.name}
              {s.is_special && <Badge variant="secondary">Standard</Badge>}
            </CardTitle>
            <CardDescription className="font-mono">
              {s.path || "–"}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {s.remark && (
              <p className="text-muted-foreground text-sm">{s.remark}</p>
            )}
            {!s.has_sd ? (
              <p className="text-sm">
                Keine Freigabeberechtigungen gesetzt (entspricht „Jeder:
                Vollzugriff“).
              </p>
            ) : (
              <div className="space-y-1">
                {s.permissions.map((a, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between gap-2 text-sm"
                  >
                    <PrincipalLink p={a.principal} />
                    <RightsBadge
                      label={a.rights_label}
                      deny={a.ace_type === "deny"}
                    />
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

function SystemGraph({ systemId }: { systemId: number }) {
  const navigate = useNavigate();
  const { data, isLoading } = useQuery({
    queryKey: ["graph", "system", systemId],
    queryFn: () =>
      api.get<GraphData>(`/graph?mode=system&system_id=${systemId}&limit=80`),
  });
  if (isLoading || !data) return <Loading />;
  const click = (n: GraphNode) => {
    if (n.sid) navigate(`/principals/${encodeURIComponent(n.sid)}`);
  };
  return (
    <Card>
      <CardHeader>
        <CardTitle>Berechtigungsstränge und Abhängigkeiten</CardTitle>
        <CardDescription>
          Ordner mit eigenen Rechten und die berechtigten Gruppen/Benutzer.
          Klick auf einen Prinzipal öffnet dessen Details.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-2">
        <GraphView data={data} layout="breadthfirst" onNodeClick={click} />
        <GraphLegend />
      </CardContent>
    </Card>
  );
}

interface ScanRow {
  uuid: string;
  finished_at: string;
  received_at: string;
  report_mode: string;
  folders_scanned: number;
  folders_reported: number;
  folders_excluded: number;
  explicit_folders: number;
  errors: number;
  orphaned_aces: number;
  duration_ms: number;
}

function ScansTab({ systemId }: { systemId: number }) {
  const { data, isLoading } = useQuery({
    queryKey: ["scans", systemId],
    queryFn: () => api.get<ScanRow[]>(`/systems/${systemId}/scans`),
  });
  if (isLoading || !data) return <Loading />;
  return (
    <Card className="py-0">
      <CardContent className="px-0">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="pl-4">Beendet</TableHead>
              <TableHead>Modus</TableHead>
              <TableHead className="text-right">Gescannt</TableHead>
              <TableHead className="text-right">Gemeldet</TableHead>
              <TableHead className="text-right">Explizit</TableHead>
              <TableHead className="text-right">Verwaist</TableHead>
              <TableHead className="text-right">Fehler</TableHead>
              <TableHead className="pr-4 text-right">Dauer</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.map((s) => (
              <TableRow key={s.uuid}>
                <TableCell className="pl-4">
                  {dateTime(s.finished_at)}
                </TableCell>
                <TableCell>{s.report_mode}</TableCell>
                <TableCell className="text-right tabular-nums">
                  {num(s.folders_scanned)}
                </TableCell>
                <TableCell className="text-right tabular-nums">
                  {num(s.folders_reported)}
                </TableCell>
                <TableCell className="text-right tabular-nums">
                  {num(s.explicit_folders)}
                </TableCell>
                <TableCell className="text-right tabular-nums">
                  {num(s.orphaned_aces)}
                </TableCell>
                <TableCell className="text-right tabular-nums">
                  {num(s.errors)}
                </TableCell>
                <TableCell className="pr-4 text-right tabular-nums">
                  {duration(s.duration_ms)}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  );
}
