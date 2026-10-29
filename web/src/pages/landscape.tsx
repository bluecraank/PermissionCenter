import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { EmptyState, ErrorState, Loading, PageHeader } from '@/components/common'
import { GraphLegend, GraphView, type GraphLayout } from '@/components/graph-view'
import { api, type GraphData, type GraphNode } from '@/lib/api'

export default function LandscapePage() {
  const navigate = useNavigate()
  const [layout, setLayout] = useState<GraphLayout>('cose')
  const [limit, setLimit] = useState('40')
  const { data, isLoading, error } = useQuery({
    queryKey: ['graph', 'landscape', limit],
    queryFn: () => api.get<GraphData>(`/graph?mode=landscape&limit=${limit}`),
  })

  const click = (n: GraphNode) => {
    if (n.type === 'system' && n.system_id) navigate(`/systems/${n.system_id}`)
    else if (n.sid) navigate(`/principals/${encodeURIComponent(n.sid)}`)
  }

  return (
    <>
      <PageHeader
        title="IT-Landschaft"
        description="Domäne, Systeme, Freigaben und die Gruppen/Benutzer mit den meisten Berechtigungen"
        actions={
          <>
            <Select value={limit} onValueChange={setLimit}>
              <SelectTrigger className="w-48">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {['20', '40', '80', '150'].map((l) => (
                  <SelectItem key={l} value={l}>
                    Top {l} Prinzipale
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={layout} onValueChange={(v) => setLayout(v as GraphLayout)}>
              <SelectTrigger className="w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="cose">Organisch</SelectItem>
                <SelectItem value="breadthfirst">Hierarchisch</SelectItem>
                <SelectItem value="concentric">Konzentrisch</SelectItem>
              </SelectContent>
            </Select>
          </>
        }
      />
      {error ? (
        <ErrorState error={error} />
      ) : isLoading || !data ? (
        <Loading rows={8} />
      ) : data.nodes.length === 0 ? (
        <EmptyState title="Noch nichts zu zeigen">Sobald Systeme gescannt wurden, erscheint hier die Landschaft.</EmptyState>
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Übersicht</CardTitle>
            <CardDescription>
              Mauszeiger über einen Knoten hebt dessen Verbindungen hervor. Klick öffnet System bzw. Prinzipal. Verwaiste
              Konten werden immer angezeigt.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            <GraphView data={data} layout={layout} onNodeClick={click} height="72vh" />
            <GraphLegend />
          </CardContent>
        </Card>
      )}
    </>
  )
}
