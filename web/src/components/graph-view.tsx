import { useEffect, useRef } from 'react'
import cytoscape, { type Core, type ElementDefinition } from 'cytoscape'
import { useTheme } from 'next-themes'

import type { GraphData, GraphNode } from '@/lib/api'
import { gradeColor } from '@/lib/format'

export type GraphLayout = 'cose' | 'breadthfirst' | 'concentric'

const TYPE_COLORS: Record<string, string> = {
  domain: '#6366f1',
  system: '#0ea5e9',
  share: '#14b8a6',
  folder: '#a3a3a3',
  group: '#8b5cf6',
  user: '#f59e0b',
  computer: '#64748b',
  well_known: '#94a3b8',
  unknown: '#94a3b8',
}

const SHAPES: Record<string, string> = {
  domain: 'hexagon',
  system: 'round-rectangle',
  share: 'diamond',
  folder: 'round-tag',
  group: 'ellipse',
  user: 'ellipse',
  computer: 'round-rectangle',
}

function nodeColor(n: GraphNode): string {
  if (n.status === 'orphaned') return '#ef4444'
  if (n.status === 'disabled') return '#f97316'
  if (n.type === 'system' && n.grade) return gradeColor(n.grade)
  if (n.type === 'folder' && n.error) return '#ef4444'
  if (n.type === 'folder' && n.protected) return '#eab308'
  return TYPE_COLORS[n.type] ?? '#94a3b8'
}

export function GraphView({
  data,
  layout = 'cose',
  onNodeClick,
  height = '70vh',
}: {
  data: GraphData
  layout?: GraphLayout
  onNodeClick?: (n: GraphNode) => void
  height?: string
}) {
  const ref = useRef<HTMLDivElement>(null)
  const cyRef = useRef<Core | null>(null)
  const clickRef = useRef(onNodeClick)
  useEffect(() => {
    clickRef.current = onNodeClick
  }, [onNodeClick])
  const { resolvedTheme } = useTheme()
  const dark = resolvedTheme === 'dark'

  useEffect(() => {
    if (!ref.current) return
    const elements: ElementDefinition[] = [
      ...data.nodes.map((n) => ({
        data: { ...n, color: nodeColor(n), shape: SHAPES[n.type] ?? 'ellipse' },
      })),
      ...data.edges.map((e) => ({ data: { ...e, label: e.label ?? '' } })),
    ]
    const fg = dark ? '#e5e5e5' : '#262626'
    const cy = cytoscape({
      container: ref.current,
      elements,
      wheelSensitivity: 0.3,
      minZoom: 0.1,
      maxZoom: 3,
      style: [
        {
          selector: 'node',
          style: {
            'background-color': 'data(color)',
            shape: 'data(shape)' as never,
            label: 'data(label)',
            color: fg,
            'font-size': 10,
            'text-valign': 'bottom',
            'text-margin-y': 4,
            'text-wrap': 'ellipsis',
            'text-max-width': '140px',
            width: 22,
            height: 22,
            'border-width': 0,
          },
        },
        { selector: 'node[type="domain"]', style: { width: 44, height: 44, 'font-size': 13, 'font-weight': 'bold' } },
        { selector: 'node[type="system"]', style: { width: 36, height: 28, 'font-size': 12, 'font-weight': 'bold' } },
        { selector: 'node[type="folder"]', style: { width: 16, height: 16, 'font-size': 9 } },
        { selector: 'node[status="orphaned"]', style: { 'border-width': 3, 'border-color': '#991b1b' } },
        {
          selector: 'edge',
          style: {
            width: 1.2,
            'line-color': dark ? '#525252' : '#d4d4d4',
            'target-arrow-color': dark ? '#525252' : '#d4d4d4',
            'target-arrow-shape': 'triangle',
            'arrow-scale': 0.7,
            'curve-style': 'bezier',
          },
        },
        {
          selector: 'edge[type="grants"]',
          style: {
            'line-color': '#60a5fa',
            'target-arrow-color': '#60a5fa',
            label: 'data(label)',
            'font-size': 8,
            color: dark ? '#a3a3a3' : '#737373',
            'text-rotation': 'autorotate',
          },
        },
        { selector: 'edge[type="deny"]', style: { 'line-color': '#ef4444', 'target-arrow-color': '#ef4444', 'line-style': 'dashed' } },
        { selector: 'edge[type="member_of"]', style: { 'line-color': '#a78bfa', 'target-arrow-color': '#a78bfa', 'line-style': 'dotted' } },
        { selector: '.faded', style: { opacity: 0.12 } },
        { selector: 'node:selected', style: { 'border-width': 3, 'border-color': '#2563eb' } },
      ],
      layout:
        layout === 'breadthfirst'
          ? { name: 'breadthfirst', directed: true, spacingFactor: 1.1, animate: false }
          : layout === 'concentric'
            ? {
                name: 'concentric',
                animate: false,
                concentric: (n: cytoscape.NodeSingular) =>
                  ({ domain: 4, system: 3, share: 2 } as Record<string, number>)[n.data('type')] ?? 1,
                levelWidth: () => 1,
              }
            : { name: 'cose', animate: false, nodeRepulsion: () => 9000, idealEdgeLength: () => 90, padding: 30 },
    })
    // Nachbarschaft hervorheben
    cy.on('mouseover', 'node', (e) => {
      const n = e.target.closedNeighborhood()
      cy.elements().difference(n).addClass('faded')
    })
    cy.on('mouseout', 'node', () => cy.elements().removeClass('faded'))
    cy.on('tap', 'node', (e) => clickRef.current?.(e.target.data() as GraphNode))
    cyRef.current = cy
    return () => cy.destroy()
  }, [data, layout, dark])

  return <div ref={ref} className="bg-muted/30 w-full rounded-lg border" style={{ height }} />
}

export function GraphLegend() {
  const items: [string, string][] = [
    ['Domäne', TYPE_COLORS.domain],
    ['System (Farbe = Note)', TYPE_COLORS.system],
    ['Freigabe', TYPE_COLORS.share],
    ['Ordner', TYPE_COLORS.folder],
    ['Vererbung unterbrochen', '#eab308'],
    ['Gruppe', TYPE_COLORS.group],
    ['Benutzer', TYPE_COLORS.user],
    ['Verwaist / Fehler', '#ef4444'],
    ['Deaktiviert', '#f97316'],
  ]
  return (
    <div className="text-muted-foreground flex flex-wrap gap-x-4 gap-y-1 text-xs">
      {items.map(([l, c]) => (
        <span key={l} className="flex items-center gap-1.5">
          <span className="size-2.5 rounded-full" style={{ background: c }} />
          {l}
        </span>
      ))}
    </div>
  )
}
