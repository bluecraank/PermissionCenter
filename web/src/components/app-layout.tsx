import { NavLink, Outlet, useLocation } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { useTheme } from 'next-themes'
import {
  Building2,
  ClipboardCheck,
  FolderTree,
  LayoutDashboard,
  Lightbulb,
  ListChecks,
  Moon,
  Network,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sun,
  Users,
} from 'lucide-react'

import { Button } from '@/components/ui/button'
import { Separator } from '@/components/ui/separator'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
} from '@/components/ui/sidebar'
import { api, type Dashboard } from '@/lib/api'

const nav = [
  {
    label: 'Überblick',
    items: [
      { to: '/', label: 'Dashboard', icon: LayoutDashboard },
      { to: '/landscape', label: 'IT-Landschaft', icon: Network },
    ],
  },
  {
    label: 'Inventar',
    items: [
      { to: '/systems', label: 'Systeme', icon: Server },
      { to: '/principals', label: 'Benutzer & Gruppen', icon: Users },
      { to: '/ad', label: 'Active Directory', icon: Building2 },
    ],
  },
  {
    label: 'Auswertung',
    items: [
      { to: '/findings', label: 'Befunde', icon: ShieldAlert, badge: true },
      { to: '/assist', label: 'Audit-Assist', icon: ListChecks },
      { to: '/audit', label: 'Audit', icon: ClipboardCheck },
      { to: '/recommendations', label: 'Empfehlungen', icon: Lightbulb },
    ],
  },
]

function ThemeToggle() {
  const { resolvedTheme, setTheme } = useTheme()
  const dark = resolvedTheme === 'dark'
  return (
    <Button variant="ghost" size="icon" onClick={() => setTheme(dark ? 'light' : 'dark')} title="Darstellung wechseln">
      {dark ? <Sun className="size-4" /> : <Moon className="size-4" />}
    </Button>
  )
}

const titles: [RegExp, string][] = [
  [/^\/$/, 'Dashboard'],
  [/^\/landscape/, 'IT-Landschaft'],
  [/^\/systems\/\d+/, 'System'],
  [/^\/systems/, 'Systeme'],
  [/^\/principals\/.+/, 'Prinzipal'],
  [/^\/principals/, 'Benutzer & Gruppen'],
  [/^\/ad/, 'Active Directory'],
  [/^\/findings/, 'Befunde'],
  [/^\/assist/, 'Audit-Assist'],
  [/^\/audit/, 'Audit'],
  [/^\/recommendations/, 'Empfehlungen'],
  [/^\/settings/, 'Einstellungen'],
]

export function AppLayout() {
  const { pathname } = useLocation()
  const { data } = useQuery({ queryKey: ['dashboard'], queryFn: () => api.get<Dashboard>('/dashboard') })
  const open = data ? data.findings.critical + data.findings.high : 0
  const title = titles.find(([re]) => re.test(pathname))?.[1] ?? ''

  return (
    <SidebarProvider>
      <Sidebar collapsible="icon">
        <SidebarHeader>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton size="lg" asChild>
                <NavLink to="/">
                  <div className="bg-sidebar-primary text-sidebar-primary-foreground flex aspect-square size-8 items-center justify-center rounded-lg">
                    <ShieldCheck className="size-4" />
                  </div>
                  <div className="grid flex-1 text-left text-sm leading-tight">
                    <span className="truncate font-semibold">PermissionCenter</span>
                    <span className="text-muted-foreground truncate text-xs">
                      {data?.ad.domain ?? 'Berechtigungsanalyse'}
                    </span>
                  </div>
                </NavLink>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarHeader>
        <SidebarContent>
          {nav.map((group) => (
            <SidebarGroup key={group.label}>
              <SidebarGroupLabel>{group.label}</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {group.items.map((item) => {
                    const active = item.to === '/' ? pathname === '/' : pathname.startsWith(item.to)
                    return (
                      <SidebarMenuItem key={item.to}>
                        <SidebarMenuButton asChild isActive={active} tooltip={item.label}>
                          <NavLink to={item.to}>
                            <item.icon />
                            <span>{item.label}</span>
                          </NavLink>
                        </SidebarMenuButton>
                        {item.badge && open > 0 && <SidebarMenuBadge className="text-sev-high">{open}</SidebarMenuBadge>}
                      </SidebarMenuItem>
                    )
                  })}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          ))}
        </SidebarContent>
        <SidebarFooter>
          <SidebarMenu>
            <SidebarMenuItem>
              <SidebarMenuButton asChild isActive={pathname.startsWith('/settings')} tooltip="Einstellungen">
                <NavLink to="/settings">
                  <Settings />
                  <span>Einstellungen</span>
                </NavLink>
              </SidebarMenuButton>
            </SidebarMenuItem>
          </SidebarMenu>
        </SidebarFooter>
      </Sidebar>
      <SidebarInset>
        <header className="bg-background/80 sticky top-0 z-10 flex h-14 shrink-0 items-center gap-2 border-b px-4 backdrop-blur">
          <SidebarTrigger className="-ml-1" />
          <Separator orientation="vertical" className="mr-2 data-[orientation=vertical]:h-4" />
          <span className="text-sm font-medium">{title}</span>
          <div className="ml-auto flex items-center gap-1">
            <span className="text-muted-foreground hidden items-center gap-1 text-xs sm:flex">
              <FolderTree className="size-3.5" />
              {data ? `${data.totals.systems} Systeme` : ''}
            </span>
            <ThemeToggle />
          </div>
        </header>
        <main className="mx-auto w-full max-w-[1600px] flex-1 space-y-6 p-4 md:p-6">
          <Outlet />
        </main>
      </SidebarInset>
    </SidebarProvider>
  )
}
