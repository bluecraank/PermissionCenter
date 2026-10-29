import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { ThemeProvider } from 'next-themes'

import './index.css'
import { AppLayout } from '@/components/app-layout'
import { TooltipProvider } from '@/components/ui/tooltip'
import { Toaster } from '@/components/ui/sonner'
import DashboardPage from '@/pages/dashboard'
import SystemsPage from '@/pages/systems'
import SystemDetailPage from '@/pages/system-detail'
import FindingsPage from '@/pages/findings'
import RecommendationsPage from '@/pages/recommendations'
import AuditPage from '@/pages/audit'
import AssistPage from '@/pages/assist'
import ChangesPage from '@/pages/changes'
import AccessPage from '@/pages/access'
import OwnersPage from '@/pages/owners'
import { AuditReportPage, PrincipalReportPage } from '@/pages/reports'
import PrincipalsPage from '@/pages/principals'
import PrincipalDetailPage from '@/pages/principal-detail'
import AdPage from '@/pages/active-directory'
import LandscapePage from '@/pages/landscape'
import SettingsPage from '@/pages/settings'
import NotFoundPage from '@/pages/not-found'

const queryClient = new QueryClient({
  defaultOptions: { queries: { staleTime: 30_000, refetchOnWindowFocus: false, retry: 1 } },
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeProvider attribute="class" defaultTheme="system" enableSystem>
      <QueryClientProvider client={queryClient}>
        <TooltipProvider>
          <BrowserRouter>
            <Routes>
              <Route path="report/audit" element={<AuditReportPage />} />
              <Route path="report/principal/:sid" element={<PrincipalReportPage />} />
              <Route element={<AppLayout />}>
                <Route index element={<DashboardPage />} />
                <Route path="landscape" element={<LandscapePage />} />
                <Route path="systems" element={<SystemsPage />} />
                <Route path="systems/:id" element={<SystemDetailPage />} />
                <Route path="principals" element={<PrincipalsPage />} />
                <Route path="principals/:sid" element={<PrincipalDetailPage />} />
                <Route path="ad" element={<AdPage />} />
                <Route path="findings" element={<FindingsPage />} />
                <Route path="audit" element={<AuditPage />} />
                <Route path="assist" element={<AssistPage />} />
                <Route path="changes" element={<ChangesPage />} />
                <Route path="access" element={<AccessPage />} />
                <Route path="owners" element={<OwnersPage />} />
                <Route path="recommendations" element={<RecommendationsPage />} />
                <Route path="settings" element={<SettingsPage />} />
                <Route path="*" element={<NotFoundPage />} />
              </Route>
            </Routes>
          </BrowserRouter>
          <Toaster richColors position="bottom-right" />
        </TooltipProvider>
      </QueryClientProvider>
    </ThemeProvider>
  </StrictMode>,
)
