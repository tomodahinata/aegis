import type { ReactNode } from 'react';
import { AppShell } from '@/components/layout/app-shell';

// Auth is enforced by middleware (redirect to /login); this layout provides the shell + landmarks.
export default function DashboardLayout({ children }: { children: ReactNode }) {
  return <AppShell>{children}</AppShell>;
}
