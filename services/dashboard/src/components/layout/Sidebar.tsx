"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  ShieldAlert,
  Activity,
  Network,
  AlertTriangle,
  Search,
  Wrench,
  Shield,
} from "lucide-react";
import { cn } from "@/lib/utils";

const NAV_ITEMS = [
  { href: "/attack-surface", label: "Attack Surface", icon: ShieldAlert },
  { href: "/runtime-analytics", label: "Runtime Analytics", icon: Activity },
  { href: "/asset-graph", label: "Asset Graph", icon: Network },
  { href: "/exposure", label: "Exposure Prioritization", icon: AlertTriangle },
  { href: "/evidence", label: "Evidence Viewer", icon: Search },
  { href: "/remediation", label: "Remediation Tracking", icon: Wrench },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="flex h-screen w-[240px] flex-shrink-0 flex-col border-r border-border bg-card">
      {/* Logo */}
      <div className="flex h-14 items-center gap-2.5 border-b border-border px-5">
        <Shield className="h-6 w-6 text-primary" />
        <span className="text-sm font-bold tracking-wide text-foreground">
          CVEs <span className="text-primary">Enterprise</span>
        </span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-4">
        <ul className="space-y-0.5 px-3">
          {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
            const isActive = pathname.startsWith(href);
            return (
              <li key={href}>
                <Link
                  href={href}
                  className={cn(
                    "flex items-center gap-3 rounded-md px-3 py-2.5 text-sm font-medium transition-colors",
                    isActive
                      ? "bg-primary/10 text-primary"
                      : "text-muted-foreground hover:bg-accent hover:text-foreground"
                  )}
                >
                  <Icon className="h-4 w-4 flex-shrink-0" />
                  {label}
                </Link>
              </li>
            );
          })}
        </ul>
      </nav>

      {/* Footer */}
      <div className="border-t border-border px-5 py-3">
        <p className="text-xs text-muted-foreground">CVEs Enterprise v0.1.0</p>
      </div>
    </aside>
  );
}
