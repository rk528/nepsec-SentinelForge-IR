import {
  Activity,
  BookOpenCheck,
  FileText,
  Gauge,
  Grid3x3,
  ListChecks,
  type LucideIcon,
  Radar,
  ScrollText,
  Search,
  Settings,
  ShieldAlert,
  Siren,
  Workflow,
} from "lucide-react";

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  keywords?: string;
}

export const NAV: { section: string; items: NavItem[] }[] = [
  {
    section: "Operate",
    items: [
      { href: "/dashboard", label: "Overview", icon: Gauge, keywords: "dashboard kpi metrics" },
      { href: "/incidents", label: "Incidents", icon: Siren, keywords: "cases" },
      { href: "/alerts", label: "Alerts", icon: ShieldAlert, keywords: "triage queue detections" },
      { href: "/events", label: "Events", icon: Activity, keywords: "telemetry logs search" },
    ],
  },
  {
    section: "Investigate",
    items: [
      { href: "/investigations", label: "My investigations", icon: ListChecks, keywords: "assigned work" },
      { href: "/threat-intel", label: "Threat intel", icon: Search, keywords: "ioc indicator lookup virustotal abuseipdb otx nepsec" },
    ],
  },
  {
    section: "Engineer",
    items: [
      { href: "/detections", label: "Detections", icon: Radar, keywords: "rules sigma tests" },
      { href: "/attack-coverage", label: "ATT&CK coverage", icon: Grid3x3, keywords: "mitre techniques gaps" },
    ],
  },
  {
    section: "Respond",
    items: [
      { href: "/playbooks", label: "Playbooks", icon: Workflow, keywords: "automation soar" },
      { href: "/response-actions", label: "Response actions", icon: BookOpenCheck, keywords: "approvals containment" },
      { href: "/reports", label: "Reports", icon: FileText, keywords: "export markdown pdf" },
    ],
  },
  {
    section: "Govern",
    items: [
      { href: "/audit", label: "Audit log", icon: ScrollText, keywords: "history who did what" },
      { href: "/settings", label: "Settings", icon: Settings, keywords: "users integrations data sources system" },
    ],
  },
];
