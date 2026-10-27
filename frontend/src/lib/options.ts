import type { IncidentStatus } from "./types";

export const STATUS_OPTIONS = [
  { value: "new", label: "New" },
  { value: "open", label: "Open" },
  { value: "investigating", label: "Investigating" },
  { value: "contained", label: "Contained" },
  { value: "resolved", label: "Resolved" },
  { value: "closed", label: "Closed" },
];

export const SEVERITY_OPTIONS = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "informational", label: "Info" },
];

export const ALERT_STATUS_OPTIONS = [
  { value: "new", label: "New" },
  { value: "acknowledged", label: "Acknowledged" },
  { value: "escalated", label: "Escalated" },
  { value: "closed", label: "Closed" },
];

/** Mirrors the backend state machine (app/services/incidents.py). The server is authoritative. */
export const TRANSITIONS: Record<IncidentStatus, IncidentStatus[]> = {
  new: ["open", "investigating", "closed"],
  open: ["investigating", "closed"],
  investigating: ["contained", "resolved", "closed"],
  contained: ["investigating", "resolved"],
  resolved: ["investigating", "closed"],
  closed: ["open"],
};

export const TRANSITION_LABEL: Record<IncidentStatus, string> = {
  new: "Mark new",
  open: "Open",
  investigating: "Start investigating",
  contained: "Mark contained",
  resolved: "Mark resolved",
  closed: "Close incident",
};
