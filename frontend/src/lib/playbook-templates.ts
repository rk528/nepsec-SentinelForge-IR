// Ready-made playbooks for common scenarios. A lead starts the builder from one, changes what their organisation does
// differently, and saves it as their own; nothing here runs until it is saved and started on an incident.
// Automated steps name the built-in actions (app/playbooks/registry.py); the firewall block still needs a lead's approval.

import type { PlaybookStep } from "@/lib/types";

export interface PlaybookTemplate {
  id: string;
  name: string;
  description: string;
  trigger_rules: string[];
  steps: PlaybookStep[];
}

const action = (id: string, title: string, instructions = ""): PlaybookStep => ({ kind: "action", action: id, title, instructions });
const task = (title: string, instructions = ""): PlaybookStep => ({ kind: "task", action: null, title, instructions });

const COLLECT = action("collect_related_evidence", "Collect related evidence", "Pulls in events that share a host, user or IP within 12 hours.");
const ENRICH = action("enrich_iocs", "Enrich associated IOCs", "Looks up the external IPs, domains and hashes in the evidence.");
const SUMMARY = action("prepare_summary", "Prepare the incident summary");
const CLOSE = action("closure_report", "Generate the closure report");

export const PLAYBOOK_TEMPLATES: PlaybookTemplate[] = [
  {
    id: "phishing",
    name: "Phishing email",
    description: "A user opened or clicked a phishing email. Find who else got it, stop the link, and check whether credentials were entered.",
    trigger_rules: ["SF-MAIL-001"],
    steps: [
      COLLECT,
      ENRICH,
      task("Find every recipient of the same message", "Search mail logs for the sender, subject and link. List each recipient and whether they clicked."),
      task("Remove the message from all mailboxes", "Purge it with the mail platform's search-and-purge, and record the number removed."),
      action("propose_blocklist", "Propose blocking the sender domain and link"),
      task("Ask users who clicked whether they entered a password", "If they did, reset it, revoke their sessions and check sign-ins since the click."),
      task("Warn staff", "Send a short notice with a screenshot of the email and how to report it."),
      SUMMARY,
      CLOSE,
    ],
  },
  {
    id: "compromised-account",
    name: "Compromised account (password guessing)",
    description: "Repeated failed sign-ins followed by a success. Confirm with the user, lock the account down and look for what the attacker did.",
    trigger_rules: ["SF-AUTH-001"],
    steps: [
      COLLECT,
      ENRICH,
      task("Confirm with the user by phone", "Ask whether they signed in at that time and from that place. Do not use email, which may be read by the attacker."),
      task("Reset the password and revoke all sessions", "Also remove any MFA methods, app passwords or mail forwarding rules added recently."),
      action("propose_blocklist", "Propose blocking the source addresses"),
      action("simulate_firewall_block", "Block the source addresses at the firewall", "Needs approval from a different lead."),
      task("Review what the account did after the sign-in", "Files opened, mail sent, rules created, other systems reached."),
      action("record_containment", "Record containment"),
      SUMMARY,
      CLOSE,
    ],
  },
  {
    id: "malware-endpoint",
    name: "Malware or suspicious process on an endpoint",
    description: "A living-off-the-land binary, an odd scheduled task or a Run key. Isolate the machine, find how it started and whether it spread.",
    trigger_rules: ["SF-PROC-001", "SF-PERS-001", "SF-PERS-002"],
    steps: [
      COLLECT,
      ENRICH,
      task("Isolate the host from the network", "Use the EDR's network isolation, or move it to a quarantine VLAN. Keep it powered on for memory evidence."),
      task("Collect the file and its hash", "Save the binary or script, its parent process and command line as evidence."),
      task("Remove persistence", "Delete the scheduled task, service or Run key, and record exactly what was removed."),
      task("Search for the same hash and command line on other hosts"),
      action("propose_blocklist", "Propose blocking the domains and IPs it contacted"),
      action("record_containment", "Record containment"),
      task("Reimage or clean the host and return it to service"),
      SUMMARY,
      CLOSE,
    ],
  },
  {
    id: "credential-dumping",
    name: "Credential dumping (LSASS)",
    description: "Someone read LSASS memory or copied the credential hives. Treat every account that used the host as exposed.",
    trigger_rules: ["SF-CRED-001"],
    steps: [
      COLLECT,
      task("Isolate the host immediately", "Credential theft usually comes just before lateral movement."),
      task("List every account that signed in to the host", "Include service accounts and administrators. Each one's password or hash must be treated as stolen."),
      task("Reset those passwords, privileged accounts first", "Reset the krbtgt account twice if a domain controller was involved."),
      task("Look for use of the stolen accounts elsewhere", "Sign-ins from the host to other systems, new RDP or SMB sessions, pass-the-hash patterns."),
      ENRICH,
      action("record_containment", "Record containment"),
      SUMMARY,
      CLOSE,
    ],
  },
  {
    id: "ransomware",
    name: "Ransomware",
    description: "Files being encrypted, shadow copies deleted or security logging turned off. Contain fast, protect backups, then recover.",
    trigger_rules: ["SF-PROC-001", "SF-DEF-001", "SF-CRED-001"],
    steps: [
      task("Isolate affected hosts and disconnect shared drives", "Speed matters more than evidence here. Do not power machines off: memory may hold the key."),
      task("Protect the backups", "Take backup systems offline or make sure they are immutable before anything else."),
      COLLECT,
      ENRICH,
      task("Identify the ransomware family", "From the ransom note, file extension and hashes. Check whether a free decryptor exists."),
      action("propose_blocklist", "Propose blocking its command and control addresses"),
      action("simulate_firewall_block", "Block command and control at the firewall", "Needs approval from a different lead."),
      task("Inform management, legal and, if personal data is involved, the regulator", "Record who was told and when."),
      task("Restore from clean backups and reset all credentials"),
      action("record_containment", "Record containment"),
      SUMMARY,
      CLOSE,
    ],
  },
  {
    id: "data-exfiltration",
    name: "Data exfiltration or suspicious outbound traffic",
    description: "Large or unusual uploads to an outside address. Find what left, stop it and decide who must be told.",
    trigger_rules: ["SF-NET-001"],
    steps: [
      COLLECT,
      ENRICH,
      task("Work out what data left", "Bytes sent, files read just before, the destination and its owner."),
      action("propose_blocklist", "Propose blocking the destination"),
      action("simulate_firewall_block", "Block the destination at the firewall", "Needs approval from a different lead."),
      task("Check the user and host for compromise", "Was it the user, malware or a misconfigured backup?"),
      task("Decide on notification", "If personal or customer data left, involve legal and record the decision."),
      action("record_containment", "Record containment"),
      SUMMARY,
      CLOSE,
    ],
  },
  {
    id: "privileged-account",
    name: "New privileged account",
    description: "An account was created or added to an administrators group. Confirm it was a planned change, or remove it.",
    trigger_rules: ["SF-IAM-001"],
    steps: [
      COLLECT,
      task("Find the change ticket", "Ask the person who made the change. No ticket means treat it as hostile."),
      task("Disable the account or remove it from the group if it was not planned"),
      task("Check what the account did", "Sign-ins, systems reached, other accounts it changed."),
      task("Check how the creator's account was used", "If it was not them, follow the compromised account playbook for that account too."),
      action("record_containment", "Record containment"),
      SUMMARY,
      CLOSE,
    ],
  },
  {
    id: "rdp-lateral-movement",
    name: "Suspicious RDP / lateral movement",
    description: "Remote desktop sessions from unusual places or between workstations. Trace the path and cut it.",
    trigger_rules: ["SF-LAT-001"],
    steps: [
      COLLECT,
      ENRICH,
      task("Map the path", "Which host and account connected to which, in time order."),
      task("Confirm with the account owner"),
      task("Reset the accounts used and close the sessions"),
      action("propose_blocklist", "Propose blocking any outside source addresses"),
      task("Restrict RDP", "Allow it only from jump hosts, and require MFA for remote access."),
      action("record_containment", "Record containment"),
      SUMMARY,
      CLOSE,
    ],
  },
  {
    id: "exposed-service",
    name: "Exposed service or vulnerability (NepSec Intel)",
    description: "NepSec Intel's attack surface monitoring found an open service, a known vulnerability or weak mail settings on your domain.",
    trigger_rules: ["SF-EXT-001"],
    steps: [
      task("Open the finding in NepSec Intel", "The alert's evidence has the link, the asset and the CVEs behind it."),
      task("Confirm the owner of the asset", "Which team runs it, and whether it should face the internet at all."),
      task("Check for signs it was already exploited", "Search events for the asset's address, especially for exploited CVEs (CISA KEV)."),
      COLLECT,
      task("Patch, close the port or put it behind a VPN", "Record the change and who made it."),
      task("Ask NepSec Intel to scan again", "Attack surface, Scan now. The finding should no longer appear."),
      SUMMARY,
      CLOSE,
    ],
  },
  {
    id: "user-report",
    name: "Reported by a user or another team",
    description: "For alerts raised by hand: a call to the help desk, a tip from IT, something no rule caught.",
    trigger_rules: ["SF-MAN-001"],
    steps: [
      task("Talk to the person who reported it", "What they saw, when, on which device. Keep their words in a note."),
      task("Link the events that match", "From the incident, Evidence, Link events, or from each event's page."),
      COLLECT,
      ENRICH,
      task("Decide: real, harmless or mistaken", "If real, start the playbook for the scenario it turned out to be."),
      SUMMARY,
      CLOSE,
    ],
  },
];
