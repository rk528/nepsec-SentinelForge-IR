#!/usr/bin/env bash
# Install the SentinelForge IR Linux shipper on Ubuntu Server or Ubuntu Desktop.
#
#   sudo ./install.sh --api-url https://sentinelforge-api.kuinkel.com
#   sudo ./install.sh --uninstall
#
# The ingest key is read from SENTINELFORGE_INGEST_KEY or prompted for (hidden input),
# never taken as an argument, so it does not appear in shell history or process listings.
set -euo pipefail

PREFIX=/opt/sentinelforge
CONF_DIR=/etc/sentinelforge
ENV_FILE=$CONF_DIR/linux-shipper.env
STATE_DIR=/var/lib/sentinelforge
SERVICE_USER=sentinelforge
UNIT=sentinelforge-shipper
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

api_url=""
uninstall=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --api-url) api_url="${2:-}"; shift 2 ;;
    --uninstall) uninstall=1; shift ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ $EUID -ne 0 ]]; then echo "Run with sudo." >&2; exit 1; fi

if [[ $uninstall -eq 1 ]]; then
  systemctl disable --now "$UNIT.timer" 2>/dev/null || true
  rm -f "/etc/systemd/system/$UNIT.service" "/etc/systemd/system/$UNIT.timer"
  systemctl daemon-reload
  rm -rf "$PREFIX" "$CONF_DIR" "$STATE_DIR"
  id "$SERVICE_USER" >/dev/null 2>&1 && userdel "$SERVICE_USER"
  echo "SentinelForge shipper removed."
  exit 0
fi

if [[ ! "$api_url" =~ ^https:// ]]; then echo "--api-url must be an https:// URL" >&2; exit 2; fi
command -v python3 >/dev/null || { echo "python3 is required (sudo apt install python3)" >&2; exit 1; }
command -v journalctl >/dev/null || { echo "journalctl not found: this shipper needs systemd" >&2; exit 1; }

key="${SENTINELFORGE_INGEST_KEY:-}"
if [[ -z "$key" ]]; then
  read -r -s -p "Ingest key for this host's data source (sfk_...): " key; echo
fi
if [[ ! "$key" =~ ^sfk_ ]]; then echo "That is not an ingest key (it starts with sfk_)." >&2; exit 2; fi

# Dedicated, login-less account that may read the system journal and nothing more.
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE_USER"
fi
usermod -a -G systemd-journal "$SERVICE_USER"

install -d -m 0755 "$PREFIX"
install -m 0755 "$HERE/sentinelforge_linux_shipper.py" "$PREFIX/sentinelforge_linux_shipper.py"
install -d -m 0750 -o root -g "$SERVICE_USER" "$CONF_DIR"
umask 027
printf 'SENTINELFORGE_URL=%s\nSENTINELFORGE_INGEST_KEY=%s\n' "$api_url" "$key" > "$ENV_FILE"
chown root:"$SERVICE_USER" "$ENV_FILE"
chmod 0640 "$ENV_FILE"
install -d -m 0750 -o "$SERVICE_USER" -g "$SERVICE_USER" "$STATE_DIR"

cat > "/etc/systemd/system/$UNIT.service" <<EOF
[Unit]
Description=Ship security events from the journal to SentinelForge IR
Documentation=https://github.com/rk528/nepsec-SentinelForge-IR/blob/main/docs/connectors-linux.md
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=$SERVICE_USER
Group=$SERVICE_USER
SupplementaryGroups=systemd-journal
EnvironmentFile=$ENV_FILE
ExecStart=/usr/bin/python3 $PREFIX/sentinelforge_linux_shipper.py --state $STATE_DIR/journal.cursor
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ReadWritePaths=$STATE_DIR
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
EOF

cat > "/etc/systemd/system/$UNIT.timer" <<EOF
[Unit]
Description=Run the SentinelForge IR shipper every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min
RandomizedDelaySec=30
Persistent=true

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now "$UNIT.timer"
echo "Running a first collection..."
if systemctl start "$UNIT.service"; then
  journalctl -u "$UNIT.service" -n 3 --no-pager -o cat
  echo "Installed. Events are sent every 5 minutes. Check: systemctl list-timers $UNIT.timer"
else
  journalctl -u "$UNIT.service" -n 20 --no-pager -o cat
  echo "The first run failed; see the log above. Fix the cause and run: sudo systemctl start $UNIT.service" >&2
  exit 1
fi
