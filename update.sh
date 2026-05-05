# Safer bash behavior
set -euo pipefail

die() {
  echo "[✘] $*" >&2
  exit 1
}

restart_service() {
  local svc="$1"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl restart "$svc" || die "Failed to restart $svc via systemctl"
  else
    service "$svc" restart || die "Failed to restart $svc via service"
  fi
}

require_path() {
  local p="$1"
  local what="${2:-path}"
  [[ -e "$p" ]] || die "Missing required ${what}: $p"
}

# Checking rights.
if [[ $EUID -ne 0 ]]; then
    echo "The update must be run as root. Type in 'sudo bash $0' to run it as root."
	exit 1
fi

if [[ "$PWD" == "/usr/share/spyguard" ]]; then
    echo "[+] Cloning the current repository to /tmp/"
    [[ -d /tmp/spyguard ]] && rm -rf /tmp/spyguard/ &> /dev/null
    command -v git >/dev/null 2>&1 || die "git is required for update (please install git)"
    cd /tmp/
    git clone https://github.com/SpyGuard/spyguard || die "git clone failed"
    [[ -d /tmp/spyguard ]] || die "Clone did not create /tmp/spyguard"
    cd /tmp/spyguard && bash update.sh
elif [[ "$PWD" == "/tmp/spyguard" ]]; then

    # Fail-fast: ensure the new version contains expected directories.
    require_path "/tmp/spyguard/app" "directory"
    require_path "/tmp/spyguard/server" "directory"
    require_path "/tmp/spyguard/analysis" "directory"
    require_path "/tmp/spyguard/assets/requirements.txt" "file"
    require_path "/tmp/spyguard/assets/scheme.sql" "file"

    echo "[+] Backing up local configuration and database"
    BACKUP_DIR="/tmp/spyguard-update-backup-$(date +%s)"
    mkdir -p "$BACKUP_DIR"
    if [[ -f /usr/share/spyguard/config.yaml ]]; then
      cp -f /usr/share/spyguard/config.yaml "$BACKUP_DIR/config.yaml"
    fi
    if [[ -f /usr/share/spyguard/database.sqlite3 ]]; then
      cp -f /usr/share/spyguard/database.sqlite3 "$BACKUP_DIR/database.sqlite3"
    fi

    echo "[+] Saving SpyGuard backend's SSL configuration in /tmp/"
    if compgen -G "/usr/share/spyguard/server/backend/*.pem" > /dev/null; then
        mv /usr/share/spyguard/server/backend/*.pem "$BACKUP_DIR/" || die "Failed to backup backend PEM files"
    fi

    echo "[+] Deleting the current SpyGuard folders and files."
    [[ -d /usr/share/spyguard/app ]] && rm -rf /usr/share/spyguard/app/
    [[ -d /usr/share/spyguard/spyguard-venv ]] && rm -rf /usr/share/spyguard/spyguard-venv/
    [[ -d /usr/share/spyguard/server ]] && rm -rf /usr/share/spyguard/server/
    [[ -d /usr/share/spyguard/analysis ]] && rm -rf /usr/share/spyguard/analysis/
    [[ -f /usr/share/spyguard/update.sh ]] && rm /usr/share/spyguard/update.sh
    [[ -f /usr/share/spyguard/uninstall.sh ]] && rm /usr/share/spyguard/uninstall.sh

    echo "[+] Copying the new SpyGuard version"
    mkdir -p /usr/share/spyguard
    cp -R /tmp/spyguard/app /usr/share/spyguard/app || die "Failed copying app/"
    cp -R /tmp/spyguard/server /usr/share/spyguard/server || die "Failed copying server/"
    cp -R /tmp/spyguard/analysis /usr/share/spyguard/analysis || die "Failed copying analysis/"
    cp /tmp/spyguard/update.sh /usr/share/spyguard/update.sh || die "Failed copying update.sh"
    cp /tmp/spyguard/uninstall.sh /usr/share/spyguard/uninstall.sh || die "Failed copying uninstall.sh"

    echo "[+] Retoring the backend's SSL configuration from /tmp/"
    if compgen -G "$BACKUP_DIR/*.pem" > /dev/null; then
        mv "$BACKUP_DIR"/*.pem /usr/share/spyguard/server/backend/ || die "Failed restoring backend PEM files"
    fi
    if [[ -f "$BACKUP_DIR/config.yaml" ]]; then
      cp -f "$BACKUP_DIR/config.yaml" /usr/share/spyguard/config.yaml || die "Failed restoring config.yaml"
    fi
    if [[ -f "$BACKUP_DIR/database.sqlite3" ]]; then
      cp -f "$BACKUP_DIR/database.sqlite3" /usr/share/spyguard/database.sqlite3 || die "Failed restoring database.sqlite3"
    fi

    echo "[+] Checking system dependencies"
    packages=("tshark"
              "sqlite3"
              "suricata"
              "dnsutils"
              "python3-pip"
              "python3-venv"
              "net-tools")

    apt-get update
    # suricata-update can conflict with packaged suricata on some installs.
    if dpkg-query -W -f='${Status}' suricata-update 2>/dev/null | grep -q -P '^install ok installed$'; then
      echo "[+] Removing suricata-update (conflicts with suricata on some systems)"
      DEBIAN_FRONTEND=noninteractive apt-get remove -y suricata-update || die "Failed removing suricata-update"
    fi
    # `apt-get install` also upgrades already-installed packages to the candidate version.
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}" || die "Failed installing/upgrading system packages"

    echo "[+] Checking possible new Python dependencies"
    python3 -m venv /usr/share/spyguard/spyguard-venv
    source /usr/share/spyguard/spyguard-venv/bin/activate
    # requirements.txt lives in the cloned repo (assets/ is not kept under /usr/share/spyguard after install).
    python3 -m pip install -r /tmp/spyguard/assets/requirements.txt

    echo "[+] Updating the database scheme..."
    cd /usr/share/spyguard/
    sqlite3 database.sqlite3 < /tmp/spyguard/assets/scheme.sql 2>/dev/null

    echo "[+] Updating spyguard configuration"
    sed -i '/max_alerts/d' /tmp/spyguard/config.yaml
    sed -i '/free_issuers/d' /tmp/spyguard/config.yaml
    sed -i '/ CN=/d' /tmp/spyguard/config.yaml
    sed -i '/^frontend:/a\  capture_export: server' /tmp/spyguard/config.yaml
    sed -i '/^frontend:/a\  spyguard_server: https://spyguard.net' /tmp/spyguard/config.yaml
    sed -i '/^frontend:/a\  ui_zoom: 100' /tmp/spyguard/config.yaml


    echo "[+] Restarting services"
    restart_service spyguard-backend
    restart_service spyguard-frontend
    restart_service spyguard-watchers

    echo "[+] Updating the SpyGuard version"
    cd /tmp/spyguard && git describe --tags --always 2>/dev/null | tr -d '\n' > /usr/share/spyguard/VERSION || true

    echo "[+] SpyGuard updated!"
else
    die "Please run this script from /usr/share/spyguard (or from /tmp/spyguard after clone)."
fi
