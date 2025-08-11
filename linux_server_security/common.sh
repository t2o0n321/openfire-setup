#!/bin/bash

# --------------------------------------------------
# Constants
# --------------------------------------------------
# Fail2ban
declare -r WORKING_FAIL2BAN_CONF="/etc/fail2ban/fail2ban.conf"
declare -r WORKING_JAIL_LOCAL_PATH="/etc/fail2ban/jail.local"
declare -r WORKING_UFW_AGGRESSIVE_CONF="/etc/fail2ban/filter.d/ufw.aggressive.conf"
declare -r FAIL2BAN_LOG="/var/log/fail2ban.log"

# Shared memory
declare -r WORKING_FSTAB="/etc/fstab"
declare -r WORKING_SYSCTL_CONF="/etc/sysctl.conf"
declare -r WORKING_SHM="/dev/shm"
declare -r SHM_SIZE="256m"
declare -r MOUNT_ACTION="tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev,size=$SHM_SIZE 0 0"
declare -r KERNEL_SHMMAX=16777216
declare -r KERNEL_SHMALL=4096
declare -r SHM_PERSISTENCE_SCRIPT="set-shm-permissions.sh"
declare -r SHM_PERSISTENCE_SERVICE="set-shm-permissions.service"

# Kernel parameters
declare -r IP_FORWARD="net.ipv4.ip_forward=0"
declare -r ACCEPT_REDIRECT="net.ipv4.conf.all.accept_redirects=0"
declare -r SEND_REDIRECT="net.ipv4.conf.all.send_redirects=0"
declare -r TCP_SYNCOOKIES="net.ipv4.tcp_syncookies=1"
declare -r DISABLE_IPV6="net.ipv6.conf.all.disable_ipv6=1"

# Insecure services
declare -r INSECURE_SERVICES=(
    "xinetd"
    "nis"
    "yp-tools"
    "tftpd"
    "atftpd"
    "tftpd-hpa"
    "telnetd"
    "rsh-server"
    "rsh-redone-server"
)

# SSH
declare -r SSH_CONFIG="/etc/ssh/sshd_config"
declare -r SSH_PERMIT_ROOT_LOGIN="PermitRootLogin no"
get_ssh_port() {
    local port
    if [ -f "$SSH_CONFIG" ]; then
        port=$(grep -E "^Port\s+[0-9]+" "$SSH_CONFIG" | awk '{print $2}' | head -n 1)
        if [ -n "$port" ]; then
            echo "$port"
            return
        fi
    fi
    echo "22"
}
declare -r SSH_CURRENT_PORT=$(get_ssh_port)

# UFW allowed ports (customize as needed)
declare -r UFW_ALLOWED_PORTS=(
    "$SSH_CURRENT_PORT/tcp"   # SSH
    "80/tcp"        # HTTP
    "443/tcp"       # HTTPS
    "9090/tcp"      # Openfire admin console(HTTP)
    "9091/tcp"      # Openfire admin console(HTTPS)
    "5222/tcp"      # XMPP
    "5223/tcp"      # XMPP
    "7443/tcp"      # HTTP binding, file transfer
    "3478/tcp"      # Coturn STUN/TURN
    "3478/udp"      # Coturn STUN/TURN
)

# --------------------------------------------------
# Functions
# --------------------------------------------------
# Get the current timestamp for logging
get_timestamp() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')]"
}

# Check if script is run as root
check_permission() {
    if [ "$EUID" -ne 0 ]; then
        echo "$(get_timestamp) This script must be run with sudo."
        exit 1
    fi
}

# Update ufw.aggressive.conf to ignore allowed ports
update_ufw_aggressive_conf() {
    local ufw_aggressive_conf=$1
    local allowed_ports=()
    for entry in "${UFW_ALLOWED_PORTS[@]}"; do
        port=$(echo "$entry" | cut -d'/' -f1)
        allowed_ports+=("$port")
    done

    local port_regex
    port_regex=$(IFS='|'; echo "${allowed_ports[*]}")
    port_regex=$(echo "$port_regex" | sed 's/|/\\|/g')

    if grep -q "^ignoreregex\s*=" "$ufw_aggressive_conf"; then
        # Update existing ignoreregex line
        sed -i "s#^ignoreregex\s*=.*#ignoreregex = [UFW BLOCK].+SRC=<HOST> DST=.*DPT=(${port_regex})#" "$ufw_aggressive_conf"
    else
        # Append ignoreregex if it doesn't exist
        echo "ignoreregex = [UFW BLOCK].+SRC=<HOST> DST=.*DPT=(${port_regex})" >> "$ufw_aggressive_conf"
    fi

    if [ $? -ne 0 ]; then
        exit 1
    fi
}
