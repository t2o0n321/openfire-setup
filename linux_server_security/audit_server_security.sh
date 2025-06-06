#!/bin/bash
# Script to audit the security settings applied to an Ubuntu server based on the hardening script.
# Reference: https://gist.github.com/mirajehossain/59c6e62fcdc84ca1e28b6a048038676c
# Usage: sudo ./audit_ubuntu_hardening.sh
# Outputs a report of compliance status and logs to /var/log/audit_ubuntu_hardening.log

set -euo pipefail
IFS=$'\n\t'

# --------------------------------------------------
# Arts (for visual appeal)
# --------------------------------------------------
ARTS_TITLE=$(cat <<EOF
    ██╗                                                           
   ██╔╝                                                           
  ██╔╝█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗
 ██╔╝ ╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝
██╔╝       █████╗ ██╗   ██╗██████╗ ██╗████████╗                   
╚═╝       ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝                   
          ███████║██║   ██║██║  ██║██║   ██║                      
          ██╔══██║██║   ██║██║  ██║██║   ██║                      
          ██║  ██║╚██████╔╝██████╔╝██║   ██║                      
          ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝                      
███████╗███████╗ ██████╗██╗   ██╗██████╗ ██╗████████╗██╗   ██╗    
██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██║╚══██╔══╝╚██╗ ██╔╝    
███████╗█████╗  ██║     ██║   ██║██████╔╝██║   ██║    ╚████╔╝     
╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██║   ██║     ╚██╔╝      
███████║███████╗╚██████╗╚██████╔╝██║  ██║██║   ██║      ██║    ██╗
╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝   ╚═╝      ╚═╝   ██╔╝
█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗ ██╔╝ 
╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝██╔╝  
                                                           ██╔╝   
                                                           ╚═╝    
EOF
)

# --------------------------------------------------
# Constants
# --------------------------------------------------
# Global
CURRENT_DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"
source "$CURRENT_DIR/common.sh" # Include common functions and variables

# Log files
LOG_FILE="/var/log/audit_ubuntu_hardening.log"
ERROR_LOG="/var/log/audit_ubuntu_hardening_error.log"
# Ensure log file exists with secure permissions
[ ! -f "$LOG_FILE" ] && sudo touch "$LOG_FILE" && sudo chmod 600 "$LOG_FILE" && sudo chown root:root "$LOG_FILE"
# Ensure log file exists with secure permissions
[ ! -f "$ERROR_LOG" ] && sudo touch "$ERROR_LOG" && sudo chmod 600 "$ERROR_LOG" && sudo chown root:root "$ERROR_LOG"

# --------------------------------------------------
# Functions
# --------------------------------------------------
# Log messages to file and console, and to system logger
log() {
    local level="$1"
    local message="$2"
    echo "$(get_timestamp) [$level] $message" | tee -a "$LOG_FILE"
    logger -t "audit_ubuntu_hardening" "[$level] $message"
}

# Handle errors with logging and exit
error_exit() {
    log "ERROR" "$1"
    exit 1
}

# Initialize audit report
init_report() {
    log "INFO" "Initializing audit report"
    REPORT=()
    NON_COMPLIANT=0
}

# Add to audit report
add_to_report() {
    local status="$1"
    local message="$2"
    REPORT+=("$status: $message")
    if [ "$status" = "FAIL" ]; then
        NON_COMPLIANT=$((NON_COMPLIANT + 1))
    fi
}

# Audit shared memory configuration
audit_shared_memory() {
    log "INFO" "Auditing shared memory configuration"

    # -----------------------------------------------
    # Check /dev/shm mount options in fstab
    # -----------------------------------------------
    log "INFO" "Checking $WORKING_FSTAB for correct $WORKING_SHM mount options"
    if grep -q "tmpfs.*$WORKING_SHM.*noexec.*nosuid.*nodev.*size=$SHM_SIZE" "$WORKING_FSTAB"; then
        add_to_report "PASS" "$WORKING_FSTAB contains correct mount options (noexec,nosuid,nodev,size=$SHM_SIZE)"
    else
        add_to_report "FAIL" "$WORKING_FSTAB missing or incorrect $WORKING_SHM mount options"
    fi

    # -----------------------------------------------
    # Check current /dev/shm mount options
    # -----------------------------------------------
    log "INFO" "Checking current mount options for $WORKING_SHM"
    local mount_output
    mount_output=$(mount | grep "$WORKING_SHM" || true)
    log "INFO" "Current mount options: $mount_output"
    local missing_options=()
    for option in noexec nosuid nodev; do
        if ! echo "$mount_output" | grep -q "$option"; then
            missing_options+=("$option")
        fi
    done
    if [ ${#missing_options[@]} -eq 0 ]; then
        add_to_report "PASS" "$WORKING_SHM mount options include noexec,nosuid,nodev"
    else
        add_to_report "FAIL" "$WORKING_SHM mount missing options: $(IFS=','; echo "${missing_options[*]}")"
    fi

    # -----------------------------------------------
    # Check /dev/shm permissions and ownership
    # -----------------------------------------------
    log "INFO" "Checking permissions (750) and ownership (root:sudo) on $WORKING_SHM"
    local perms owner
    perms=$(stat -c "%a" "$WORKING_SHM" 2>/dev/null || echo "not found")
    owner=$(stat -c "%U:%G" "$WORKING_SHM" 2>/dev/null || echo "not found")
    if [ "$perms" = "750" ] && [ "$owner" = "root:sudo" ]; then
        add_to_report "PASS" "$WORKING_SHM permissions (750) and ownership (root:sudo) are correct"
    else
        add_to_report "FAIL" "$WORKING_SHM permissions ($perms) or ownership ($owner) are incorrect"
    fi

    # -----------------------------------------------
    # Check systemd service for /dev/shm permissions
    # -----------------------------------------------
    log "INFO" "Checking $SHM_PERSISTENCE_SERVICE for persisting $WORKING_SHM permissions"
    if [ -f "/usr/local/bin/$SHM_PERSISTENCE_SCRIPT" ] && systemctl is-enabled --quiet "$SHM_PERSISTENCE_SERVICE" && \
       systemctl is-active --quiet "$SHM_PERSISTENCE_SERVICE"; then
        add_to_report "PASS" "$SHM_PERSISTENCE_SERVICE is enabled and active to persist $WORKING_SHM permissions"
    else
        add_to_report "FAIL" "$SHM_PERSISTENCE_SERVICE is missing, not enabled, or not active"
    fi

    # -----------------------------------------------
    # Check sysctl shared memory settings
    # -----------------------------------------------
    log "INFO" "Checking sysctl shared memory settings in $WORKING_SYSCTL_CONF"
    if grep -q "^kernel.shmmax=$KERNEL_SHMMAX" "$WORKING_SYSCTL_CONF" && \
       grep -q "^kernel.shmall=$KERNEL_SHMALL" "$WORKING_SYSCTL_CONF"; then
        add_to_report "PASS" "Sysctl shared memory settings (shmmax=$KERNEL_SHMMAX, shmall=$KERNEL_SHMALL) are correct"
    else
        add_to_report "FAIL" "Sysctl shared memory settings in $WORKING_SYSCTL_CONF are incorrect or missing"
    fi

    # -----------------------------------------------
    # Verify applied sysctl values
    # -----------------------------------------------
    log "INFO" "Verifying applied sysctl shared memory values"
    local shmmax_value shmall_value
    shmmax_value=$(sysctl -n kernel.shmmax 2>/dev/null || echo "not found")
    shmall_value=$(sysctl -n kernel.shmall 2>/dev/null || echo "not found")
    if [ "$shmmax_value" = "$KERNEL_SHMMAX" ] && [ "$shmall_value" = "$KERNEL_SHMALL" ]; then
        add_to_report "PASS" "Applied sysctl shared memory values are correct (shmmax=$KERNEL_SHMMAX, shmall=$KERNEL_SHMALL)"
    else
        add_to_report "FAIL" "Applied sysctl shared memory values are incorrect (shmmax=$shmmax_value, shmall=$shmall_value)"
    fi
}

# Audit insecure services
audit_insecure_services() {
    log "INFO" "Auditing insecure services: $(IFS=','; echo "${INSECURE_SERVICES[*]}")"

    # -----------------------------------------------
    # Check for installed insecure services
    # -----------------------------------------------
    local installed_services=()
    for service in "${INSECURE_SERVICES[@]}"; do
        if dpkg -l | grep -q "^ii\s*$service\s"; then
            installed_services+=("$service")
        fi
    done
    if [ ${#installed_services[@]} -eq 0 ]; then
        add_to_report "PASS" "No insecure services ($(IFS=','; echo "${INSECURE_SERVICES[*]}")) are installed"
    else
        add_to_report "FAIL" "Insecure services installed: $(IFS=','; echo "${installed_services[*]}")"
    fi
}

# Audit non-root accounts with UID 0
audit_uid_zero() {
    log "INFO" "Auditing accounts with UID 0"

    # -----------------------------------------------
    # Check for non-root accounts with UID 0
    # -----------------------------------------------
    local uid_zero_accounts
    uid_zero_accounts=$(awk -F: '($3 == "0") {print $1}' /etc/passwd || true)
    if [[ "$uid_zero_accounts" == "root" || -z "$uid_zero_accounts" ]]; then
        add_to_report "PASS" "Only root account (or no accounts) have UID 0"
    else
        add_to_report "FAIL" "Non-root accounts with UID 0 detected: $(echo "$uid_zero_accounts" | tr '\n' ',')"
    fi
}

# Audit SSH configuration
audit_ssh() {
    log "INFO" "Auditing SSH configuration"

    # -----------------------------------------------
    # Check SSH service status
    # -----------------------------------------------
    log "INFO" "Checking if SSH service is running"
    if systemctl is-active --quiet ssh; then
        add_to_report "PASS" "SSH service is running"
    else
        add_to_report "FAIL" "SSH service is not running"
    fi

    # -----------------------------------------------
    # Check PermitRootLogin setting
    # -----------------------------------------------
    log "INFO" "Checking PermitRootLogin in $SSH_CONFIG"
    if grep -q "^$SSH_PERMIT_ROOT_LOGIN" "$SSH_CONFIG"; then
        add_to_report "PASS" "Root SSH login is disabled (PermitRootLogin no)"
    else
        add_to_report "FAIL" "Root SSH login is not disabled in $SSH_CONFIG"
    fi

    # -----------------------------------------------
    # Check for AllowUsers directive
    # -----------------------------------------------
    log "INFO" "Checking for AllowUsers directive in $SSH_CONFIG"
    if grep -q "^AllowUsers" "$SSH_CONFIG"; then
        local allowed_users
        allowed_users=$(grep "^AllowUsers" "$SSH_CONFIG" | awk '{print $2}' | tr '\n' ',')
        add_to_report "PASS" "SSH restricted to specific users: $allowed_users"
    else
        add_to_report "WARNING" "No AllowUsers directive found in $SSH_CONFIG; SSH access not restricted to specific users"
    fi

    # -----------------------------------------------
    # Check SSH port rate-limiting
    # -----------------------------------------------
    log "INFO" "Checking UFW rate-limiting for SSH port $SSH_CURRENT_PORT"
    if ufw status | grep -q "^$SSH_CURRENT_PORT/tcp.*LIMIT"; then
        add_to_report "PASS" "SSH port $SSH_CURRENT_PORT is rate-limited in UFW"
    else
        add_to_report "FAIL" "SSH port $SSH_CURRENT_PORT is not rate-limited in UFW"
    fi
}

# Audit Fail2Ban configuration
audit_fail2ban() {
    log "INFO" "Auditing Fail2Ban configuration"

    # -----------------------------------------------
    # Check Fail2Ban installation and service status
    # -----------------------------------------------
    log "INFO" "Checking Fail2Ban installation and service status"
    if command -v fail2ban-server >/dev/null && systemctl is-active --quiet fail2ban; then
        add_to_report "PASS" "Fail2Ban is installed and running"
    else
        add_to_report "FAIL" "Fail2Ban is not installed or not running"
    fi

    # -----------------------------------------------
    # Check Fail2Ban log file
    # -----------------------------------------------
    log "INFO" "Checking readability of Fail2Ban log file $FAIL2BAN_LOG"
    if [ -r "$FAIL2BAN_LOG" ]; then
        add_to_report "PASS" "Fail2Ban log file $FAIL2BAN_LOG is readable"
    else
        add_to_report "FAIL" "Fail2Ban log file $FAIL2BAN_LOG is not readable or does not exist"
    fi

    # -----------------------------------------------
    # Check jail.local configuration
    # -----------------------------------------------
    log "INFO" "Checking $WORKING_JAIL_LOCAL_PATH configuration for SSH"
    if [ -f "$WORKING_JAIL_LOCAL_PATH" ] && \
       grep -q "^\[sshd\]" "$WORKING_JAIL_LOCAL_PATH" && \
       grep -q "^enabled\s*=\s*true" "$WORKING_JAIL_LOCAL_PATH" && \
       grep -q "^port\s*=\s*$SSH_CURRENT_PORT" "$WORKING_JAIL_LOCAL_PATH" && \
       grep -q "^filter\s*=\s*sshd" "$WORKING_JAIL_LOCAL_PATH" && \
       grep -q "^logpath\s*=\s*/var/log/auth.log" "$WORKING_JAIL_LOCAL_PATH" && \
       grep -q "^maxretry\s*=\s*5" "$WORKING_JAIL_LOCAL_PATH"; then
        add_to_report "PASS" "$WORKING_JAIL_LOCAL_PATH is configured correctly for SSH on port $SSH_CURRENT_PORT"
    else
        add_to_report "FAIL" "$WORKING_JAIL_LOCAL_PATH is missing or misconfigured"
    fi

    # -----------------------------------------------
    # Check fail2ban.conf settings
    # -----------------------------------------------
    log "INFO" "Checking $WORKING_FAIL2BAN_CONF settings"
    if grep -q "^loglevel\s*=\s*INFO" "$WORKING_FAIL2BAN_CONF" && \
       grep -q "^dbpurgeage\s*=\s*648000" "$WORKING_FAIL2BAN_CONF"; then
        add_to_report "PASS" "Fail2Ban configuration (loglevel=INFO, dbpurgeage=648000) is correct"
    else
        add_to_report "FAIL" "Fail2Ban configuration in $WORKING_FAIL2BAN_CONF is incorrect"
    fi

    # -----------------------------------------------
    # Check ufw.aggressive.conf
    # -----------------------------------------------
    log "INFO" "Checking $WORKING_UFW_AGGRESSIVE_CONF existence"
    if [ -f "$WORKING_UFW_AGGRESSIVE_CONF" ]; then
        add_to_report "PASS" "$WORKING_UFW_AGGRESSIVE_CONF exists"
    else
        add_to_report "FAIL" "$WORKING_UFW_AGGRESSIVE_CONF is missing"
    fi
}

# Audit UFW configuration
audit_ufw() {
    log "INFO" "Auditing UFW configuration"

    # -----------------------------------------------
    # Check UFW service status
    # -----------------------------------------------
    log "INFO" "Checking UFW service status"
    if systemctl is-active --quiet ufw; then
        add_to_report "PASS" "UFW is enabled and running"
    else
        add_to_report "FAIL" "UFW is not enabled or not running"
    fi

    # -----------------------------------------------
    # Check UFW default policies
    # -----------------------------------------------
    log "INFO" "Checking UFW default policies"
    local default_incoming default_outgoing
    default_incoming=$(sudo ufw status verbose | grep "^Default:.*incoming" | awk '{print $2}' || echo "not found")
    default_outgoing=$(sudo ufw status verbose | grep "^Default:.*outgoing" | awk '{print $4}' || echo "not found")
    if [ "$default_incoming" = "deny" ] && [ "$default_outgoing" = "allow" ]; then
        add_to_report "PASS" "UFW default policies are correct (deny incoming, allow outgoing)"
    else
        add_to_report "FAIL" "UFW default policies are incorrect (incoming=$default_incoming, outgoing=$default_outgoing)"
    fi

    # -----------------------------------------------
    # Check UFW allowed ports
    # -----------------------------------------------
    log "INFO" "Checking UFW allowed ports: $(IFS=','; echo "${UFW_ALLOWED_PORTS[*]}")"
    local allowed_ports=()
    while IFS= read -r line; do
        if [[ "$line" =~ ^([0-9]+(,[0-9]+)*(/[a-z]+)?).*(ALLOW|LIMIT)\ IN ]]; then
            # Split multi-port rules
            local ports="${BASH_REMATCH[1]}"
            local proto=""
            # Extract protocol ("/tcp" ...)
            if [[ "$ports" =~ (/[a-z]+)$ ]]; then
                proto="${BASH_REMATCH[1]}"
                ports=${ports%"${proto}"}
            fi
            # Split comma-separated ports
            IFS=',' read -ra port_list <<< "$ports"
            for port in "${port_list[@]}"; do
                allowed_ports+=("${port}${proto}")
            done
        fi
    done < <(ufw status verbose | grep -E "ALLOW|LIMIT" || true)
    local missing_ports=()
    for port in "${UFW_ALLOWED_PORTS[@]}"; do
        if ! printf '%s\n' "${allowed_ports[@]}" | grep -Fx "$port" >/dev/null; then
            missing_ports+=("$port")
        fi
    done
    if [ ${#missing_ports[@]} -eq 0 ]; then
        add_to_report "PASS" "UFW allows expected ports: $(IFS=','; echo "${UFW_ALLOWED_PORTS[*]}")"
    else
        add_to_report "FAIL" "UFW missing expected ports: $(IFS=','; echo "${missing_ports[*]}")"
    fi
}

# Audit kernel parameters
audit_kernel_parameters() {
    log "INFO" "Auditing kernel parameters"

    # -----------------------------------------------
    # Check kernel parameters
    # -----------------------------------------------
    local kernel_params=(
        "$IP_FORWARD"
        "$ACCEPT_REDIRECT"
        "$SEND_REDIRECT"
        "$TCP_SYNCOOKIES"
        "$DISABLE_IPV6"
    )
    for param in "${kernel_params[@]}"; do
        local key="${param%%=*}"
        local expected_value="${param#*=}"
        log "INFO" "Checking $key=$expected_value"
        local current_value
        current_value=$(sysctl -n "$key" 2>/dev/null || echo "not found")
        if [ "$current_value" = "$expected_value" ]; then
            add_to_report "PASS" "Kernel parameter $key is set to $expected_value"
        else
            add_to_report "FAIL" "Kernel parameter $key is incorrect (expected $expected_value, got $current_value)"
        fi
    done
}

# Print audit report
print_report() {
    log "INFO" "Generating audit report"

    # -----------------------------------------------
    # Display report
    # -----------------------------------------------
    local splitline_length=100
    echo
    printf '%*s\n' "$splitline_length" | tr ' ' '='
    echo "Ubuntu Server Hardening Audit Report - $(date '+%Y-%m-%d %H:%M:%S')"
    printf '%*s\n' "$splitline_length" | tr ' ' '='
    for entry in "${REPORT[@]}"; do
        echo "$entry"
    done
    echo
    if [ "$NON_COMPLIANT" -eq 0 ]; then
        log "INFO" "Audit completed: All checks passed"
        echo "All security settings are compliant."
    else
        log "WARNING" "Audit completed: $NON_COMPLIANT non-compliant settings found"
        echo "WARNING: $NON_COMPLIANT non-compliant settings found. Review the report and take corrective action."
        exit 1
    fi
    printf '%*s\n' "$splitline_length" | tr ' ' '='

    # -----------------------------------------------
    # Reminder for physical security
    # -----------------------------------------------
    log "INFO" "Reminder: Physical security must be verified manually"
    echo "Reminder: Verify physical server security (BIOS passwords, IDC access) manually."
}

# Main function
main() {
    echo "$ARTS_TITLE"
    check_permission
    init_report
    audit_shared_memory
    audit_insecure_services
    audit_uid_zero
    audit_ssh
    audit_fail2ban
    audit_ufw
    audit_kernel_parameters
    print_report
}

# --------------------------------------------------
# Main
# --------------------------------------------------
main