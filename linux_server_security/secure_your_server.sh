#!/bin/bash
# Script to harden an Ubuntu server by securing SSH, installing Fail2Ban, securing shared memory,
# removing insecure services, and configuring basic firewall rules.
# Reference: https://gist.github.com/mirajehossain/59c6e62fcdc84ca1e28b6a048038676c
# Usage: sudo ./harden_server.sh [-y]
#   -y: Auto-confirm all prompts for non-interactive execution

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
██╔╝███████╗███████╗██████╗ ██╗   ██╗███████╗██████╗              
╚═╝ ██╔════╝██╔════╝██╔══██╗██║   ██║██╔════╝██╔══██╗             
    ███████╗█████╗  ██████╔╝██║   ██║█████╗  ██████╔╝             
    ╚════██║██╔══╝  ██╔══██╗╚██╗ ██╔╝██╔══╝  ██╔══██╗             
    ███████║███████╗██║  ██║ ╚████╔╝ ███████╗██║  ██║             
    ╚══════╝╚══════╝╚═╝  ╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝             
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

# Log file and assets
ASSETS_DIR="$CURRENT_DIR/assets"
ASSETS_JAIL_LOCAL="$ASSETS_DIR/fail2ban/jail.local"
ASSETS_UFW_AGGRESSIVE_CONF="$ASSETS_DIR/fail2ban/ufw.aggressive.conf"
LOG_FILE="/var/log/secure_your_server.log"
# Ensure log file exists with secure permissions
[ ! -f "$LOG_FILE" ] && sudo touch "$LOG_FILE" && sudo chmod 600 "$LOG_FILE" && sudo chown root:root "$LOG_FILE"

# Auto-confirm flag for non-interactive execution
AUTO_CONFIRM=0
while getopts "y" opt; do
    case "$opt" in
        y) AUTO_CONFIRM=1 ;;
        *) echo "Usage: $0 [-y]"; exit 1 ;;
    esac
done

# --------------------------------------------------
# Functions
# --------------------------------------------------
# Log messages to file and console, and to system logger
log() {
    local level="$1"
    local message="$2"
    echo "$(get_timestamp) [$level] $message" | tee -a "$LOG_FILE"
    logger -t "harden_server" "[$level] $message"
}

# Handle errors with logging and exit
error_exit() {
    log "ERROR" "$1"
    exit 1
}

# Prompt user for confirmation
confirm() {
    local splitline_length=100
    local prompt_message="$1"
    local log_message="$2"
    log "INFO" "$log_message"

    if [ "$AUTO_CONFIRM" -eq 1 ]; then
        log "INFO" "Auto-confirmed with -y flag: Proceeding with action"
        return 0
    fi

    echo
    printf '%*s\n' "$splitline_length" | tr ' ' '='
    echo "WARNING: $prompt_message"
    printf '%*s\n' "$splitline_length" | tr ' ' '='
    echo
    echo "Enter 'yes' or 'y' to proceed, or any other input to skip:"

    local response
    read -r response
    case "$response" in
        [yY][eE][sS]|[yY])
            log "INFO" "User confirmed: Proceeding with action"
            return 0
            ;;
        *)
            log "INFO" "User declined: Action skipped"
            return 1
            ;;
    esac
}

# Check prerequisites (required tools)
# Check prerequisites (required tools)
check_prerequisites() {
    log "INFO" "Checking prerequisites"
    local required_tools=("apt" "ufw" "systemctl" "sed" "grep" "stat" "netstat")
    local missing_tools=()
    
    # Check for missing tools
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            log "WARNING" "Required tool '$tool' is not installed"
            missing_tools+=("$tool")
        fi
    done

    # If any tools are missing, prompt user to install
    if [ ${#missing_tools[@]} -gt 0 ]; then
        local prompt_message=$(cat << EOF
The following required tools are not installed: $(IFS=','; echo "${missing_tools[*]}").
These tools are necessary for the script to function correctly.
Do you want to install the missing tools now? (yes/no)
EOF
)
        local log_message="Prompting user to install missing tools: $(IFS=','; echo "${missing_tools[*]}")"

        if confirm "$prompt_message" "$log_message"; then
            log "INFO" "Attempting to install missing tools: $(IFS=','; echo "${missing_tools[*]}")"
            
            # Install each missing tool
            for tool in "${missing_tools[@]}"; do
                # Map tool to package name if different
                local package="$tool"
                if [ "$tool" = "netstat" ]; then
                    package="net-tools"
                elif [ "$tool" = "ufw" ]; then
                    package="ufw"
                elif [ "$tool" = "systemctl" ]; then
                    package="systemd"
                elif [ "$tool" = "sed" ]; then
                    package="sed"
                elif [ "$tool" = "grep" ]; then
                    package="grep"
                elif [ "$tool" = "stat" ]; then
                    package="coreutils"
                elif [ "$tool" = "apt" ]; then
                    package="apt"
                fi
                
                log "INFO" "Installing package '$package' for tool '$tool'"
                sudo apt install -y "$package" || error_exit "Failed to install package '$package'"
                
                # Verify installation
                if ! command -v "$tool" &>/dev/null; then
                    error_exit "Tool '$tool' still not found after installation"
                fi
                log "INFO" "Successfully installed '$tool'"
            done
            log "INFO" "All missing tools installed successfully"
        else
            log "INFO" "User declined to install missing tools. Aborting script."
            exit 1
        fi
    fi

    log "INFO" "All prerequisites are met"
}

# Initialize system (update and install basic tools)
init() {
    log "INFO" "Initializing the server"
    sudo apt update -y || error_exit "Failed to update package lists"
    sudo apt upgrade -y || error_exit "Failed to upgrade packages"
    sudo apt install -y apprise ufw || error_exit "Failed to install apprise and ufw"
    sudo ufw logging medium || error_exit "Failed to set UFW logging level"
    log "INFO" "Initialization completed successfully"
}

# Configure basic UFW rules
setup_ufw() {
    log "INFO" "Configuring UFW firewall"
    if ! systemctl is-active --quiet ufw; then
        sudo systemctl enable ufw || error_exit "Failed to enable ufw service"
        sudo systemctl start ufw || error_exit "Failed to start ufw service"
    fi

    # Reset UFW to default state
    sudo ufw --force reset || error_exit "Failed to reset UFW"

    # Set default policies
    sudo ufw default deny incoming || error_exit "Failed to set default deny incoming"
    sudo ufw default allow outgoing || error_exit "Failed to set default allow outgoing"

    # Allow specified ports
    for port in "${UFW_ALLOWED_PORTS[@]}"; do
        sudo ufw allow "$port" || error_exit "Failed to allow port $port"
    done

    # Enable UFW
    sudo ufw --force enable || error_exit "Failed to enable UFW"
    log "INFO" "UFW configured with allowed ports: $(IFS=','; echo "${UFW_ALLOWED_PORTS[*]}")"
}

# Install Fail2Ban
install_fail2ban() {
    log "INFO" "Installing Fail2Ban"
    sudo apt install fail2ban -y || error_exit "Failed to install Fail2Ban"
    sudo systemctl start fail2ban || error_exit "Failed to start Fail2Ban"
    sudo systemctl enable fail2ban || error_exit "Failed to enable Fail2Ban"
    log "INFO" "Fail2Ban installed successfully"
}

# Setup Fail2Ban configuration
setup_fail2ban() {
    log "INFO" "Setting up Fail2Ban"

    # Verify asset files exist
    for file in "$ASSETS_JAIL_LOCAL" "$ASSETS_UFW_AGGRESSIVE_CONF"; do
        if [ ! -f "$file" ]; then
            error_exit "Fail2Ban configuration file $file not found"
        fi
    done

    # Set loglevel to INFO
    sudo sed -i.bak 's/^loglevel\s*=\s*.*/loglevel = INFO/' "$WORKING_FAIL2BAN_CONF" \
        || error_exit "Failed to set loglevel for Fail2Ban"

    # Increase dbpurgeage
    sudo sed -i.bak 's/^dbpurgeage\s*=\s*.*/dbpurgeage = 648000/' "$WORKING_FAIL2BAN_CONF" \
        || error_exit "Failed to edit dbpurgeage for Fail2Ban"

    # Edit ufw.aggressive.conf
    log "INFO" "Updating $ASSETS_UFW_AGGRESSIVE_CONF"
    update_ufw_aggressive_conf "$ASSETS_UFW_AGGRESSIVE_CONF" || error_exit "Failed to update $ASSETS_UFW_AGGRESSIVE_CONF"
    log "INFO" "Updated $ASSETS_UFW_AGGRESSIVE_CONF with allowed ports: $(IFS=','; echo "${UFW_ALLOWED_PORTS[*]}")"

    # Copy configuration files
    sudo cp "$WORKING_JAIL_LOCAL_PATH" "$WORKING_JAIL_LOCAL_PATH.bak" 2>/dev/null || true
    sudo cp "$WORKING_UFW_AGGRESSIVE_CONF" "$WORKING_UFW_AGGRESSIVE_CONF.bak" 2>/dev/null || true
    sudo cp "$ASSETS_JAIL_LOCAL" "$WORKING_JAIL_LOCAL_PATH" || error_exit "Failed to copy jail.local"
    sudo cp "$ASSETS_UFW_AGGRESSIVE_CONF" "$WORKING_UFW_AGGRESSIVE_CONF" || error_exit "Failed to copy ufw.aggressive.conf"

    # Set permissions
    sudo chmod 600 "$WORKING_JAIL_LOCAL_PATH" "$WORKING_UFW_AGGRESSIVE_CONF" || error_exit "Failed to set permissions on Fail2Ban configs"
    sudo chown root:root "$WORKING_JAIL_LOCAL_PATH" "$WORKING_UFW_AGGRESSIVE_CONF" || error_exit "Failed to set ownership on Fail2Ban configs"

    # Restart Fail2Ban
    sudo systemctl reload fail2ban || error_exit "Failed to reload Fail2Ban service"
    sudo systemctl restart fail2ban || error_exit "Failed to restart Fail2Ban service"
    log "INFO" "Fail2Ban setup completed"
}

# Check Fail2Ban health
check_fail2ban_health() {
    log "INFO" "Checking Fail2Ban health"
    if ! systemctl is-active --quiet fail2ban; then
        error_exit "Fail2Ban service is not running"
    fi
    if ! [ -r "$FAIL2BAN_LOG" ]; then
        error_exit "Fail2Ban log file is not readable"
    fi
    log "INFO" "Fail2Ban health check passed"
}

# Script to persist permission of /dev/shm
persist_shm_permission() {
    local script=$(cat << EOF
#!/bin/bash
sudo chmod 0750 $WORKING_SHM
sudo chown root:sudo $WORKING_SHM
EOF
)
    local service=$(cat << EOF
[Unit]
Description=Set $WORKING_SHM permissions and ownership
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/$SHM_PERSISTENCE_SCRIPT
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
)

    echo "$script" | sudo tee /usr/local/bin/$SHM_PERSISTENCE_SCRIPT > /dev/null
    sudo chmod +x /usr/local/bin/$SHM_PERSISTENCE_SCRIPT
    echo "$service" | sudo tee /etc/systemd/system/$SHM_PERSISTENCE_SERVICE > /dev/null

    sudo systemctl enable $SHM_PERSISTENCE_SERVICE || error_exit "Failed to enable $SHM_PERSISTENCE_SERVICE"
    sudo systemctl start $SHM_PERSISTENCE_SERVICE || error_exit "Failed to start $SHM_PERSISTENCE_SERVICE"
    log "INFO" "Created systemd service to set $WORKING_SHM permissions on boot"
}

# Secure shared memory
secure_shared_memory() {
    log "INFO" "Starting shared memory hardening process"

    # -----------------------------------------------
    # Configure /dev/shm mount options in /etc/fstab
    # -----------------------------------------------
    log "INFO" "Backing up $WORKING_FSTAB"
    sudo cp "$WORKING_FSTAB" "$WORKING_FSTAB.bak" \
        || error_exit "Failed to backup $WORKING_FSTAB"

    # Check if /dev/shm entry exists in fstab
    if grep -q "^tmpfs.*$WORKING_SHM" "$WORKING_FSTAB"; then
        log "INFO" "Updating existing $WORKING_FSTAB entry in $WORKING_FSTAB"
        sudo sed -i.bak "s|^tmpfs.*$WORKING_SHM.*|$MOUNT_ACTION|" "$WORKING_FSTAB" \
            || error_exit "Failed to update $WORKING_FSTAB entry in $WORKING_FSTAB"
    else
        log "INFO" "Appending new $WORKING_FSTAB entry to $WORKING_FSTAB"
        echo "$MOUNT_ACTION" | sudo tee -a "$WORKING_FSTAB" > /dev/null \
            || error_exit "Failed to append $WORKING_FSTAB entry to $WORKING_FSTAB"
    fi

    # Verify the fstab entry
    if ! grep -q "tmpfs.*$WORKING_SHM.*noexec.*nosuid.*nodev.*size=$SHM_SIZE" "$WORKING_FSTAB"; then
        error_exit "Failed to verify $WORKING_FSTAB entry in $WORKING_FSTAB"
    fi
    log "INFO" "Applied noexec,nosuid,nodev,size=$SHM_SIZE to $WORKING_SHM in $WORKING_FSTAB"

    # -----------------------------------------------
    # Reload systemd to recognize fstab changes
    # -----------------------------------------------
    log "INFO" "Reloading systemd to apply fstab changes"
    sudo systemctl daemon-reload || error_exit "Failed to reload systemd"

    # -----------------------------------------------
    # Remount /dev/shm to apply changes
    # -----------------------------------------------
    log "INFO" "Remounting $WORKING_SHM to apply mount options"
    sudo mount -o remount "$WORKING_SHM" || error_exit "Failed to remount $WORKING_SHM"

    # -----------------------------------------------
    # Verify mount options
    # -----------------------------------------------
    log "INFO" "Verifying mount options for $WORKING_SHM"
    local mount_output
    mount_output=$(mount | grep "$WORKING_SHM" || true)
    log "INFO" "Current mount options: $mount_output"

    # Check each required option individually
    local missing_options=()
    for option in noexec nosuid nodev; do
        if ! echo "$mount_output" | grep -q "$option"; then
            missing_options+=("$option")
        fi
    done

    if [ ${#missing_options[@]} -ne 0 ]; then
        error_exit "Failed to verify mount options for $WORKING_SHM: missing $(IFS=','; echo "${missing_options[*]}")"
    fi
    log "INFO" "$WORKING_SHM remounted with noexec,nosuid,nodev"

    # -----------------------------------------------
    # Limit System V IPC shared memory usage
    # -----------------------------------------------
    log "INFO" "Backing up $WORKING_SYSCTL_CONF"
    sudo cp "$WORKING_SYSCTL_CONF" "$WORKING_SYSCTL_CONF.bak" \
        || error_exit "Failed to backup $WORKING_SYSCTL_CONF"

    # Update or append kernel.shmmax
    if grep -q "^kernel.shmmax" "$WORKING_SYSCTL_CONF"; then
        log "INFO" "Updating existing kernel.shmmax in $WORKING_SYSCTL_CONF"
        sudo sed -i.bak "s|^kernel.shmmax.*|kernel.shmmax=$KERNEL_SHMMAX|" "$WORKING_SYSCTL_CONF" \
            || error_exit "Failed to update kernel.shmmax in $WORKING_SYSCTL_CONF"
    else
        log "INFO" "Appending kernel.shmmax to $WORKING_SYSCTL_CONF"
        echo "kernel.shmmax=$KERNEL_SHMMAX" | sudo tee -a "$WORKING_SYSCTL_CONF" > /dev/null \
            || error_exit "Failed to append kernel.shmmax to $WORKING_SYSCTL_CONF"
    fi

    # Update or append kernel.shmall
    if grep -q "^kernel.shmall" "$WORKING_SYSCTL_CONF"; then
        log "INFO" "Updating existing kernel.shmall in $WORKING_SYSCTL_CONF"
        sudo sed -i.bak "s|^kernel.shmall.*|kernel.shmall=$KERNEL_SHMALL|" "$WORKING_SYSCTL_CONF" \
            || error_exit "Failed to update kernel.shmall in $WORKING_SYSCTL_CONF"
    else
        log "INFO" "Appending kernel.shmall to $WORKING_SYSCTL_CONF"
        echo "kernel.shmall=$KERNEL_SHMALL" | sudo tee -a "$WORKING_SYSCTL_CONF" > /dev/null \
            || error_exit "Failed to append kernel.shmall to $WORKING_SYSCTL_CONF"
    fi

    # Verify sysctl entries
    if ! grep -q "^kernel.shmmax=$KERNEL_SHMMAX" "$WORKING_SYSCTL_CONF" || \
       ! grep -q "^kernel.shmall=$KERNEL_SHMALL" "$WORKING_SYSCTL_CONF"; then
        error_exit "Failed to verify sysctl entries in $WORKING_SYSCTL_CONF"
    fi

    # Apply sysctl changes
    log "INFO" "Applying sysctl changes"
    sudo sysctl -p "$WORKING_SYSCTL_CONF" || error_exit "Failed to apply sysctl changes"
    log "INFO" "Limited System V IPC shared memory usage (shmmax=$KERNEL_SHMMAX, shmall=$KERNEL_SHMALL)"

    # -----------------------------------------------
    # Restrict /dev/shm access to root and sudo group
    # -----------------------------------------------
    log "INFO" "Setting permissions (750) and ownership (root:sudo) on $WORKING_SHM"

    # Ensure /dev/shm exists and is a directory
    if [ ! -d "$WORKING_SHM" ]; then
        error_exit "$WORKING_SHM does not exist or is not a directory"
    fi

    # Verify sudo group exists
    if ! getent group sudo >/dev/null; then
        error_exit "The 'sudo' group does not exist on this system"
    fi

    # Attempt to set permissions and ownership with retry mechanism
    local max_attempts=3
    local attempt=1
    local perms owner
    while [ $attempt -le $max_attempts ]; do
        log "INFO" "Attempt $attempt/$max_attempts: Setting permissions and ownership on $WORKING_SHM"
        # Explicitly set permissions without sticky bit
        sudo chmod 0750 "$WORKING_SHM" || { log "ERROR" "Failed to set permissions on $WORKING_SHM"; error_exit "chmod failed"; }
        sudo chown root:sudo "$WORKING_SHM" || { log "ERROR" "Failed to set ownership of $WORKING_SHM"; error_exit "chown failed"; }

        # Verify permissions and ownership
        perms=$(stat -c "%a" "$WORKING_SHM")
        owner=$(stat -c "%U:%G" "$WORKING_SHM")
        if [ "$perms" = "750" ] && [ "$owner" = "root:sudo" ]; then
            log "INFO" "Successfully set permissions (750) and ownership (root:sudo) on $WORKING_SHM"
            break
        else
            log "WARNING" "Permissions ($perms) or ownership ($owner) on $WORKING_SHM not as expected"
            if [ $attempt -eq $max_attempts ]; then
                error_exit "Failed to set permissions (750) or ownership (root:sudo) on $WORKING_SHM after $max_attempts attempts"
            fi
            sleep 1 # Wait before retrying
            ((attempt++))
        fi
    done

    # Verify permissions persist after remount
    log "INFO" "Verifying permissions after remount"
    sudo mount -o remount "$WORKING_SHM" || error_exit "Failed to remount $WORKING_SHM"
    perms=$(stat -c "%a" "$WORKING_SHM")
    owner=$(stat -c "%U:%G" "$WORKING_SHM")
    if [ "$perms" != "750" ] || [ "$owner" != "root:sudo" ]; then
        log "ERROR" "Permissions ($perms) or ownership ($owner) on $WORKING_SHM reset after remount"
        error_exit "Failed to maintain permissions (750) or ownership (root:sudo) on $WORKING_SHM after remount"
    else
        persist_shm_permission
    fi

    # Verify mount point integrity
    if ! mount | grep -q "$WORKING_SHM.*tmpfs"; then
        error_exit "$WORKING_SHM is not mounted as tmpfs"
    fi

    log "INFO" "Shared memory hardening completed successfully"
}

# Hardening kernel parameters
kernel_hardening() {
    log "INFO" "Starting kernel parameters hardening"

    # -----------------------------------------------
    # Backup sysctl.conf
    # -----------------------------------------------
    log "INFO" "Backing up $WORKING_SYSCTL_CONF"
    sudo cp "$WORKING_SYSCTL_CONF" "$WORKING_SYSCTL_CONF.bak" \
        || error_exit "Failed to backup $WORKING_SYSCTL_CONF"

    # -----------------------------------------------
    # Define kernel parameters to set
    # -----------------------------------------------
    local kernel_params=(
        "$IP_FORWARD"
        "$ACCEPT_REDIRECT"
        "$SEND_REDIRECT"
        "$TCP_SYNCOOKIES"
        "$DISABLE_IPV6"
    )

    # -----------------------------------------------
    # Update or add kernel parameters
    # -----------------------------------------------
    for param in "${kernel_params[@]}"; do
        local key="${param%%=*}"
        local value="${param#*=}"
        log "INFO" "Configuring $key=$value in $WORKING_SYSCTL_CONF"

        # Check if the parameter exists in sysctl.conf
        if grep -q "^\s*${key}\s*=" "$WORKING_SYSCTL_CONF"; then
            log "INFO" "Updating existing $key in $WORKING_SYSCTL_CONF"
            sudo sed -i.bak "s|^\s*${key}\s*=.*|${key}=${value}|" "$WORKING_SYSCTL_CONF" \
                || error_exit "Failed to update $key in $WORKING_SYSCTL_CONF"
        else
            log "INFO" "Adding $key to $WORKING_SYSCTL_CONF"
            echo "${key}=${value}" | sudo tee -a "$WORKING_SYSCTL_CONF" > /dev/null \
                || error_exit "Failed to add $key to $WORKING_SYSCTL_CONF"
        fi

        # Verify the parameter was set correctly
        if ! grep -q "^${key}=${value}" "$WORKING_SYSCTL_CONF"; then
            error_exit "Failed to verify $key=$value in $WORKING_SYSCTL_CONF"
        fi
    done

    # -----------------------------------------------
    # Apply sysctl changes
    # -----------------------------------------------
    log "INFO" "Applying sysctl changes"
    sudo sysctl -p "$WORKING_SYSCTL_CONF" || error_exit "Failed to apply sysctl changes"

    # -----------------------------------------------
    # Verify applied kernel parameters
    # -----------------------------------------------
    log "INFO" "Verifying kernel parameters"
    local failed_verifications=()
    for param in "${kernel_params[@]}"; do
        local key="${param%%=*}"
        local expected_value="${param#*=}"
        local current_value
        current_value=$(sysctl -n "$key" 2>/dev/null || echo "not found")
        if [ "$current_value" != "$expected_value" ]; then
            failed_verifications+=("$key: expected $expected_value, got $current_value")
        fi
    done

    if [ ${#failed_verifications[@]} -ne 0 ]; then
        error_exit "Failed to verify kernel parameters: $(IFS=','; echo "${failed_verifications[*]}")"
    fi

    log "INFO" "Kernel parameters hardened successfully"
}

# Remove insecure services
remove_insecure_services() {
    log "INFO" "Removing insecure services: $(IFS=','; echo "${INSECURE_SERVICES[*]}")"
    local failed_services=()
    for service in "${INSECURE_SERVICES[@]}"; do
        if dpkg -l | grep -q "^ii\s*$service\s"; then
            sudo apt --purge remove -y "$service" || failed_services+=("$service")
        fi
    done

    if [ ${#failed_services[@]} -ne 0 ]; then
        log "WARNING" "Failed to remove services: $(IFS=','; echo "${failed_services[*]}")"
    fi

    # Check if any insecure services are still installed
    local remaining_services=()
    for service in "${INSECURE_SERVICES[@]}"; do
        if dpkg -l | grep -q "^ii\s*$service\s"; then
            remaining_services+=("$service")
        fi
    done

    if [ ${#remaining_services[@]} -ne 0 ]; then
        log "WARNING" "Some insecure services are still installed: $(IFS=','; echo "${failed_services[*]}")"
    else
        log "INFO" "Insecure services removed successfully"
    fi
}

# Disable root SSH login
ssh_hardening() {
    log "INFO" "Hardening SSH"

    # -----------------------------------------------
    # Rate limit on default SSH port
    # -----------------------------------------------
    sudo ufw limit "$SSH_CURRENT_PORT/tcp" || error_exit "Failed to set rate-limiting for SSH"

    # -----------------------------------------------
    # Disable root SSH login
    # -----------------------------------------------
    local prompt_message=$(cat << EOF
Disabling root SSH login requires a non-root user with sudo privileges to avoid lockout.
On Vultr VPS, the default 'ubuntu' user has sudo privileges. Ensure you have another sudo user.
Do you want to disable root SSH login? (yes/no)
EOF
)
    local log_message="Prompting user to disable root SSH login"

    log "INFO" "Disabling root SSH login"

    if ! systemctl is-active --quiet ssh; then
        error_exit "SSH service is not running"
    fi

    if ! confirm "$prompt_message" "$log_message"; then
        log "INFO" "Skipping root SSH login disable"
        return 0
    fi

    sudo cp "$SSH_CONFIG" "$SSH_CONFIG.bak" \
        || error_exit "Failed to backup $SSH_CONFIG"

    if grep -q "^PermitRootLogin" "$SSH_CONFIG"; then
        sudo sed -i.bak "s/^PermitRootLogin.*/$SSH_PERMIT_ROOT_LOGIN/" "$SSH_CONFIG" \
            || error_exit "Failed to update PermitRootLogin in $SSH_CONFIG"
    else
        echo "$SSH_PERMIT_ROOT_LOGIN" | sudo tee -a "$SSH_CONFIG" > /dev/null \
            || error_exit "Failed to append PermitRootLogin to $SSH_CONFIG"
    fi

    if ! grep -q "^$SSH_PERMIT_ROOT_LOGIN" "$SSH_CONFIG"; then
        error_exit "Failed to verify PermitRootLogin setting in $SSH_CONFIG"
    fi

    sudo systemctl restart ssh || error_exit "Failed to restart SSH service"
    log "INFO" "Root SSH login disabled successfully"
}

# Prompt for system reboot
prompt_reboot() {
    local prompt_message=$(cat << EOF
Some changes (e.g., fstab, sysctl) require a reboot to take full effect.
Do you want to reboot the system now? (yes/no)
EOF
)
    local log_message="Prompting user for system reboot"

    if confirm "$prompt_message" "$log_message"; then
        log "INFO" "Initiating system reboot"
        sudo reboot
    else
        log "WARNING" "Reboot skipped. Some changes may not take effect until the system is rebooted."
    fi
}

# Main function
main() {
    echo "$ARTS_TITLE"
    check_permission
    check_prerequisites
    init
    setup_ufw
    ssh_hardening
    install_fail2ban
    setup_fail2ban
    check_fail2ban_health
    secure_shared_memory
    kernel_hardening
    remove_insecure_services
    prompt_reboot
}

# --------------------------------------------------
# Main
# --------------------------------------------------
main