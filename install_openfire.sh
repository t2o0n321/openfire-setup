#!/bin/bash

set -euo pipefail
IFS=$'\n\t'

# --------------------------------------------------
# Arts
# --------------------------------------------------
ARTS_TITLE=$(cat <<'EOF'
    ██╗                                                           
   ██╔╝                                                           
  ██╔╝█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗
 ██╔╝ ╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝
██╔╝   ██╗███╗   ██╗███████╗████████╗ █████╗ ██╗     ██╗          
╚═╝    ██║████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║     ██║          
       ██║██╔██╗ ██║███████╗   ██║   ███████║██║     ██║          
       ██║██║╚██╗██║╚════██║   ██║   ██╔══██║██║     ██║          
       ██║██║ ╚████║███████║   ██║   ██║  ██║███████╗███████╗     
       ╚═╝╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝╚══════╝     
 ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗██████╗ ███████╗    
██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔══██╗██╔════╝    
██║   ██║██████╔╝█████╗  ██╔██╗ ██║█████╗  ██║██████╔╝█████╗      
██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║██╔══╝  ██║██╔══██╗██╔══╝      
╚██████╔╝██║     ███████╗██║ ╚████║██║     ██║██║  ██║███████╗ ██╗
 ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝██╔╝
█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗█████╗ ██╔╝ 
╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝╚════╝██╔╝  
                                                           ██╔╝   
                                                           ╚═╝    
EOF
)

# --------------------------------------------------
# Init constants
# --------------------------------------------------
CURRENT_DIR="$(realpath "$(dirname "${BASH_SOURCE[0]}")")"

COMMON_SCRIPT="$CURRENT_DIR/linux_server_security/common.sh"
if [ ! -f "$COMMON_SCRIPT" ]; then
    error_exit "Common script not found at $COMMON_SCRIPT"
fi
source "$COMMON_SCRIPT" || error_exit "Failed to source common script at $COMMON_SCRIPT"

SECURITY_SCRIPT="$CURRENT_DIR/linux_server_security/secure_your_server.sh"
if [ ! -f "$SECURITY_SCRIPT" ]; then
    error_exit "Security script not found at $SECURITY_SCRIPT"
fi

RENEW_SSL_CERT_SH="$CURRENT_DIR/renew_letsencrypt_cert.sh"
RENEW_SSL_SERVICE_NAME="renew-ssl-cert"
RENEW_SSL_SERVICE_FILE="/etc/systemd/system/${RENEW_SSL_SERVICE_NAME}.service"
RENEW_SSL_SERVICE_TIMER_FILE="/etc/systemd/system/${RENEW_SSL_SERVICE_NAME}.timer"
RENEW_SSL_SERVICE_TIMER_CALENDAR="*-*-* 03:00:00"

LOG_FILE="/var/log/install_openfire.log"

OPENFIRE_VERSION="4.9.2"
OPENFIRE_DEBIAN_NAME="openfire_${OPENFIRE_VERSION}_all.deb"
OPENFIRE_SOURCE_BASE_URL="https://www.igniterealtime.org/downloadServlet?filename=openfire"
OPENFIRE_TEMP_DIR="/tmp/openfire_install"
OPENFIRE_KEYSTORE="/usr/share/openfire/resources/security/keystore"
OPENFIRE_CONFIG="/usr/share/openfire/conf/openfire.xml"
TURN_PWD=$(openssl rand -base64 12)
COTURN_CONFIG="/etc/turnserver.conf"
COTURN_DEFAULT="/etc/default/coturn"
COTURN_CERT_DIR="/etc/coturn"

# Ensure log file exists with secure permissions
sudo touch "$LOG_FILE" || error_exit "Failed to create $LOG_FILE"
sudo chmod 600 "$LOG_FILE" || error_exit "Failed to set permissions on $LOG_FILE"
sudo chown root:root "$LOG_FILE" || error_exit "Failed to set ownership on $LOG_FILE"

# --------------------------------------------------
# Functions
# --------------------------------------------------
# Log messages to file and console, and to system logger
log() {
    local level="$1"
    local message="$2"
    echo "$(get_timestamp) [$level] $message" | tee -a "$LOG_FILE"
    logger -t "install_openfire" "[$level] $message"
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

    echo
    printf '%*s\n' "$splitline_length" | tr ' ' '='
    echo "$prompt_message"
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

# Check domain resolution
check_domain() {
    local domain="$1"
    log "INFO" "Checking domain resolution for $domain"
    local ip
    ip=$(nslookup "$domain" | grep 'Address:' | tail -n1 | awk '{print $2}' || echo "")
    if [ -z "$ip" ]; then
        error_exit "Failed to resolve domain $domain"
    fi
    local machine_ip
    machine_ip=$(curl -s ipinfo.io/ip || echo "")
    if [ -z "$machine_ip" ]; then
        error_exit "Failed to retrieve machine IP"
    fi
    if [ "$ip" != "$machine_ip" ]; then
        error_exit "The domain $domain resolves to $ip, but machine IP is $machine_ip"
    fi
    log "INFO" "Domain $domain resolves correctly to $machine_ip"
    echo "$machine_ip"
}

# Run security script
run_security_script() {
    log "INFO" "Running server security script"
    sudo bash "$SECURITY_SCRIPT" || error_exit "Failed to execute security script"
    log "INFO" "Security script completed successfully"
}

# Install certbot and request SSL certificate
setup_ssl() {
    local domain="$1"
    log "INFO" "Installing certbot and requesting SSL certificate for $domain"
    sudo apt update
    sudo apt install certbot -y || error_exit "Failed to install certbot"
    sudo certbot certonly --standalone -d "$domain" --non-interactive --agree-tos --register-unsafely-without-email || error_exit "Failed to obtain SSL certificate"
    sudo systemctl disable certbot.timer || error_exit "Failed to disable default certbot timer" # Certbot's default timer may conflict the custom timer
    log "INFO" "SSL certificate obtained for $domain"
}

# Renew SSL certificate
setup_renew_ssl_cert() {
    log "INFO" "Setting up SSL renewal timer"

    local domain=$1

    if [ ! -f "$RENEW_SSL_CERT_SH" ]; then
        error_exit "Renewal script not found at $RENEW_SSL_CERT_SH"
    fi
    local renew_ssl_sh_basename=$(basename "$RENEW_SSL_CERT_SH")
    local renew_service_script_path="/usr/local/bin/$renew_ssl_sh_basename"

    sudo cp "$RENEW_SSL_CERT_SH" "$renew_service_script_path" \
        || error_exit "Failed to copy $RENEW_SSL_CERT_SH to $renew_service_script_path"

    sudo chmod +x "$renew_service_script_path" \
        || error_exit "Failed to make $renew_service_script_path executable"

    local renew_ssl_service=$(cat << EOF
[Unit]
Description=SSL Certificate Renewal Service
After=network-online.target

[Service]
Type=oneshot
ExecStart=$renew_service_script_path $domain
RemainAfterExit=yes
EOF
)
    echo "$renew_ssl_service" | sudo tee "$RENEW_SSL_SERVICE_FILE" > /dev/null \
        || error_exit "Failed to create $RENEW_SSL_SERVICE_FILE"

    local renew_ssl_timer=$(cat << EOF
[Unit]
Description=Run SSL Certificate Renewal

[Timer]
OnCalendar=$RENEW_SSL_SERVICE_TIMER_CALENDAR
Persistent=true

[Install]
WantedBy=timers.target
EOF
)
    echo "$renew_ssl_timer" | sudo tee "$RENEW_SSL_SERVICE_TIMER_FILE" > /dev/null \
        || error_exit "Failed to create $RENEW_SSL_SERVICE_TIMER_FILE"

    sudo systemctl daemon-reload \
        || error_exit "Failed to reload systemd daemon"
    sudo systemctl enable "${RENEW_SSL_SERVICE_NAME}.timer" \
        || error_exit "Failed to enable ${RENEW_SSL_SERVICE_NAME}.timer"
    sudo systemctl start "${RENEW_SSL_SERVICE_NAME}.timer" \
        || error_exit "Failed to start ${RENEW_SSL_SERVICE_NAME}.timer"
    
    log "INFO" "SSL renewal timer is up"
}

# Install Java
install_java() {
    log "INFO" "Installing Java"
    sudo apt update
    sudo apt install default-jre -y || error_exit "Failed to install default-jre"
    if ! command -v java &>/dev/null; then
        error_exit "Java installation failed or java command not found"
    fi
    log "INFO" "Java installed successfully"
}

# Install Openfire
install_openfire() {
    log "INFO" "Installing Openfire version $OPENFIRE_VERSION"
    
    # Clean up existing /var/lib/openfire directory if it exists
    if [ -d "/var/lib/openfire" ]; then
        log "INFO" "Removing existing /var/lib/openfire directory"
        sudo rm -rf "/var/lib/openfire" || error_exit "Failed to remove existing /var/lib/openfire directory"
    fi

    # Create temporary directory
    mkdir -p "$OPENFIRE_TEMP_DIR" || error_exit "Failed to create $OPENFIRE_TEMP_DIR"
    wget -q "$OPENFIRE_SOURCE_BASE_URL/$OPENFIRE_DEBIAN_NAME" -O "$OPENFIRE_TEMP_DIR/$OPENFIRE_DEBIAN_NAME" || error_exit "Failed to download Openfire package"

    # Install Openfire
    sudo dpkg -i "$OPENFIRE_TEMP_DIR/$OPENFIRE_DEBIAN_NAME" || {
        log "WARNING" "dpkg encountered errors, attempting to fix"
        sudo apt update || error_exit "Failed to update package lists"
        sudo apt install -f -y || error_exit "Failed to resolve dependencies"
    }
    rm -rf "$OPENFIRE_TEMP_DIR" || error_exit "Failed to clean up $OPENFIRE_TEMP_DIR"

    # Ensure correct ownership
    sudo chown -R openfire:openfire /var/lib/openfire || error_exit "Failed to set ownership for /var/lib/openfire"
    sudo chmod -R 750 /var/lib/openfire || error_exit "Failed to set permissions for /var/lib/openfire"

    log "INFO" "Openfire installed successfully"
}

# Configure Openfire
configure_openfire() {
    local domain="$1"
    log "INFO" "Configuring Openfire"

    # Log firewall ports (assuming UFW_ALLOWED_PORTS is defined in security script)
    if [ -n "${UFW_ALLOWED_PORTS+x}" ]; then
        log "INFO" "Openfire firewall configured by security script with ports: $(IFS=','; echo "${UFW_ALLOWED_PORTS[*]}")"
    else
        log "WARNING" "UFW_ALLOWED_PORTS not defined, firewall ports not logged"
    fi

    # Disable port 9090
    log "INFO" "Disabling Openfire port 9090"
    sudo sed -i 's/<port>9090<\/port>/<port>-1<\/port>/' "$OPENFIRE_CONFIG" || error_exit "Failed to disable port 9090"
    if grep -q "<port>9090</port>" "$OPENFIRE_CONFIG"; then
        error_exit "Failed to verify port 9090 disable"
    fi
    log "INFO" "Port 9090 disabled successfully"

    # Update keystore with SSL certificate
    log "INFO" "Updating Openfire keystore with SSL certificate"
    mkdir -p "$OPENFIRE_TEMP_DIR" || error_exit "Failed to create $OPENFIRE_TEMP_DIR"

    local fullchain_pem="$OPENFIRE_TEMP_DIR/fullchain.pem"
    local privkey_pem="$OPENFIRE_TEMP_DIR/privkey.pem"
    local generated_p12="$OPENFIRE_TEMP_DIR/openfire.p12"

    sudo cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$fullchain_pem" \
        || error_exit "Failed to copy fullchain.pem"
    sudo cp "/etc/letsencrypt/live/$domain/privkey.pem" "$privkey_pem" \
        || error_exit "Failed to copy privkey.pem"

    sudo openssl pkcs12 -export \
        -in "$fullchain_pem" -inkey "$privkey_pem" -out "$generated_p12" \
        -name openfire -password pass:changeit || error_exit "Failed to create PKCS12 keystore"

    sudo cp "$OPENFIRE_KEYSTORE" "$OPENFIRE_KEYSTORE.bak" || error_exit "Failed to backup keystore"
    sudo keytool -importkeystore \
        -srckeystore "$generated_p12" -srcstoretype PKCS12 \
        -destkeystore "$OPENFIRE_KEYSTORE" -deststoretype JKS \
        -srcstorepass changeit -deststorepass changeit || error_exit "Failed to import keystore"

    rm -rf "$OPENFIRE_TEMP_DIR" || error_exit "Failed to clean up $OPENFIRE_TEMP_DIR"
    sudo chown openfire:openfire "$OPENFIRE_KEYSTORE" || error_exit "Failed to set keystore ownership"
    sudo chmod 640 "$OPENFIRE_KEYSTORE" || error_exit "Failed to set keystore permissions"
    log "INFO" "Openfire keystore updated successfully"
}

# Start Openfire
start_openfire() {
    log "INFO" "Starting Openfire service"
    sudo systemctl start openfire || error_exit "Failed to start Openfire"
    sudo systemctl enable openfire || error_exit "Failed to enable Openfire"
    if ! systemctl is-active --quiet openfire; then
        error_exit "Openfire service is not running"
    fi
    log "INFO" "Openfire started and enabled successfully"
}

# Install and configure Coturn
setup_coturn() {
    local domain="$1"
    local machine_ip="$2"
    log "INFO" "Installing and configuring Coturn"
    sudo apt update
    sudo apt install coturn -y || error_exit "Failed to install Coturn"
    sudo mkdir -p "$COTURN_CERT_DIR" || error_exit "Failed to create Coturn certificate directory"
    sudo cp "/etc/letsencrypt/live/$domain/fullchain.pem" "$COTURN_CERT_DIR/fullchain.pem" || error_exit "Failed to copy fullchain.pem for Coturn"
    sudo cp "/etc/letsencrypt/live/$domain/privkey.pem" "$COTURN_CERT_DIR/privkey.pem" || error_exit "Failed to copy privkey.pem for Coturn"

    # Configure turnserver.conf
    log "INFO" "Configuring Coturn server"
    sudo tee "$COTURN_CONFIG" > /dev/null <<EOF
listening-port=3478
tls-listening-port=5349
alt-listening-port=3479
alt-tls-listening-port=5350
external-ip=$machine_ip
fingerprint
lt-cred-mech
server-name=$domain
user=openfire:$TURN_PWD
realm=$domain
cert=$COTURN_CERT_DIR/fullchain.pem
pkey=$COTURN_CERT_DIR/privkey.pem
cipher-list="DEFAULT"
log-file=/var/log/turnserver.log
simple-log
verbose
TURNSERVER_ENABLED=1
EOF
    sudo chmod 640 "$COTURN_CONFIG" || error_exit "Failed to set permissions on turnserver.conf"
    sudo chown root:root "$COTURN_CONFIG" || error_exit "Failed to set ownership on turnserver.conf"

    # Enable Coturn in default config
    log "INFO" "Enabling Coturn service"
    sudo sed -i 's/^#TURNSERVER_ENABLED=1/TURNSERVER_ENABLED=1/' "$COTURN_DEFAULT" || error_exit "Failed to enable Coturn in $COTURN_DEFAULT"

    # Add turn admin user
    log "INFO" "Adding Coturn admin user"
    sudo turnadmin -a -u openfire -r "$domain" -p "$TURN_PWD" || error_exit "Failed to add Coturn admin user"

    # Start Coturn
    sudo systemctl start coturn || error_exit "Failed to start Coturn"
    sudo systemctl enable coturn || error_exit "Failed to enable Coturn"
    if ! systemctl is-active --quiet coturn; then
        error_exit "Coturn service is not running"
    fi
    log "INFO" "Coturn configured and started successfully"
}

# Display final instructions
display_instructions() {
    local domain="$1"
    local prompt_message=$(cat << EOF
* Openfire and Coturn are running.
* You need to configure the Openfire admin console.
* Please visit: https://$domain:9091
* 
* The Coturn server credentials are (see $COTURN_CONFIG):
* - username=openfire
* - password=$TURN_PWD
* 
* Do you want to save these informations in current folder($CURRENT_DIR)? (Yn)
EOF
)
    local log_message="Prompting user instructions"

    if confirm "$prompt_message" "$log_message"; then
        local info_file="$CURRENT_DIR/openfire_info.txt"
        log "INFO" "Saving informations to $info_file"
        echo "$prompt_message" | sudo tee "$info_file" > /dev/null || error_exit "Failed to save openfire_info.txt"
        log "INFO" "Informations saved to $info_file successfully"
    fi
    log "INFO" "Installation and configuration completed"
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
    local domain="$1"
    check_permission
    local machine_ip=$(check_domain "$domain")
    run_security_script
    echo "$ARTS_TITLE"
    setup_ssl "$domain"
    setup_renew_ssl_cert "$domain"
    install_java
    install_openfire
    configure_openfire "$domain"
    setup_coturn "$domain" "$machine_ip"
    display_instructions "$domain"
    prompt_reboot
}

# --------------------------------------------------
# Main
# --------------------------------------------------
if [ $# -eq 0 ]; then
    log "ERROR" "No domain provided. Usage: $(basename "$0") your_domain"
    echo "Usage: $(basename "$0") your_domain"
    exit 1
fi
main "$1"