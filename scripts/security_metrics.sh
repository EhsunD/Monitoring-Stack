#!/bin/bash
# Consolidated Security Monitoring Script with Detailed Outputs

# Set output directory
OUTPUT_DIR="/opt/node_exporter/metrics"

# 1. Open Ports Monitoring using `ss` - list open ports individually
function monitor_open_ports {
    OUTPUT="$OUTPUT_DIR/open_ports.prom"
    echo "# HELP open_ports Open ports on the server" > $OUTPUT
    echo "# TYPE open_ports gauge" >> $OUTPUT
    ss -tuln | awk 'NR>1 {print $5}' | awk -F':' '{print $NF}' | sort | uniq | while read -r port; do
        echo "open_ports{port=\"$port\"} 1" >> $OUTPUT
    done
}

# 2. Last 10 Failed Authentication Attempts - with username and number of attempts
function monitor_auth_failures {
    OUTPUT="$OUTPUT_DIR/auth_failures.prom"
    echo "# HELP auth_failures Last 10 failed SSH login attempts by user" > $OUTPUT
    echo "# TYPE auth_failures counter" >> $OUTPUT
    grep "Failed password" /var/log/auth.log | awk '{print $(NF-5)}' | sort | uniq -c | sort -nr | head -10 | while read -r count user; do
        echo "auth_failures{user=\"$user\"} $count" >> $OUTPUT
    done
}

# 3. Sudoers Users Monitoring - list usernames with sudo privileges
function monitor_sudoers_users {
    OUTPUT="$OUTPUT_DIR/sudoers_users.prom"
    echo "# HELP sudoers_users Users with sudo privileges" > $OUTPUT
    echo "# TYPE sudoers_users gauge" >> $OUTPUT
    grep -E '^[^#].*ALL=\(ALL:ALL\).*ALL' /etc/sudoers | awk '{print $1}' | while read -r user; do
        echo "sudoers_users{user=\"$user\"} 1" >> $OUTPUT
    done
}

# 4. File Integrity Monitoring (FIM) - log directory and file path of changes
function monitor_file_integrity {
    OUTPUT="$OUTPUT_DIR/file_integrity.prom"
    WATCH_DIR="/etc"
    echo "# HELP file_integrity_changes File integrity monitoring for $WATCH_DIR" > $OUTPUT
    echo "# TYPE file_integrity_changes gauge" >> $OUTPUT
    find $WATCH_DIR -type f | while read -r file; do
        checksum=$(md5sum "$file" | awk '{print $1}')
        echo "file_integrity_changes{file=\"$file\"} \"$checksum\"" >> $OUTPUT
    done
}

# 5. SSL/TLS Certificate Expiry Monitoring - add domain name and expiry date
function monitor_certificate_expiry {
    OUTPUT="$OUTPUT_DIR/certificate_expiry.prom"
    DOMAIN="example.com"
    expiry_date=$(echo | openssl s_client -connect "$DOMAIN:443" 2>/dev/null | openssl x509 -noout -enddate | cut -d= -f2)
    expiry_seconds=$(date -d "$expiry_date" +%s)
    current_seconds=$(date +%s)
    days_left=$(( (expiry_seconds - current_seconds) / 86400 ))
    echo "# HELP certificate_days_left Days until SSL/TLS certificate expires for $DOMAIN" > $OUTPUT
    echo "# TYPE certificate_days_left gauge" >> $OUTPUT
    echo "certificate_days_left{domain=\"$DOMAIN\",expiry_date=\"$expiry_date\"} $days_left" >> $OUTPUT
}

# 6. Unauthorized Access Attempt Detection - with request details and username if available
function monitor_unauthorized_access {
    OUTPUT="$OUTPUT_DIR/unauthorized_access.prom"
    echo "# HELP unauthorized_access_attempts Unauthorized access attempts by user" > $OUTPUT
    echo "# TYPE unauthorized_access_attempts counter" >> $OUTPUT
    grep "unauthorized" /var/log/auth.log | awk '{print $(NF-1)}' | sort | uniq -c | while read -r count user; do
        echo "unauthorized_access_attempts{user=\"$user\"} $count" >> $OUTPUT
    done
}

# 7. Endpoint and API Monitoring for DDoS Detection - with API name and count of requests
function monitor_ddos_detection {
    OUTPUT="$OUTPUT_DIR/ddos_detection.prom"
    LOG_PATH="/var/log/nginx/access.log"
    echo "# HELP ddos_detection_request_count HTTP requests per minute per API endpoint" > $OUTPUT
    echo "# TYPE ddos_detection_request_count gauge" >> $OUTPUT
    tail -n 1000 $LOG_PATH | grep "$(date +"[%d/%b/%Y:%H:%M")" | awk '{print $7, $1}' | sort | uniq -c | while read -r count endpoint user; do
        echo "ddos_detection_request_count{endpoint=\"$endpoint\",user=\"$user\"} $count" >> $OUTPUT
    done
}

# 8. User Account Creation and Privilege Escalation Detection - list new user creations and sudo attempts
function monitor_user_privileges {
    OUTPUT="$OUTPUT_DIR/user_privilege_monitoring.prom"
    new_users=$(grep "useradd" /var/log/auth.log | wc -l)
    sudo_attempts=$(grep "sudo:" /var/log/auth.log | grep "TTY=" | awk '{print $(NF-5)}' | sort | uniq -c | while read -r count user; do
        echo "# HELP new_user_creations Count of new user account creations" > $OUTPUT
        echo "# TYPE new_user_creations counter" >> $OUTPUT
        echo "new_user_creations $new_users" >> $OUTPUT
        echo "# HELP sudo_privilege_escalations Count of sudo privilege escalation attempts" >> $OUTPUT
        echo "# TYPE sudo_privilege_escalations counter" >> $OUTPUT
        echo "sudo_privilege_escalations{user=\"$user\"} $count" >> $OUTPUT
    done
}

# Execute all monitoring functions
monitor_open_ports
monitor_auth_failures
monitor_sudoers_users
monitor_file_integrity
monitor_certificate_expiry
monitor_unauthorized_access
monitor_ddos_detection
monitor_user_privileges
