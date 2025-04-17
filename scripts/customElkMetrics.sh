#!/bin/bash
# Security Monitoring Script - Sends logs to Logstash

LOGSTASH_URL="http://localhost:8080"  # Change if Logstash runs on a different host

# Function to send JSON data to Logstash
send_to_logstash() {
    local json_data="$1"
    curl -XPOST "$LOGSTASH_URL" \
         -H "Content-Type: application/json" \
         -d "$json_data"
}

# 0. Online Users
function online_users {
    ONLINE_USERS=$(who | awk '{print $1}' | sort | uniq)
    for user in $ONLINE_USERS; do
        send_to_logstash "{\"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\", \"metric\": \"online_users\", \"username\": \"$user\", \"value\": 1}"
    done
}

# 1. Open Ports Monitoring
function monitor_open_ports {
    ss -tuln | awk 'NR>1 && $5 ~ /^0.0.0.0:/ {print $5}' | awk -F':' '{print $NF}' | sort | uniq | while read -r port; do
        send_to_logstash "{\"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\", \"metric\": \"open_ports\", \"port\": \"$port\", \"value\": 1}"
    done
}

# 2. Failed Authentication Attempts
function monitor_auth_failures {
    grep "Failed password" /var/log/auth.log | awk '{print $(NF-5)}' | sort | uniq -c | while read -r count user; do
        send_to_logstash "{\"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\", \"metric\": \"auth_failures\", \"username\": \"$user\", \"failed_attempts\": $count}"
    done
}

# 3. Sudoers Users
function monitor_sudoers_users {
    sudo_groups=$(sudo grep -E '^%.*ALL=\(ALL:ALL\).*ALL' /etc/sudoers | sed -E 's/^(%[^ ]+(\s+[^ ]+)*)\s+ALL=\(ALL:ALL\).*$/\1/')
    sudo_groups=$(echo "$sudo_groups" | sed 's/\\//g') 

    sudoers_users=$(grep -E '^[^#].*ALL=\(ALL:ALL\).*ALL' /etc/sudoers | awk '{print $1}')
    
    for user in $sudoers_users; do
        send_to_logstash "{\"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\", \"metric\": \"sudo_users\", \"username\": \"$user\", \"value\": 1}"
    done

    while IFS= read -r line; do
        group=$(echo "$line" | sed -E 's/^%([^ ]+(\s+[^ ]+)*)\s+ALL=\(ALL:ALL\).*$/\1/')
        getnet_group=$(echo "$group" | sed 's/^%//; s/\\//g')
        group_members=$(getent group "$getnet_group" | awk -F: '{print $4}' | tr ',' '\n')

        for member in $group_members; do
            send_to_logstash "{\"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\", \"metric\": \"sudo_users\", \"group\": \"%$group\", \"username\": \"$member\", \"value\": 1}"
        done
    done <<< "$sudo_groups"
}

# 4. File Integrity Monitoring (FIM)
function monitor_file_changing {
    WATCH_DIR="/home/os-admin1"
    HASH_LIST_FILE="/tmp/directory_file_hashes.txt"

    if [ ! -f "$HASH_LIST_FILE" ]; then
        find "$WATCH_DIR" -type f -exec md5sum {} + > "$HASH_LIST_FILE"
    fi

    CURRENT_HASH_FILE=$(find "$WATCH_DIR" -type f -exec md5sum {} +)
    echo "$CURRENT_HASH_FILE" > /tmp/current_hash_file.txt

    NEW_FILES=$(comm -13 <(awk '{print $2}' "$HASH_LIST_FILE" | sort) <(awk '{print $2}' /tmp/current_hash_file.txt | sort))
    DELETE_FILES=$(comm -13 <(awk '{print $2}' /tmp/current_hash_file.txt | sort) <(awk '{print $2}' "$HASH_LIST_FILE" | sort))

    while read -r OLD_LINE; do
        OLD_HASH=$(echo "$OLD_LINE" | awk '{print $1}')
        OLD_FILE=$(echo "$OLD_LINE" | awk '{print $2}')
        NEW_HASH=$(grep "$OLD_FILE" /tmp/current_hash_file.txt | awk '{print $1}')

        if [[ -n "$NEW_HASH" && "$OLD_HASH" != "$NEW_HASH" ]]; then
            send_to_logstash "{\"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\", \"metric\": \"file_change\", \"file\": \"$OLD_FILE\", \"action\": \"modified\"}"
        fi
    done < "$HASH_LIST_FILE"

    for FILE in $NEW_FILES; do
        send_to_logstash "{\"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\", \"metric\": \"file_change\", \"file\": \"$FILE\", \"action\": \"created\"}"
    done

    for FILE in $DELETE_FILES; do
        send_to_logstash "{\"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\", \"metric\": \"file_change\", \"file\": \"$FILE\", \"action\": \"deleted\"}"
    done

    mv /tmp/current_hash_file.txt "$HASH_LIST_FILE"
}

# 5. Unauthorized Access Attempts
function monitor_unauthorized_access {
    grep "unauthorized" /var/log/auth.log | awk '{print $(NF-1)}' | sort | uniq -c | while read -r count user; do
        send_to_logstash "{\"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\", \"metric\": \"unauthorized_access\", \"username\": \"$user\", \"count\": $count}"
    done
}

# 6. User Authentication Activities
function user_authentication_activities {
    grep -E "sshd.*(Failed|Accepted) password for" /var/log/auth.log | tail -n 10 | while IFS= read -r line; do
        if [[ "$line" =~ "Accepted password for" ]]; then
            STATUS="success"
        elif [[ "$line" =~ "Failed password for" ]]; then
            STATUS="failed"
        fi
        USER=$(echo "$line" | awk '{print $(NF-5)}')
        send_to_logstash "{\"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\", \"metric\": \"auth_activity\", \"username\": \"$USER\", \"status\": \"$STATUS\"}"
    done
}

# 7. Linux Users with Shell
function linux_users {
    awk -F: '($7 !~ /nologin|false/){print $1, $7}' /etc/passwd | while read -r user shell; do
        send_to_logstash "{\"timestamp\": \"$(date -u +"%Y-%m-%dT%H:%M:%SZ")\", \"metric\": \"linux_users\", \"username\": \"$user\", \"shell\": \"$shell\"}"
    done
}

# Execute all functions
online_users
monitor_open_ports
monitor_auth_failures
monitor_sudoers_users
monitor_file_changing
monitor_unauthorized_access
user_authentication_activities
linux_users
