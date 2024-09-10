#!/bin/bash

# Define the target website
TARGET=$1
OUTPUT_FORMAT=$2
VERBOSE=$3

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <website> [json|text] [verbose|quiet]"
  exit 1
fi

# Default output format
if [ -z "$OUTPUT_FORMAT" ]; then
  OUTPUT_FORMAT="json"
fi

# Set logging level (verbose/quiet)
if [ -z "$VERBOSE" ]; then
  VERBOSE="quiet"
fi

# Check if user has necessary privileges for certain commands
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run as root (for nmap, netstat, and ps)."
  exit 1
fi

# Create a directory for results
OUTPUT_DIR="scan_results"
mkdir -p $OUTPUT_DIR
LOG_FILE="$OUTPUT_DIR/scan_log.txt"
exec > >(tee -a "$LOG_FILE") 2>&1

# Color functions for enhanced terminal readability
log_info() {
  echo -e "\033[1;32m[INFO]\033[0m $1"
}

log_warn() {
  echo -e "\033[1;33m[WARN]\033[0m $1"
}

log_error() {
  echo -e "\033[1;31m[ERROR]\033[0m $1"
}

# Function to log output based on format
write_output() {
  local text_output="$1"
  local json_output="$2"
  local filename="$3"

  if [[ "$OUTPUT_FORMAT" == "json" ]]; then
    echo "$json_output" | jq '.' > "$OUTPUT_DIR/$filename.json" 2>/dev/null
    if ! jq -e . > /dev/null 2>&1 <<<"$json_output"; then
      log_warn "Invalid JSON output for $filename. Saved as text."
      echo "$text_output" > "$OUTPUT_DIR/$filename.txt"
    fi
  else
    echo "$text_output" > "$OUTPUT_DIR/$filename.txt"
  fi
}

# Function to handle execution errors
check_command_status() {
  if [ $? -ne 0 ]; then
    log_error "$1 command failed. Skipping..."
  else
    log_info "$1 completed successfully."
  fi
}

log_info "----- Starting Website Information Gathering -----"
log_info "Target Domain: $TARGET"
START_TIME=$(date)
log_info "Start Time: $START_TIME"

# Basic domain information
log_info "----- Collecting Basic Information -----"
BASIC_INFO=$(ping -c 1 $TARGET 2>/dev/null | awk '/PING/ {print "IP Address: " $3}')
DNS_INFO=$(dig $TARGET ANY +noall +answer 2>/dev/null | awk '{print "DNS Record:", $1, $4, $5}')
basic_text_output="$BASIC_INFO\n$DNS_INFO"
basic_json_output="{\"domain\":\"$TARGET\",\"ip\":\"$(echo $BASIC_INFO | awk '{print $3}')\",\"dns\":[$(echo $DNS_INFO | jq -R . | jq -s .)]}"
write_output "$basic_text_output" "$basic_json_output" "basic_info"
check_command_status "Basic Information"

# Traceroute (running in the background for parallel execution)
log_info "----- Running Traceroute -----"
(traceroute -n $TARGET 2>/dev/null | tee /tmp/traceroute.log) &
write_output "$(cat /tmp/traceroute.log)" "{\"traceroute\":[$(cat /tmp/traceroute.log | jq -R . | jq -s .)]}" "traceroute"
check_command_status "Traceroute"

# Nmap scan (open ports and services)
log_info "----- Nmap Scan -----"
NMAP_SCAN=$(nmap -sV $TARGET 2>/dev/null)
NMAP_OPEN_PORTS=$(echo "$NMAP_SCAN" | awk '/open/ {print "Port:", $1, "Service:", $3}')
write_output "$NMAP_OPEN_PORTS" "{\"open_ports\":[$(echo "$NMAP_OPEN_PORTS" | jq -R . | jq -s .)]}" "nmap_scan"
check_command_status "Nmap Scan"

# MTR network diagnostic
log_info "----- MTR Network Diagnostic -----"
(mtr -r $TARGET 2>/dev/null | tee /tmp/mtr_report.log) &
write_output "$(cat /tmp/mtr_report.log)" "{\"mtr_report\":[$(cat /tmp/mtr_report.log | jq -R . | jq -s .)]}" "mtr_report"
check_command_status "MTR Network Diagnostic"

# Netstat (active connections, protocols)
log_info "----- Gathering Netstat Information -----"
NETSTAT_INFO=$(netstat -tunlp 2>/dev/null | awk 'NR==1 || /tcp|udp/')
write_output "$NETSTAT_INFO" "{\"netstat\":[$(echo "$NETSTAT_INFO" | jq -R . | jq -s .)]}" "netstat_info"
check_command_status "Netstat Information"

# Get HTTP headers and identify protocol version (HTTP/1.1, HTTP/2, HTTP/3)
log_info "----- Fetching HTTP Headers -----"
HTTP_HEADERS=$(curl -s -I $TARGET 2>/dev/null)
HTTP_PROTOCOL=$(echo "$HTTP_HEADERS" | awk '/HTTP/ {print $1}')
header_text_output="HTTP Protocol: $HTTP_PROTOCOL\n$HTTP_HEADERS"
header_json_output="{\"http_protocol\":\"$HTTP_PROTOCOL\",\"http_headers\":[$(echo "$HTTP_HEADERS" | jq -R . | jq -s .)]}"
write_output "$header_text_output" "$header_json_output" "http_headers"
check_command_status "HTTP Headers"

# SSL/TLS scan if HTTPS is available
if echo $TARGET | grep -q "^https"; then
  log_info "----- SSL/TLS Certificate Information -----"
  SSL_CERT=$(echo | openssl s_client -connect $TARGET:443 2>/dev/null | openssl x509 -noout -text)
  SSL_ISSUER=$(echo "$SSL_CERT" | grep "Issuer:" | sed 's/Issuer://g')
  SSL_SUBJECT=$(echo "$SSL_CERT" | grep "Subject:" | sed 's/Subject://g')
  SSL_VALIDITY=$(echo "$SSL_CERT" | grep -A 2 "Validity" | awk 'NR==2')
  ssl_text_output="SSL Certificate Issuer: $SSL_ISSUER\nSSL Subject: $SSL_SUBJECT\nSSL Validity: $SSL_VALIDITY\n$SSL_CERT"
  ssl_json_output="{\"issuer\":\"$SSL_ISSUER\",\"subject\":\"$SSL_SUBJECT\",\"validity\":\"$SSL_VALIDITY\",\"ssl_details\":[$(echo "$SSL_CERT" | jq -R . | jq -s .)]}"
  write_output "$ssl_text_output" "$ssl_json_output" "ssl_info"
  check_command_status "SSL/TLS Scan"
fi

# Process Monitoring (web-related processes)
log_info "----- Process Monitoring (Web Servers, Databases) -----"
PROCESS_INFO=$(ps aux 2>/dev/null | awk '/nginx|apache|httpd|mysql/ {print "Process:", $11, "PID:", $2, "Memory Usage:", $4, "CPU Usage:", $3}')
write_output "$PROCESS_INFO" "{\"process_info\":[$(echo "$PROCESS_INFO" | jq -R . | jq -s .)]}" "process_info"
check_command_status "Process Monitoring"

# System Information (CPU and memory usage)
log_info "----- System Resource Usage -----"
CPU_USAGE=$(top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{print "CPU Usage: " $2 + $4 "%"}')
MEM_USAGE=$(free -h 2>/dev/null | awk '/Mem/ {print "Memory Usage: " $3 "/" $2}')
sys_text_output="$CPU_USAGE\n$MEM_USAGE"
sys_json_output="{\"cpu_usage\":\"$CPU_USAGE\",\"memory_usage\":\"$MEM_USAGE\"}"
write_output "$sys_text_output" "$sys_json_output" "system_info"
check_command_status "System Resource Usage"

# Log all actions and summary
log_info "----- End of Script -----"
END_TIME=$(date)
log_info "End Time: $END_TIME"
log_info "Logs stored in $LOG_FILE"

# Wait for background processes to finish
wait
