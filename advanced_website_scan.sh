#!/bin/bash

# Define the target website
TARGET=$1
OUTPUT_FORMAT=$2

if [ -z "$TARGET" ]; then
  echo "Usage: $0 <website> [json|text]"
  exit 1
fi

# Default output format
if [ -z "$OUTPUT_FORMAT" ]; then
  OUTPUT_FORMAT="json"
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

# Function to log info in both JSON and plain text format
write_output() {
  local text_output="$1"
  local json_output="$2"
  local filename="$3"

  if [[ "$OUTPUT_FORMAT" == "json" ]]; then
    echo "$json_output" | jq '.' > "$OUTPUT_DIR/$filename.json"
  else
    echo "$text_output" > "$OUTPUT_DIR/$filename.txt"
  fi
}

echo "----- Starting Website Information Gathering -----"
echo "Target Domain: $TARGET"
START_TIME=$(date)
echo "Start Time: $START_TIME"

# Basic domain information
echo "----- Collecting Basic Information -----"
BASIC_INFO=$(ping -c 1 $TARGET | awk '/PING/ {print "IP Address: " $3}')
DNS_INFO=$(dig $TARGET ANY +noall +answer | awk '{print "DNS Record:", $1, $4, $5}')
basic_text_output="$BASIC_INFO\n$DNS_INFO"
basic_json_output="{\"domain\":\"$TARGET\",\"ip\":\"$(echo $BASIC_INFO | awk '{print $3}')\",\"dns\":[$(echo $DNS_INFO | jq -R . | jq -s .)]}"
write_output "$basic_text_output" "$basic_json_output" "basic_info"

# Traceroute
echo "----- Running Traceroute -----"
TRACEROUTE=$(traceroute -n $TARGET)
write_output "$TRACEROUTE" "{\"traceroute\":[$(echo "$TRACEROUTE" | jq -R . | jq -s .)]}" "traceroute"

# Nmap scan (open ports and services)
echo "----- Nmap Scan -----"
NMAP_SCAN=$(nmap -sV $TARGET)
NMAP_OPEN_PORTS=$(echo "$NMAP_SCAN" | awk '/open/ {print "Port:", $1, "Service:", $3}')
write_output "$NMAP_OPEN_PORTS" "{\"open_ports\":[$(echo "$NMAP_OPEN_PORTS" | jq -R . | jq -s .)]}" "nmap_scan"

# MTR network diagnostic (packet loss and latency)
echo "----- MTR Network Diagnostic -----"
MTR_REPORT=$(mtr -r $TARGET)
write_output "$MTR_REPORT" "{\"mtr_report\":[$(echo "$MTR_REPORT" | jq -R . | jq -s .)]}" "mtr_report"

# Netstat (active connections, protocols)
echo "----- Gathering Netstat Information -----"
NETSTAT_INFO=$(netstat -tunlp | awk 'NR==1 || /tcp|udp/')
write_output "$NETSTAT_INFO" "{\"netstat\":[$(echo "$NETSTAT_INFO" | jq -R . | jq -s .)]}" "netstat_info"

# Get HTTP headers and identify protocol version (HTTP/1.1, HTTP/2, HTTP/3)
echo "----- Fetching HTTP Headers -----"
HTTP_HEADERS=$(curl -s -I $TARGET)
HTTP_PROTOCOL=$(echo "$HTTP_HEADERS" | awk '/HTTP/ {print $1}')
header_text_output="HTTP Protocol: $HTTP_PROTOCOL\n$HTTP_HEADERS"
header_json_output="{\"http_protocol\":\"$HTTP_PROTOCOL\",\"http_headers\":[$(echo "$HTTP_HEADERS" | jq -R . | jq -s .)]}"
write_output "$header_text_output" "$header_json_output" "http_headers"

# SSL/TLS scan and extended certificate details using openssl (if https available)
if echo $TARGET | grep -q "^https"; then
  echo "----- SSL/TLS Certificate Information -----"
  SSL_CERT=$(echo | openssl s_client -connect $TARGET:443 2>/dev/null | openssl x509 -noout -text)
  SSL_ISSUER=$(echo "$SSL_CERT" | grep "Issuer:" | sed 's/Issuer://g')
  SSL_SUBJECT=$(echo "$SSL_CERT" | grep "Subject:" | sed 's/Subject://g')
  SSL_VALIDITY=$(echo "$SSL_CERT" | grep -A 2 "Validity" | awk 'NR==2')
  ssl_text_output="SSL Certificate Issuer: $SSL_ISSUER\nSSL Subject: $SSL_SUBJECT\nSSL Validity: $SSL_VALIDITY\n$SSL_CERT"
  ssl_json_output="{\"issuer\":\"$SSL_ISSUER\",\"subject\":\"$SSL_SUBJECT\",\"validity\":\"$SSL_VALIDITY\",\"ssl_details\":[$(echo "$SSL_CERT" | jq -R . | jq -s .)]}"
  write_output "$ssl_text_output" "$ssl_json_output" "ssl_info"
fi

# Process Monitoring (web-related processes)
echo "----- Process Monitoring (Web Servers, Databases) -----"
PROCESS_INFO=$(ps aux | awk '/nginx|apache|httpd|mysql/ {print "Process:", $11, "PID:", $2, "Memory Usage:", $4, "CPU Usage:", $3}')
write_output "$PROCESS_INFO" "{\"process_info\":[$(echo "$PROCESS_INFO" | jq -R . | jq -s .)]}" "process_info"

# System Information (CPU and memory usage)
echo "----- System Resource Usage -----"
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{print "CPU Usage: " $2 + $4 "%"}')
MEM_USAGE=$(free -h | awk '/Mem/ {print "Memory Usage: " $3 "/" $2}')
sys_text_output="$CPU_USAGE\n$MEM_USAGE"
sys_json_output="{\"cpu_usage\":\"$CPU_USAGE\",\"memory_usage\":\"$MEM_USAGE\"}"
write_output "$sys_text_output" "$sys_json_output" "system_info"

# Log all actions and summary
echo "----- End of Script -----"
END_TIME=$(date)
echo "End Time: $END_TIME"
echo "Logs stored in $LOG_FILE"
