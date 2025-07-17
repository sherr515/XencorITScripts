#!/bin/bash

# =============================================================================
# System Monitoring Script
# =============================================================================
# Purpose: Comprehensive system monitoring and health checking
# Author: System Administrator
# Version: 1.0.0
# Date: $(date +%Y-%m-%d)
# =============================================================================

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_NAME="system-monitor.sh"
VERSION="1.0.0"
CONFIG_FILE="/etc/system-monitor.conf"
LOG_FILE="/var/log/system-monitor.log"
ALERT_FILE="/var/log/system-alerts.log"
INTERVAL=60
DURATION=3600
CPU_THRESHOLD=80
MEMORY_THRESHOLD=85
DISK_THRESHOLD=90
LOAD_THRESHOLD=5.0

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} $message"
            ;;
        "WARNING")
            echo -e "${YELLOW}[WARNING]${NC} $message"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            ;;
        "ALERT")
            echo -e "${RED}[ALERT]${NC} $message"
            ;;
        "HEADER")
            echo -e "${PURPLE}=== $message ===${NC}"
            ;;
    esac
}

# Function to log messages
log_message() {
    local level=$1
    local message=$2
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" >> "$LOG_FILE"
}

# Function to log alerts
log_alert() {
    local message=$1
    echo "$(date '+%Y-%m-%d %H:%M:%S') [ALERT] $message" >> "$ALERT_FILE"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to display script header
show_header() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                  System Monitoring Script                    ║"
    echo "║                        Version $VERSION                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to display help
show_help() {
    echo "Usage: $SCRIPT_NAME [OPTIONS] [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  monitor [DURATION]           Start continuous monitoring"
    echo "  status                       Show current system status"
    echo "  cpu                          Monitor CPU usage"
    echo "  memory                       Monitor memory usage"
    echo "  disk                         Monitor disk usage"
    echo "  network                      Monitor network usage"
    echo "  processes                    Monitor process activity"
    echo "  services                     Monitor service status"
    echo "  alerts                       Show recent alerts"
    echo "  report                       Generate monitoring report"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -v, --version       Show version information"
    echo "  -c, --config FILE   Use specified config file"
    echo "  -l, --log FILE      Use specified log file"
    echo "  -i, --interval N    Set monitoring interval in seconds (default: $INTERVAL)"
    echo "  -t, --threshold N   Set alert threshold percentage (default: $CPU_THRESHOLD)"
    echo "  -q, --quiet         Suppress verbose output"
    echo "  -d, --daemon        Run in daemon mode"
    echo ""
    echo "Examples:"
    echo "  $SCRIPT_NAME monitor 3600        # Monitor for 1 hour"
    echo "  $SCRIPT_NAME status               # Show current status"
    echo "  $SCRIPT_NAME cpu -t 90           # Monitor CPU with 90% threshold"
    echo "  $SCRIPT_NAME alerts               # Show recent alerts"
}

# Function to get CPU usage
get_cpu_usage() {
    if command_exists top; then
        top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//'
    elif command_exists vmstat; then
        vmstat 1 2 | tail -1 | awk '{print 100-$15}'
    elif command_exists cat; then
        # Read from /proc/loadavg and /proc/stat
        local load=$(cat /proc/loadavg | awk '{print $1}')
        echo "Load average: $load"
    else
        echo "CPU monitoring tools not available"
        return 1
    fi
}

# Function to get memory usage
get_memory_usage() {
    if command_exists free; then
        local total=$(free | grep Mem | awk '{print $2}')
        local used=$(free | grep Mem | awk '{print $3}')
        local usage=$((used * 100 / total))
        echo "$usage"
    elif command_exists cat; then
        # Read from /proc/meminfo
        local total=$(grep MemTotal /proc/meminfo | awk '{print $2}')
        local available=$(grep MemAvailable /proc/meminfo | awk '{print $2}')
        local used=$((total - available))
        local usage=$((used * 100 / total))
        echo "$usage"
    else
        echo "Memory monitoring tools not available"
        return 1
    fi
}

# Function to get disk usage
get_disk_usage() {
    if command_exists df; then
        df -h | grep -E '^/dev/' | while read device size used avail use_percent mount; do
            local usage=$(echo $use_percent | sed 's/%//')
            echo "$mount:$usage"
        done
    else
        echo "Disk monitoring tools not available"
        return 1
    fi
}

# Function to get network usage
get_network_usage() {
    if command_exists cat; then
        # Read from /proc/net/dev
        cat /proc/net/dev | grep -E '^(eth|en|wl|wlan)' | while read interface bytes_recv packets_recv errs_recv drop_recv fifo_recv frame_recv compressed_recv multicast_recv bytes_sent packets_sent errs_sent drop_sent fifo_sent colls_sent carrier_sent compressed_sent; do
            echo "$interface:$bytes_recv:$bytes_sent"
        done
    else
        echo "Network monitoring tools not available"
        return 1
    fi
}

# Function to get load average
get_load_average() {
    if command_exists cat; then
        cat /proc/loadavg | awk '{print $1, $2, $3}'
    elif command_exists uptime; then
        uptime | awk -F'load average:' '{print $2}' | sed 's/,//g'
    else
        echo "Load average not available"
        return 1
    fi
}

# Function to monitor CPU
monitor_cpu() {
    print_status "HEADER" "CPU Monitoring"
    
    local cpu_usage=$(get_cpu_usage)
    if [[ -n "$cpu_usage" && "$cpu_usage" =~ ^[0-9]+$ ]]; then
        echo "Current CPU Usage: ${cpu_usage}%"
        
        if [[ $cpu_usage -gt $CPU_THRESHOLD ]]; then
            print_status "ALERT" "CPU usage is high: ${cpu_usage}%"
            log_alert "CPU usage threshold exceeded: ${cpu_usage}%"
        else
            print_status "SUCCESS" "CPU usage is normal: ${cpu_usage}%"
        fi
        
        # Show top processes by CPU
        echo ""
        echo "Top CPU Processes:"
        if command_exists ps; then
            ps aux --sort=-%cpu | head -6
        fi
    else
        print_status "ERROR" "Could not get CPU usage"
    fi
}

# Function to monitor memory
monitor_memory() {
    print_status "HEADER" "Memory Monitoring"
    
    local memory_usage=$(get_memory_usage)
    if [[ -n "$memory_usage" && "$memory_usage" =~ ^[0-9]+$ ]]; then
        echo "Current Memory Usage: ${memory_usage}%"
        
        if [[ $memory_usage -gt $MEMORY_THRESHOLD ]]; then
            print_status "ALERT" "Memory usage is high: ${memory_usage}%"
            log_alert "Memory usage threshold exceeded: ${memory_usage}%"
        else
            print_status "SUCCESS" "Memory usage is normal: ${memory_usage}%"
        fi
        
        # Show memory details
        echo ""
        echo "Memory Details:"
        if command_exists free; then
            free -h
        fi
        
        # Show top processes by memory
        echo ""
        echo "Top Memory Processes:"
        if command_exists ps; then
            ps aux --sort=-%mem | head -6
        fi
    else
        print_status "ERROR" "Could not get memory usage"
    fi
}

# Function to monitor disk
monitor_disk() {
    print_status "HEADER" "Disk Monitoring"
    
    local disk_usage=$(get_disk_usage)
    if [[ -n "$disk_usage" ]]; then
        echo "Disk Usage:"
        echo "$disk_usage" | while IFS=':' read -r mount usage; do
            echo "  $mount: ${usage}%"
            
            if [[ $usage -gt $DISK_THRESHOLD ]]; then
                print_status "ALERT" "Disk usage is high on $mount: ${usage}%"
                log_alert "Disk usage threshold exceeded on $mount: ${usage}%"
            fi
        done
        
        # Show disk details
        echo ""
        echo "Disk Details:"
        if command_exists df; then
            df -h
        fi
        
        # Show disk I/O
        echo ""
        echo "Disk I/O Statistics:"
        if command_exists iostat; then
            iostat -x 1 1 2>/dev/null || echo "iostat not available"
        fi
    else
        print_status "ERROR" "Could not get disk usage"
    fi
}

# Function to monitor network
monitor_network() {
    print_status "HEADER" "Network Monitoring"
    
    local network_usage=$(get_network_usage)
    if [[ -n "$network_usage" ]]; then
        echo "Network Usage:"
        echo "$network_usage" | while IFS=':' read -r interface bytes_recv bytes_sent; do
            local recv_mb=$((bytes_recv / 1024 / 1024))
            local sent_mb=$((bytes_sent / 1024 / 1024))
            echo "  $interface: RX ${recv_mb}MB, TX ${sent_mb}MB"
        done
        
        # Show network connections
        echo ""
        echo "Network Connections:"
        if command_exists ss; then
            ss -tuln | head -10
        elif command_exists netstat; then
            netstat -tuln | head -10
        fi
        
        # Show network interface status
        echo ""
        echo "Network Interfaces:"
        if command_exists ip; then
            ip addr show | grep -E "inet|UP|DOWN" | head -10
        elif command_exists ifconfig; then
            ifconfig | head -10
        fi
    else
        print_status "ERROR" "Could not get network usage"
    fi
}

# Function to monitor processes
monitor_processes() {
    print_status "HEADER" "Process Monitoring"
    
    echo "Process Statistics:"
    if command_exists ps; then
        local total_processes=$(ps aux | wc -l)
        local running_processes=$(ps aux | grep -v "ps aux" | grep -v "grep" | wc -l)
        echo "  Total Processes: $total_processes"
        echo "  Running Processes: $running_processes"
        
        # Show process tree
        echo ""
        echo "Process Tree (top level):"
        ps -eo pid,ppid,cmd --forest | head -10
        
        # Show zombie processes
        echo ""
        echo "Zombie Processes:"
        ps aux | grep -w Z | grep -v grep || echo "  No zombie processes found"
        
        # Show processes with high resource usage
        echo ""
        echo "High Resource Usage Processes:"
        ps aux | awk '$3 > 10 || $4 > 10 {print}' | head -5
    else
        print_status "ERROR" "Process monitoring tools not available"
    fi
}

# Function to monitor services
monitor_services() {
    print_status "HEADER" "Service Monitoring"
    
    echo "Service Status:"
    
    # Check systemd services
    if command_exists systemctl; then
        echo "Systemd Services:"
        systemctl list-units --type=service --state=running | head -10
        echo ""
        
        echo "Failed Services:"
        systemctl list-units --type=service --state=failed
        echo ""
        
        echo "Service Load Times:"
        systemctl list-units --type=service --state=running --no-pager | head -5
    fi
    
    # Check for critical services
    local critical_services=("sshd" "systemd" "cron" "rsyslog")
    echo ""
    echo "Critical Services Status:"
    for service in "${critical_services[@]}"; do
        if command_exists systemctl; then
            local status=$(systemctl is-active "$service" 2>/dev/null)
            if [[ "$status" == "active" ]]; then
                print_status "SUCCESS" "$service: $status"
            else
                print_status "ALERT" "$service: $status"
                log_alert "Critical service $service is not active: $status"
            fi
        fi
    done
}

# Function to show system status
show_system_status() {
    print_status "HEADER" "System Status"
    
    echo "System Information:"
    echo "  Hostname: $(hostname)"
    echo "  OS: $(uname -s) $(uname -r)"
    echo "  Architecture: $(uname -m)"
    echo "  Uptime: $(uptime -p)"
    echo "  Current Time: $(date)"
    echo ""
    
    # Load average
    local load=$(get_load_average)
    echo "Load Average: $load"
    local load_1=$(echo $load | awk '{print $1}')
    if [[ $(echo "$load_1 > $LOAD_THRESHOLD" | bc -l 2>/dev/null) -eq 1 ]]; then
        print_status "ALERT" "Load average is high: $load_1"
        log_alert "Load average threshold exceeded: $load_1"
    fi
    echo ""
    
    # Quick resource check
    echo "Resource Status:"
    
    # CPU
    local cpu_usage=$(get_cpu_usage)
    if [[ -n "$cpu_usage" && "$cpu_usage" =~ ^[0-9]+$ ]]; then
        if [[ $cpu_usage -gt $CPU_THRESHOLD ]]; then
            print_status "ALERT" "CPU: ${cpu_usage}%"
        else
            print_status "SUCCESS" "CPU: ${cpu_usage}%"
        fi
    fi
    
    # Memory
    local memory_usage=$(get_memory_usage)
    if [[ -n "$memory_usage" && "$memory_usage" =~ ^[0-9]+$ ]]; then
        if [[ $memory_usage -gt $MEMORY_THRESHOLD ]]; then
            print_status "ALERT" "Memory: ${memory_usage}%"
        else
            print_status "SUCCESS" "Memory: ${memory_usage}%"
        fi
    fi
    
    # Disk
    local disk_usage=$(get_disk_usage)
    if [[ -n "$disk_usage" ]]; then
        echo "$disk_usage" | while IFS=':' read -r mount usage; do
            if [[ $usage -gt $DISK_THRESHOLD ]]; then
                print_status "ALERT" "Disk $mount: ${usage}%"
            else
                print_status "SUCCESS" "Disk $mount: ${usage}%"
            fi
        done
    fi
}

# Function to show alerts
show_alerts() {
    print_status "HEADER" "Recent Alerts"
    
    if [[ -f "$ALERT_FILE" ]]; then
        if command_exists tail; then
            tail -20 "$ALERT_FILE"
        else
            cat "$ALERT_FILE"
        fi
    else
        print_status "INFO" "No alerts found"
    fi
}

# Function to generate report
generate_report() {
    print_status "HEADER" "System Monitoring Report"
    
    local report_file="system-report-$(date +%Y%m%d-%H%M%S).txt"
    
    {
        echo "System Monitoring Report"
        echo "Generated on: $(date)"
        echo "Hostname: $(hostname)"
        echo "========================================"
        echo ""
        
        echo "System Information:"
        echo "  OS: $(uname -s) $(uname -r)"
        echo "  Architecture: $(uname -m)"
        echo "  Uptime: $(uptime -p)"
        echo ""
        
        echo "Resource Usage:"
        echo "  CPU Usage: $(get_cpu_usage)%"
        echo "  Memory Usage: $(get_memory_usage)%"
        echo "  Load Average: $(get_load_average)"
        echo ""
        
        echo "Disk Usage:"
        get_disk_usage
        echo ""
        
        echo "Process Information:"
        if command_exists ps; then
            echo "  Total Processes: $(ps aux | wc -l)"
            echo "  Running Processes: $(ps aux | grep -v "ps aux" | grep -v "grep" | wc -l)"
        fi
        echo ""
        
        echo "Service Status:"
        if command_exists systemctl; then
            echo "  Running Services: $(systemctl list-units --type=service --state=running | wc -l)"
            echo "  Failed Services: $(systemctl list-units --type=service --state=failed | wc -l)"
        fi
        echo ""
        
        echo "Recent Alerts:"
        if [[ -f "$ALERT_FILE" ]]; then
            tail -10 "$ALERT_FILE"
        else
            echo "  No alerts found"
        fi
        
    } > "$report_file"
    
    print_status "SUCCESS" "Report generated: $report_file"
}

# Function to continuous monitoring
continuous_monitor() {
    local duration="${1:-$DURATION}"
    local end_time=$((SECONDS + duration))
    
    print_status "HEADER" "Continuous Monitoring"
    print_status "INFO" "Monitoring for $duration seconds (until $(date -d @$end_time))"
    print_status "INFO" "Press Ctrl+C to stop"
    
    while [[ $SECONDS -lt $end_time ]]; do
        echo ""
        echo "=== $(date) ==="
        
        show_system_status
        
        # Wait for next interval
        sleep $INTERVAL
    done
    
    print_status "SUCCESS" "Monitoring completed"
}

# Main function
main() {
    local command=""
    local args=()
    local quiet_mode=false
    local daemon_mode=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -v|--version)
                echo "$SCRIPT_NAME version $VERSION"
                exit 0
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -l|--log)
                LOG_FILE="$2"
                shift 2
                ;;
            -i|--interval)
                INTERVAL="$2"
                shift 2
                ;;
            -t|--threshold)
                CPU_THRESHOLD="$2"
                shift 2
                ;;
            -q|--quiet)
                quiet_mode=true
                shift
                ;;
            -d|--daemon)
                daemon_mode=true
                shift
                ;;
            monitor|status|cpu|memory|disk|network|processes|services|alerts|report)
                command="$1"
                shift
                args=("$@")
                break
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Initialize logging
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/system-monitor.log"
    touch "$ALERT_FILE" 2>/dev/null || ALERT_FILE="/tmp/system-alerts.log"
    log_message "INFO" "Script started with command: $command"
    
    # Show header
    if [[ "$quiet_mode" == false ]]; then
        show_header
    fi
    
    # Execute command
    case $command in
        monitor)
            continuous_monitor "${args[0]}"
            ;;
        status)
            show_system_status
            ;;
        cpu)
            monitor_cpu
            ;;
        memory)
            monitor_memory
            ;;
        disk)
            monitor_disk
            ;;
        network)
            monitor_network
            ;;
        processes)
            monitor_processes
            ;;
        services)
            monitor_services
            ;;
        alerts)
            show_alerts
            ;;
        report)
            generate_report
            ;;
        "")
            print_status "ERROR" "No command specified"
            show_help
            exit 1
            ;;
        *)
            print_status "ERROR" "Unknown command: $command"
            show_help
            exit 1
            ;;
    esac
    
    log_message "INFO" "Script completed"
}

# Trap to handle script interruption
trap 'log_message "ERROR" "Script interrupted by user"; exit 1' INT TERM

# Check if script is being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi 