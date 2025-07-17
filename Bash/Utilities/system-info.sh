#!/bin/bash

# =============================================================================
# System Information Gathering Script
# =============================================================================
# Purpose: Comprehensive system information collection and reporting
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
SCRIPT_NAME="system-info.sh"
VERSION="1.0.0"
LOG_FILE="/var/log/system-info.log"
OUTPUT_FILE="system-info-$(date +%Y%m%d-%H%M%S).txt"

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

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to display script header
show_header() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    System Information Script                  ║"
    echo "║                        Version $VERSION                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to display help
show_help() {
    echo "Usage: $SCRIPT_NAME [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -v, --version       Show version information"
    echo "  -o, --output FILE   Save output to specified file"
    echo "  -q, --quiet         Suppress verbose output"
    echo "  -c, --cpu           CPU information only"
    echo "  -m, --memory        Memory information only"
    echo "  -d, --disk          Disk information only"
    echo "  -n, --network       Network information only"
    echo "  -p, --processes     Process information only"
    echo "  -s, --services      Service information only"
    echo "  -a, --all           All information (default)"
    echo ""
    echo "Examples:"
    echo "  $SCRIPT_NAME                    # Show all system information"
    echo "  $SCRIPT_NAME -o report.txt      # Save output to report.txt"
    echo "  $SCRIPT_NAME -c -m              # Show CPU and memory only"
    echo "  $SCRIPT_NAME -q                 # Quiet mode"
}

# Function to get CPU information
get_cpu_info() {
    print_status "HEADER" "CPU Information"
    
    if command_exists lscpu; then
        echo "CPU Architecture:"
        lscpu | grep -E "(Architecture|CPU op-mode|Byte Order|CPU\(s\)|On-line CPU\(s\) list|Thread\(s\) per core|Core\(s\) per socket|Socket\(s\)|NUMA node\(s\)|Vendor ID|CPU family|Model|Model name|CPU MHz|CPU max MHz|CPU min MHz|BogoMIPS|Virtualization|L1d cache|L1i cache|L2 cache|L3 cache)"
        echo ""
    fi
    
    if command_exists cat; then
        echo "CPU Details from /proc/cpuinfo:"
        echo "Processor count: $(grep -c processor /proc/cpuinfo)"
        echo "Model name: $(grep "model name" /proc/cpuinfo | head -1 | cut -d: -f2 | sed 's/^[ \t]*//')"
        echo ""
    fi
    
    if command_exists uptime; then
        echo "System Load:"
        uptime
        echo ""
    fi
}

# Function to get memory information
get_memory_info() {
    print_status "HEADER" "Memory Information"
    
    if command_exists free; then
        echo "Memory Usage:"
        free -h
        echo ""
    fi
    
    if command_exists cat; then
        echo "Memory Details from /proc/meminfo:"
        grep -E "(MemTotal|MemFree|MemAvailable|Buffers|Cached|SwapTotal|SwapFree)" /proc/meminfo
        echo ""
    fi
    
    if command_exists vmstat; then
        echo "Virtual Memory Statistics:"
        vmstat 1 3
        echo ""
    fi
}

# Function to get disk information
get_disk_info() {
    print_status "HEADER" "Disk Information"
    
    if command_exists df; then
        echo "Disk Usage:"
        df -h
        echo ""
    fi
    
    if command_exists lsblk; then
        echo "Block Devices:"
        lsblk
        echo ""
    fi
    
    if command_exists fdisk; then
        echo "Partition Information:"
        sudo fdisk -l 2>/dev/null || echo "fdisk requires sudo privileges"
        echo ""
    fi
    
    if command_exists iostat; then
        echo "Disk I/O Statistics:"
        iostat -x 1 3 2>/dev/null || echo "iostat not available"
        echo ""
    fi
}

# Function to get network information
get_network_info() {
    print_status "HEADER" "Network Information"
    
    if command_exists ip; then
        echo "Network Interfaces:"
        ip addr show
        echo ""
    elif command_exists ifconfig; then
        echo "Network Interfaces:"
        ifconfig
        echo ""
    fi
    
    if command_exists ss; then
        echo "Network Connections:"
        ss -tuln
        echo ""
    elif command_exists netstat; then
        echo "Network Connections:"
        netstat -tuln
        echo ""
    fi
    
    if command_exists route; then
        echo "Routing Table:"
        route -n
        echo ""
    fi
    
    if command_exists ping; then
        echo "Network Connectivity Test:"
        ping -c 3 8.8.8.8 2>/dev/null || echo "ping test failed"
        echo ""
    fi
}

# Function to get process information
get_process_info() {
    print_status "HEADER" "Process Information"
    
    if command_exists ps; then
        echo "Top Processes by CPU Usage:"
        ps aux --sort=-%cpu | head -10
        echo ""
        
        echo "Top Processes by Memory Usage:"
        ps aux --sort=-%mem | head -10
        echo ""
    fi
    
    if command_exists top; then
        echo "System Process Summary:"
        top -bn1 | head -20
        echo ""
    fi
}

# Function to get service information
get_service_info() {
    print_status "HEADER" "Service Information"
    
    if command_exists systemctl; then
        echo "System Services Status:"
        systemctl list-units --type=service --state=running | head -20
        echo ""
        
        echo "Failed Services:"
        systemctl list-units --type=service --state=failed
        echo ""
    elif command_exists service; then
        echo "Service Status (legacy):"
        service --status-all | head -20
        echo ""
    fi
}

# Function to get system information
get_system_info() {
    print_status "HEADER" "System Information"
    
    echo "Hostname: $(hostname)"
    echo "Operating System: $(uname -s)"
    echo "Kernel Version: $(uname -r)"
    echo "Architecture: $(uname -m)"
    echo "Distribution: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || echo "Unknown")"
    echo "Uptime: $(uptime -p)"
    echo "Current Time: $(date)"
    echo ""
    
    if command_exists who; then
        echo "Logged in Users:"
        who
        echo ""
    fi
    
    if command_exists last; then
        echo "Recent Logins:"
        last | head -10
        echo ""
    fi
}

# Function to get hardware information
get_hardware_info() {
    print_status "HEADER" "Hardware Information"
    
    if command_exists lshw; then
        echo "Hardware Information:"
        sudo lshw -short 2>/dev/null || echo "lshw requires sudo privileges"
        echo ""
    fi
    
    if command_exists dmidecode; then
        echo "BIOS Information:"
        sudo dmidecode -t bios 2>/dev/null | head -20 || echo "dmidecode requires sudo privileges"
        echo ""
    fi
    
    if command_exists lspci; then
        echo "PCI Devices:"
        lspci | head -20
        echo ""
    fi
    
    if command_exists lsusb; then
        echo "USB Devices:"
        lsusb | head -20
        echo ""
    fi
}

# Function to get security information
get_security_info() {
    print_status "HEADER" "Security Information"
    
    echo "SELinux Status:"
    if command_exists sestatus; then
        sestatus
    else
        echo "SELinux not available"
    fi
    echo ""
    
    echo "AppArmor Status:"
    if command_exists aa-status; then
        aa-status 2>/dev/null || echo "AppArmor not available"
    else
        echo "AppArmor not available"
    fi
    echo ""
    
    echo "Failed Login Attempts:"
    if command_exists lastb; then
        lastb | head -10 2>/dev/null || echo "No failed login attempts or insufficient privileges"
    else
        echo "lastb command not available"
    fi
    echo ""
}

# Main function
main() {
    local show_cpu=false
    local show_memory=false
    local show_disk=false
    local show_network=false
    local show_processes=false
    local show_services=false
    local show_all=true
    local quiet_mode=false
    
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
            -o|--output)
                OUTPUT_FILE="$2"
                shift 2
                ;;
            -q|--quiet)
                quiet_mode=true
                shift
                ;;
            -c|--cpu)
                show_cpu=true
                show_all=false
                shift
                ;;
            -m|--memory)
                show_memory=true
                show_all=false
                shift
                ;;
            -d|--disk)
                show_disk=true
                show_all=false
                shift
                ;;
            -n|--network)
                show_network=true
                show_all=false
                shift
                ;;
            -p|--processes)
                show_processes=true
                show_all=false
                shift
                ;;
            -s|--services)
                show_services=true
                show_all=false
                shift
                ;;
            -a|--all)
                show_all=true
                shift
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Initialize logging
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/system-info.log"
    log_message "INFO" "Script started"
    
    # Show header
    if [[ "$quiet_mode" == false ]]; then
        show_header
    fi
    
    # Create output file
    {
        echo "System Information Report"
        echo "Generated on: $(date)"
        echo "Hostname: $(hostname)"
        echo "========================================"
        echo ""
        
        # Collect information based on options
        if [[ "$show_all" == true ]] || [[ "$show_cpu" == true ]]; then
            get_cpu_info
        fi
        
        if [[ "$show_all" == true ]] || [[ "$show_memory" == true ]]; then
            get_memory_info
        fi
        
        if [[ "$show_all" == true ]] || [[ "$show_disk" == true ]]; then
            get_disk_info
        fi
        
        if [[ "$show_all" == true ]] || [[ "$show_network" == true ]]; then
            get_network_info
        fi
        
        if [[ "$show_all" == true ]] || [[ "$show_processes" == true ]]; then
            get_process_info
        fi
        
        if [[ "$show_all" == true ]] || [[ "$show_services" == true ]]; then
            get_service_info
        fi
        
        if [[ "$show_all" == true ]]; then
            get_system_info
            get_hardware_info
            get_security_info
        fi
        
    } | tee "$OUTPUT_FILE"
    
    log_message "INFO" "Script completed successfully"
    print_status "SUCCESS" "System information saved to: $OUTPUT_FILE"
    print_status "INFO" "Log file: $LOG_FILE"
}

# Trap to handle script interruption
trap 'log_message "ERROR" "Script interrupted by user"; exit 1' INT TERM

# Check if script is being sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi 