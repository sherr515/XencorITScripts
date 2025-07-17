#!/bin/bash

# =============================================================================
# Linux Security Audit Script
# =============================================================================
# Purpose: Comprehensive Linux system security auditing and assessment
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
SCRIPT_NAME="security-audit.sh"
VERSION="1.0.0"
CONFIG_FILE="/etc/security-audit.conf"
LOG_FILE="/var/log/security-audit.log"
REPORT_FILE="/var/log/security-report.txt"
ALERT_FILE="/var/log/security-alerts.log"

# Security thresholds
PASSWORD_MIN_LENGTH=8
PASSWORD_MAX_AGE=90
ACCOUNT_LOCKOUT_THRESHOLD=5
SESSION_TIMEOUT=300
FILE_PERMISSIONS_STRICT=true

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
        "CRITICAL")
            echo -e "${RED}[CRITICAL]${NC} $message"
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

# Function to check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_status "ERROR" "This script must be run as root"
        exit 1
    fi
}

# Function to display script header
show_header() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                Linux Security Audit Script                   ║"
    echo "║                        Version $VERSION                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to display help
show_help() {
    echo "Usage: $SCRIPT_NAME [OPTIONS] [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  audit [CATEGORY]             Perform comprehensive security audit"
    echo "  users                        Audit user accounts and passwords"
    echo "  files                        Audit file permissions and ownership"
    echo "  services                     Audit running services"
    echo "  network                      Audit network configuration"
    echo "  firewall                     Audit firewall rules"
    echo "  logs                         Audit system logs"
    echo "  packages                     Audit installed packages"
    echo "  kernel                       Audit kernel configuration"
    echo "  compliance                   Check compliance standards"
    echo "  report                       Generate security report"
    echo "  fix [ISSUE]                  Fix identified security issues"
    echo ""
    echo "Categories:"
    echo "  all                          All security checks (default)"
    echo "  basic                        Basic security checks"
    echo "  advanced                     Advanced security checks"
    echo "  compliance                   Compliance-specific checks"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -v, --version       Show version information"
    echo "  -c, --config FILE   Use specified config file"
    echo "  -l, --log FILE      Use specified log file"
    echo "  -r, --report FILE   Use specified report file"
    echo "  -q, --quiet         Suppress verbose output"
    echo "  -f, --fix           Automatically fix issues"
    echo "  -d, --detailed      Show detailed information"
    echo ""
    echo "Examples:"
    echo "  $SCRIPT_NAME audit all              # Full security audit"
    echo "  $SCRIPT_NAME users                   # Audit user accounts"
    echo "  $SCRIPT_NAME fix weak-passwords     # Fix weak passwords"
    echo "  $SCRIPT_NAME report                  # Generate report"
}

# Function to audit user accounts
audit_users() {
    print_status "HEADER" "User Account Security Audit"
    
    local issues_found=0
    
    echo "Checking user accounts..."
    
    # Check for accounts without passwords
    local no_password_users=$(awk -F: '$2 == "" {print $1}' /etc/shadow 2>/dev/null)
    if [[ -n "$no_password_users" ]]; then
        print_status "CRITICAL" "Found users without passwords:"
        echo "$no_password_users"
        log_alert "Users without passwords found: $no_password_users"
        ((issues_found++))
    else
        print_status "SUCCESS" "All users have passwords"
    fi
    
    # Check for weak passwords
    echo ""
    echo "Checking password strength..."
    local weak_passwords=$(awk -F: '$2 != "*" && $2 != "!" {print $1}' /etc/shadow 2>/dev/null | while read user; do
        # Check if password is in common wordlists
        if command_exists john; then
            john --wordlist=/usr/share/dict/words --users="$user" /etc/shadow 2>/dev/null | grep -q "$user" && echo "$user"
        fi
    done)
    
    if [[ -n "$weak_passwords" ]]; then
        print_status "WARNING" "Found users with potentially weak passwords:"
        echo "$weak_passwords"
        log_alert "Users with weak passwords found: $weak_passwords"
        ((issues_found++))
    else
        print_status "SUCCESS" "No weak passwords detected"
    fi
    
    # Check password aging
    echo ""
    echo "Checking password aging..."
    while IFS=: read -r user pass uid gid info home shell; do
        if [[ $uid -ge 1000 ]]; then
            local max_age=$(chage -l "$user" 2>/dev/null | grep "Maximum number of days" | awk '{print $4}')
            if [[ "$max_age" != "99999" && "$max_age" != "never" ]]; then
                if [[ $max_age -gt $PASSWORD_MAX_AGE ]]; then
                    print_status "WARNING" "User $user has long password age: $max_age days"
                    ((issues_found++))
                fi
            else
                print_status "WARNING" "User $user has no password expiration"
                ((issues_found++))
            fi
        fi
    done < /etc/passwd
    
    # Check for locked accounts
    echo ""
    echo "Checking account lockouts..."
    local locked_accounts=$(passwd -S 2>/dev/null | grep " L " | awk '{print $1}')
    if [[ -n "$locked_accounts" ]]; then
        print_status "INFO" "Locked accounts found:"
        echo "$locked_accounts"
    fi
    
    # Check for root access
    echo ""
    echo "Checking root access..."
    local root_users=$(awk -F: '$3 == 0 {print $1}' /etc/passwd)
    if [[ $(echo "$root_users" | wc -l) -gt 1 ]]; then
        print_status "WARNING" "Multiple root accounts found:"
        echo "$root_users"
        log_alert "Multiple root accounts found: $root_users"
        ((issues_found++))
    else
        print_status "SUCCESS" "Single root account found"
    fi
    
    # Check for default accounts
    echo ""
    echo "Checking default accounts..."
    local default_accounts=("adm" "lp" "sync" "shutdown" "halt" "mail" "news" "uucp" "operator" "games" "gopher" "ftp" "nobody" "systemd-network" "systemd-resolve" "systemd-timesync" "dbus" "polkitd" "avahi" "usbmux" "dnsmasq" "rtkit" "pulse" "gdm" "gnome-initial-setup" "sshd" "tcpdump" "nfsnobody")
    
    for account in "${default_accounts[@]}"; do
        if id "$account" >/dev/null 2>&1; then
            local shell=$(grep "^$account:" /etc/passwd | cut -d: -f7)
            if [[ "$shell" != "/sbin/nologin" && "$shell" != "/bin/false" ]]; then
                print_status "WARNING" "Default account $account has login shell: $shell"
                ((issues_found++))
            fi
        fi
    done
    
    echo ""
    print_status "INFO" "User account audit completed. Issues found: $issues_found"
    return $issues_found
}

# Function to audit file permissions
audit_files() {
    print_status "HEADER" "File Permission Security Audit"
    
    local issues_found=0
    
    echo "Checking critical file permissions..."
    
    # Check critical system files
    local critical_files=(
        "/etc/passwd:644"
        "/etc/shadow:400"
        "/etc/group:644"
        "/etc/gshadow:400"
        "/etc/sudoers:440"
        "/etc/ssh/sshd_config:600"
        "/etc/ssh/ssh_host_rsa_key:600"
        "/etc/ssh/ssh_host_ecdsa_key:600"
        "/etc/ssh/ssh_host_ed25519_key:600"
        "/etc/crontab:644"
        "/etc/anacrontab:644"
        "/etc/at.allow:600"
        "/etc/at.deny:600"
        "/etc/cron.allow:600"
        "/etc/cron.deny:600"
    )
    
    for file_spec in "${critical_files[@]}"; do
        local file="${file_spec%:*}"
        local expected_perms="${file_spec#*:}"
        
        if [[ -f "$file" ]]; then
            local actual_perms=$(stat -c "%a" "$file" 2>/dev/null)
            if [[ "$actual_perms" != "$expected_perms" ]]; then
                print_status "WARNING" "File $file has incorrect permissions: $actual_perms (expected: $expected_perms)"
                ((issues_found++))
            fi
        fi
    done
    
    # Check for world-writable files
    echo ""
    echo "Checking for world-writable files..."
    local world_writable=$(find / -type f -perm -002 -ls 2>/dev/null | head -20)
    if [[ -n "$world_writable" ]]; then
        print_status "WARNING" "Found world-writable files:"
        echo "$world_writable"
        ((issues_found++))
    else
        print_status "SUCCESS" "No world-writable files found"
    fi
    
    # Check for SUID/SGID files
    echo ""
    echo "Checking for SUID/SGID files..."
    local suid_files=$(find / -type f -perm -4000 -ls 2>/dev/null | head -20)
    if [[ -n "$suid_files" ]]; then
        print_status "INFO" "Found SUID files:"
        echo "$suid_files"
    fi
    
    local sgid_files=$(find / -type f -perm -2000 -ls 2>/dev/null | head -20)
    if [[ -n "$sgid_files" ]]; then
        print_status "INFO" "Found SGID files:"
        echo "$sgid_files"
    fi
    
    # Check for unowned files
    echo ""
    echo "Checking for unowned files..."
    local unowned_files=$(find / -nouser -ls 2>/dev/null | head -20)
    if [[ -n "$unowned_files" ]]; then
        print_status "WARNING" "Found unowned files:"
        echo "$unowned_files"
        ((issues_found++))
    else
        print_status "SUCCESS" "No unowned files found"
    fi
    
    # Check for ungrouped files
    echo ""
    echo "Checking for ungrouped files..."
    local ungrouped_files=$(find / -nogroup -ls 2>/dev/null | head -20)
    if [[ -n "$ungrouped_files" ]]; then
        print_status "WARNING" "Found ungrouped files:"
        echo "$ungrouped_files"
        ((issues_found++))
    else
        print_status "SUCCESS" "No ungrouped files found"
    fi
    
    echo ""
    print_status "INFO" "File permission audit completed. Issues found: $issues_found"
    return $issues_found
}

# Function to audit services
audit_services() {
    print_status "HEADER" "Service Security Audit"
    
    local issues_found=0
    
    echo "Checking running services..."
    
    # Check for unnecessary services
    local unnecessary_services=("telnet" "rsh" "rlogin" "rexec" "tftp" "xinetd" "inetd")
    
    for service in "${unnecessary_services[@]}"; do
        if command_exists systemctl; then
            if systemctl is-active "$service" >/dev/null 2>&1; then
                print_status "CRITICAL" "Unnecessary service running: $service"
                log_alert "Unnecessary service running: $service"
                ((issues_found++))
            fi
        fi
    done
    
    # Check for listening ports
    echo ""
    echo "Checking listening ports..."
    if command_exists ss; then
        local listening_ports=$(ss -tuln | grep LISTEN)
        echo "Listening ports:"
        echo "$listening_ports"
        
        # Check for common vulnerable ports
        local vulnerable_ports=("21" "23" "25" "110" "143" "513" "514")
        for port in "${vulnerable_ports[@]}"; do
            if echo "$listening_ports" | grep -q ":$port "; then
                print_status "WARNING" "Potentially vulnerable port listening: $port"
                ((issues_found++))
            fi
        done
    fi
    
    # Check SSH configuration
    echo ""
    echo "Checking SSH configuration..."
    if [[ -f /etc/ssh/sshd_config ]]; then
        local ssh_config_issues=0
        
        # Check PermitRootLogin
        if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config; then
            print_status "CRITICAL" "SSH root login is enabled"
            log_alert "SSH root login is enabled"
            ((ssh_config_issues++))
        fi
        
        # Check PasswordAuthentication
        if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config; then
            print_status "WARNING" "SSH password authentication is enabled"
            ((ssh_config_issues++))
        fi
        
        # Check Protocol
        if grep -q "^Protocol 1" /etc/ssh/sshd_config; then
            print_status "CRITICAL" "SSH Protocol 1 is enabled (insecure)"
            log_alert "SSH Protocol 1 is enabled"
            ((ssh_config_issues++))
        fi
        
        if [[ $ssh_config_issues -eq 0 ]]; then
            print_status "SUCCESS" "SSH configuration is secure"
        fi
        ((issues_found += ssh_config_issues))
    fi
    
    # Check for running daemons
    echo ""
    echo "Checking running daemons..."
    if command_exists systemctl; then
        local running_services=$(systemctl list-units --type=service --state=running --no-pager | grep -v "UNIT\|LOAD\|ACTIVE\|SUB\|running")
        echo "Running services:"
        echo "$running_services"
    fi
    
    echo ""
    print_status "INFO" "Service audit completed. Issues found: $issues_found"
    return $issues_found
}

# Function to audit network configuration
audit_network() {
    print_status "HEADER" "Network Security Audit"
    
    local issues_found=0
    
    echo "Checking network configuration..."
    
    # Check network interfaces
    echo ""
    echo "Network interfaces:"
    if command_exists ip; then
        ip addr show
    elif command_exists ifconfig; then
        ifconfig
    fi
    
    # Check routing table
    echo ""
    echo "Routing table:"
    if command_exists ip; then
        ip route show
    elif command_exists route; then
        route -n
    fi
    
    # Check for promiscuous interfaces
    echo ""
    echo "Checking for promiscuous interfaces..."
    local promiscuous=$(ip link show | grep -i promisc)
    if [[ -n "$promiscuous" ]]; then
        print_status "WARNING" "Found promiscuous interfaces:"
        echo "$promiscuous"
        ((issues_found++))
    else
        print_status "SUCCESS" "No promiscuous interfaces found"
    fi
    
    # Check for IP forwarding
    echo ""
    echo "Checking IP forwarding..."
    local ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    if [[ "$ip_forward" == "1" ]]; then
        print_status "INFO" "IP forwarding is enabled"
    else
        print_status "SUCCESS" "IP forwarding is disabled"
    fi
    
    # Check for ICMP redirects
    echo ""
    echo "Checking ICMP redirects..."
    local icmp_redirects=$(cat /proc/sys/net/ipv4/conf/*/accept_redirects 2>/dev/null | grep -v "^0$" | head -1)
    if [[ -n "$icmp_redirects" ]]; then
        print_status "WARNING" "ICMP redirects are accepted"
        ((issues_found++))
    else
        print_status "SUCCESS" "ICMP redirects are disabled"
    fi
    
    # Check for source routing
    echo ""
    echo "Checking source routing..."
    local source_routing=$(cat /proc/sys/net/ipv4/conf/*/accept_source_route 2>/dev/null | grep -v "^0$" | head -1)
    if [[ -n "$source_routing" ]]; then
        print_status "WARNING" "Source routing is accepted"
        ((issues_found++))
    else
        print_status "SUCCESS" "Source routing is disabled"
    fi
    
    echo ""
    print_status "INFO" "Network audit completed. Issues found: $issues_found"
    return $issues_found
}

# Function to audit firewall
audit_firewall() {
    print_status "HEADER" "Firewall Security Audit"
    
    local issues_found=0
    
    echo "Checking firewall configuration..."
    
    # Check iptables
    if command_exists iptables; then
        echo ""
        echo "iptables rules:"
        iptables -L -n -v
        
        # Check if default policies are restrictive
        local input_policy=$(iptables -L INPUT --line-numbers | grep "Chain INPUT" | awk '{print $4}')
        local forward_policy=$(iptables -L FORWARD --line-numbers | grep "Chain FORWARD" | awk '{print $4}')
        
        if [[ "$input_policy" != "DROP" && "$input_policy" != "REJECT" ]]; then
            print_status "WARNING" "iptables INPUT policy is not restrictive: $input_policy"
            ((issues_found++))
        fi
        
        if [[ "$forward_policy" != "DROP" && "$forward_policy" != "REJECT" ]]; then
            print_status "WARNING" "iptables FORWARD policy is not restrictive: $forward_policy"
            ((issues_found++))
        fi
    fi
    
    # Check firewalld
    if command_exists firewall-cmd; then
        echo ""
        echo "firewalld status:"
        firewall-cmd --state 2>/dev/null || echo "firewalld not running"
        
        if firewall-cmd --state >/dev/null 2>&1; then
            echo "Active zones:"
            firewall-cmd --get-active-zones
            
            echo "Default zone:"
            firewall-cmd --get-default-zone
        fi
    fi
    
    # Check ufw
    if command_exists ufw; then
        echo ""
        echo "ufw status:"
        ufw status verbose
    fi
    
    # Check for listening ports
    echo ""
    echo "Checking for open ports..."
    if command_exists ss; then
        local open_ports=$(ss -tuln | grep LISTEN)
        echo "Open ports:"
        echo "$open_ports"
    fi
    
    echo ""
    print_status "INFO" "Firewall audit completed. Issues found: $issues_found"
    return $issues_found
}

# Function to audit system logs
audit_logs() {
    print_status "HEADER" "System Log Security Audit"
    
    local issues_found=0
    
    echo "Checking system logs..."
    
    # Check log file permissions
    echo ""
    echo "Checking log file permissions..."
    local log_files=("/var/log/auth.log" "/var/log/secure" "/var/log/messages" "/var/log/syslog")
    
    for log_file in "${log_files[@]}"; do
        if [[ -f "$log_file" ]]; then
            local perms=$(stat -c "%a" "$log_file" 2>/dev/null)
            if [[ "$perms" != "640" && "$perms" != "644" ]]; then
                print_status "WARNING" "Log file $log_file has incorrect permissions: $perms"
                ((issues_found++))
            fi
        fi
    done
    
    # Check for failed login attempts
    echo ""
    echo "Checking for failed login attempts..."
    if [[ -f /var/log/auth.log ]]; then
        local failed_logins=$(grep "Failed password" /var/log/auth.log | tail -10)
        if [[ -n "$failed_logins" ]]; then
            print_status "WARNING" "Recent failed login attempts:"
            echo "$failed_logins"
            ((issues_found++))
        fi
    elif [[ -f /var/log/secure ]]; then
        local failed_logins=$(grep "Failed password" /var/log/secure | tail -10)
        if [[ -n "$failed_logins" ]]; then
            print_status "WARNING" "Recent failed login attempts:"
            echo "$failed_logins"
            ((issues_found++))
        fi
    fi
    
    # Check for sudo usage
    echo ""
    echo "Checking sudo usage..."
    if [[ -f /var/log/auth.log ]]; then
        local sudo_usage=$(grep "sudo:" /var/log/auth.log | tail -10)
        if [[ -n "$sudo_usage" ]]; then
            echo "Recent sudo usage:"
            echo "$sudo_usage"
        fi
    fi
    
    # Check for system errors
    echo ""
    echo "Checking for system errors..."
    local system_errors=$(journalctl -p err --since "1 hour ago" --no-pager | tail -10)
    if [[ -n "$system_errors" ]]; then
        print_status "WARNING" "Recent system errors:"
        echo "$system_errors"
        ((issues_found++))
    fi
    
    echo ""
    print_status "INFO" "Log audit completed. Issues found: $issues_found"
    return $issues_found
}

# Function to audit installed packages
audit_packages() {
    print_status "HEADER" "Package Security Audit"
    
    local issues_found=0
    
    echo "Checking installed packages..."
    
    # Check for vulnerable packages
    if command_exists apt; then
        echo ""
        echo "Checking for security updates (Debian/Ubuntu)..."
        apt list --upgradable 2>/dev/null | grep security || echo "No security updates available"
    elif command_exists yum; then
        echo ""
        echo "Checking for security updates (RHEL/CentOS)..."
        yum check-update --security 2>/dev/null || echo "No security updates available"
    elif command_exists dnf; then
        echo ""
        echo "Checking for security updates (Fedora)..."
        dnf check-update --security 2>/dev/null || echo "No security updates available"
    fi
    
    # Check for unnecessary packages
    echo ""
    echo "Checking for unnecessary packages..."
    local unnecessary_packages=("telnet" "rsh" "rlogin" "rexec" "tftp" "xinetd" "inetd" "vsftpd" "proftpd")
    
    for package in "${unnecessary_packages[@]}"; do
        if command_exists dpkg; then
            if dpkg -l | grep -q "^ii.*$package"; then
                print_status "WARNING" "Unnecessary package installed: $package"
                ((issues_found++))
            fi
        elif command_exists rpm; then
            if rpm -q "$package" >/dev/null 2>&1; then
                print_status "WARNING" "Unnecessary package installed: $package"
                ((issues_found++))
            fi
        fi
    done
    
    # Check for development tools
    echo ""
    echo "Checking for development tools..."
    local dev_tools=("gcc" "make" "gdb" "strace" "ltrace")
    
    for tool in "${dev_tools[@]}"; do
        if command_exists "$tool"; then
            print_status "INFO" "Development tool found: $tool"
        fi
    done
    
    echo ""
    print_status "INFO" "Package audit completed. Issues found: $issues_found"
    return $issues_found
}

# Function to audit kernel configuration
audit_kernel() {
    print_status "HEADER" "Kernel Security Audit"
    
    local issues_found=0
    
    echo "Checking kernel configuration..."
    
    # Check kernel version
    echo ""
    echo "Kernel version:"
    uname -r
    
    # Check kernel parameters
    echo ""
    echo "Checking kernel security parameters..."
    
    # Check for core dumps
    local core_dumps=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)
    if [[ "$core_dumps" != "|/bin/false" && "$core_dumps" != "/dev/null" ]]; then
        print_status "WARNING" "Core dumps are enabled: $core_dumps"
        ((issues_found++))
    else
        print_status "SUCCESS" "Core dumps are disabled"
    fi
    
    # Check for ASLR
    local aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
    if [[ "$aslr" == "0" ]]; then
        print_status "WARNING" "ASLR is disabled"
        ((issues_found++))
    else
        print_status "SUCCESS" "ASLR is enabled"
    fi
    
    # Check for dmesg restrictions
    local dmesg_restrict=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)
    if [[ "$dmesg_restrict" == "0" ]]; then
        print_status "WARNING" "dmesg restrictions are disabled"
        ((issues_found++))
    else
        print_status "SUCCESS" "dmesg restrictions are enabled"
    fi
    
    # Check for kptr_restrict
    local kptr_restrict=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)
    if [[ "$kptr_restrict" == "0" ]]; then
        print_status "WARNING" "Kernel pointer restrictions are disabled"
        ((issues_found++))
    else
        print_status "SUCCESS" "Kernel pointer restrictions are enabled"
    fi
    
    # Check for module loading
    local module_loading=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null)
    if [[ "$module_loading" == "1" ]]; then
        print_status "SUCCESS" "Module loading is disabled"
    else
        print_status "INFO" "Module loading is enabled"
    fi
    
    echo ""
    print_status "INFO" "Kernel audit completed. Issues found: $issues_found"
    return $issues_found
}

# Function to check compliance
check_compliance() {
    print_status "HEADER" "Compliance Check"
    
    local compliance_issues=0
    
    echo "Checking compliance standards..."
    
    # CIS Benchmark checks
    echo ""
    echo "CIS Benchmark Checks:"
    
    # Check password policy
    local min_len=$(grep "^PASS_MIN_LEN" /etc/login.defs | awk '{print $2}')
    if [[ $min_len -lt $PASSWORD_MIN_LENGTH ]]; then
        print_status "WARNING" "Password minimum length is too short: $min_len"
        ((compliance_issues++))
    fi
    
    # Check password aging
    local max_age=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
    if [[ $max_age -gt $PASSWORD_MAX_AGE ]]; then
        print_status "WARNING" "Password maximum age is too long: $max_age"
        ((compliance_issues++))
    fi
    
    # Check account lockout
    if [[ -f /etc/pam.d/system-auth ]]; then
        local lockout=$(grep "pam_tally2" /etc/pam.d/system-auth | grep "deny=" | awk '{print $4}' | cut -d= -f2)
        if [[ -n "$lockout" && $lockout -gt $ACCOUNT_LOCKOUT_THRESHOLD ]]; then
            print_status "WARNING" "Account lockout threshold is too high: $lockout"
            ((compliance_issues++))
        fi
    fi
    
    # Check session timeout
    if [[ -f /etc/profile ]]; then
        local timeout=$(grep "TMOUT" /etc/profile | awk -F= '{print $2}')
        if [[ -n "$timeout" && $timeout -gt $SESSION_TIMEOUT ]]; then
            print_status "WARNING" "Session timeout is too long: $timeout"
            ((compliance_issues++))
        fi
    fi
    
    echo ""
    print_status "INFO" "Compliance check completed. Issues found: $compliance_issues"
    return $compliance_issues
}

# Function to generate report
generate_report() {
    print_status "HEADER" "Generating Security Report"
    
    local report_file="${1:-$REPORT_FILE}"
    
    {
        echo "Linux Security Audit Report"
        echo "Generated on: $(date)"
        echo "Hostname: $(hostname)"
        echo "OS: $(uname -s) $(uname -r)"
        echo "========================================"
        echo ""
        
        echo "Executive Summary:"
        echo "=================="
        echo "This report contains the results of a comprehensive security audit"
        echo "performed on the system. The audit covers user accounts, file"
        echo "permissions, services, network configuration, and compliance."
        echo ""
        
        echo "Critical Findings:"
        echo "=================="
        if [[ -f "$ALERT_FILE" ]]; then
            cat "$ALERT_FILE"
        else
            echo "No critical findings"
        fi
        echo ""
        
        echo "Recommendations:"
        echo "================"
        echo "1. Review and fix all identified security issues"
        echo "2. Implement regular security audits"
        echo "3. Keep system and packages updated"
        echo "4. Monitor system logs regularly"
        echo "5. Implement intrusion detection"
        echo ""
        
        echo "Detailed Findings:"
        echo "=================="
        echo "See the log file for detailed information: $LOG_FILE"
        
    } > "$report_file"
    
    print_status "SUCCESS" "Security report generated: $report_file"
}

# Function to fix security issues
fix_issues() {
    local issue_type="$1"
    
    print_status "HEADER" "Fixing Security Issues"
    
    case $issue_type in
        "weak-passwords")
            print_status "INFO" "Fixing weak passwords..."
            # Force password change for all users
            while IFS=: read -r user pass uid gid info home shell; do
                if [[ $uid -ge 1000 ]]; then
                    chage -d 0 "$user" 2>/dev/null
                    print_status "INFO" "Forced password change for user: $user"
                fi
            done < /etc/passwd
            ;;
        "file-permissions")
            print_status "INFO" "Fixing file permissions..."
            # Fix critical file permissions
            chmod 644 /etc/passwd
            chmod 400 /etc/shadow
            chmod 644 /etc/group
            chmod 400 /etc/gshadow
            chmod 440 /etc/sudoers
            print_status "SUCCESS" "Critical file permissions fixed"
            ;;
        "unnecessary-services")
            print_status "INFO" "Disabling unnecessary services..."
            # Disable unnecessary services
            local services=("telnet" "rsh" "rlogin" "rexec" "tftp")
            for service in "${services[@]}"; do
                if command_exists systemctl; then
                    systemctl disable "$service" 2>/dev/null
                    systemctl stop "$service" 2>/dev/null
                    print_status "INFO" "Disabled service: $service"
                fi
            done
            ;;
        *)
            print_status "ERROR" "Unknown issue type: $issue_type"
            return 1
            ;;
    esac
    
    print_status "SUCCESS" "Security issues fixed"
}

# Main function
main() {
    local command=""
    local args=()
    local quiet_mode=false
    local fix_mode=false
    local detailed_mode=false
    
    # Check if running as root
    check_root
    
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
            -r|--report)
                REPORT_FILE="$2"
                shift 2
                ;;
            -q|--quiet)
                quiet_mode=true
                shift
                ;;
            -f|--fix)
                fix_mode=true
                shift
                ;;
            -d|--detailed)
                detailed_mode=true
                shift
                ;;
            audit|users|files|services|network|firewall|logs|packages|kernel|compliance|report|fix)
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
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/security-audit.log"
    touch "$ALERT_FILE" 2>/dev/null || ALERT_FILE="/tmp/security-alerts.log"
    log_message "INFO" "Script started with command: $command"
    
    # Show header
    if [[ "$quiet_mode" == false ]]; then
        show_header
    fi
    
    # Execute command
    case $command in
        audit)
            local category="${args[0]:-all}"
            print_status "HEADER" "Comprehensive Security Audit"
            
            audit_users
            audit_files
            audit_services
            audit_network
            audit_firewall
            audit_logs
            audit_packages
            audit_kernel
            check_compliance
            
            generate_report
            ;;
        users)
            audit_users
            ;;
        files)
            audit_files
            ;;
        services)
            audit_services
            ;;
        network)
            audit_network
            ;;
        firewall)
            audit_firewall
            ;;
        logs)
            audit_logs
            ;;
        packages)
            audit_packages
            ;;
        kernel)
            audit_kernel
            ;;
        compliance)
            check_compliance
            ;;
        report)
            generate_report "${args[0]}"
            ;;
        fix)
            if [[ ${#args[@]} -lt 1 ]]; then
                print_status "ERROR" "fix command requires issue type"
                exit 1
            fi
            fix_issues "${args[0]}"
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