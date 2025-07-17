#!/bin/bash

# =============================================================================
# User Management Script
# =============================================================================
# Purpose: Comprehensive user account management and administration
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
SCRIPT_NAME="user-management.sh"
VERSION="1.0.0"
CONFIG_FILE="/etc/user-management.conf"
LOG_FILE="/var/log/user-management.log"
DEFAULT_SHELL="/bin/bash"
DEFAULT_HOME="/home"
PASSWORD_EXPIRY_DAYS=90

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
    echo "║                  User Management Script                      ║"
    echo "║                        Version $VERSION                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to display help
show_help() {
    echo "Usage: $SCRIPT_NAME [OPTIONS] [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  create USERNAME [OPTIONS]     Create a new user account"
    echo "  delete USERNAME               Delete a user account"
    echo "  modify USERNAME [OPTIONS]     Modify user account properties"
    echo "  list [OPTIONS]                List user accounts"
    echo "  lock USERNAME                 Lock a user account"
    echo "  unlock USERNAME               Unlock a user account"
    echo "  password USERNAME             Change user password"
    echo "  expire USERNAME [DAYS]        Set password expiry"
    echo "  groups USERNAME               Show user groups"
    echo "  addgroup USERNAME GROUP       Add user to group"
    echo "  removegroup USERNAME GROUP    Remove user from group"
    echo "  audit                         Audit user accounts"
    echo "  cleanup                       Clean up inactive accounts"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -v, --version       Show version information"
    echo "  -c, --config FILE   Use specified config file"
    echo "  -l, --log FILE      Use specified log file"
    echo "  -q, --quiet         Suppress verbose output"
    echo "  -f, --force         Force operation without confirmation"
    echo "  -s, --shell SHELL   Set user shell (default: $DEFAULT_SHELL)"
    echo "  -d, --home DIR      Set home directory (default: $DEFAULT_HOME)"
    echo "  -g, --group GROUP   Set primary group"
    echo "  -G, --groups GROUPS Set additional groups (comma-separated)"
    echo "  -e, --expiry DATE   Set account expiry date (YYYY-MM-DD)"
    echo "  -c, --comment TEXT  Set user comment"
    echo ""
    echo "Examples:"
    echo "  $SCRIPT_NAME create john -s /bin/bash -g users"
    echo "  $SCRIPT_NAME list --inactive"
    echo "  $SCRIPT_NAME modify john --expiry 2024-12-31"
    echo "  $SCRIPT_NAME audit"
}

# Function to create user
create_user() {
    local username="$1"
    local shell="${2:-$DEFAULT_SHELL}"
    local home_dir="${3:-$DEFAULT_HOME/$username}"
    local primary_group="${4:-users}"
    local additional_groups="${5:-}"
    local expiry_date="${6:-}"
    local comment="${7:-}"
    
    print_status "HEADER" "Creating User Account"
    
    # Validate username
    if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]*$ ]]; then
        print_status "ERROR" "Invalid username format: $username"
        return 1
    fi
    
    # Check if user already exists
    if id "$username" >/dev/null 2>&1; then
        print_status "ERROR" "User already exists: $username"
        return 1
    fi
    
    # Build useradd command
    local useradd_cmd="useradd"
    
    if [[ -n "$shell" ]]; then
        useradd_cmd="$useradd_cmd -s $shell"
    fi
    
    if [[ -n "$home_dir" ]]; then
        useradd_cmd="$useradd_cmd -d $home_dir"
    fi
    
    if [[ -n "$primary_group" ]]; then
        useradd_cmd="$useradd_cmd -g $primary_group"
    fi
    
    if [[ -n "$additional_groups" ]]; then
        useradd_cmd="$useradd_cmd -G $additional_groups"
    fi
    
    if [[ -n "$expiry_date" ]]; then
        useradd_cmd="$useradd_cmd -e $expiry_date"
    fi
    
    if [[ -n "$comment" ]]; then
        useradd_cmd="$useradd_cmd -c '$comment'"
    fi
    
    useradd_cmd="$useradd_cmd $username"
    
    print_status "INFO" "Creating user: $username"
    print_status "INFO" "Shell: $shell"
    print_status "INFO" "Home directory: $home_dir"
    print_status "INFO" "Primary group: $primary_group"
    
    if [[ -n "$additional_groups" ]]; then
        print_status "INFO" "Additional groups: $additional_groups"
    fi
    
    # Execute user creation
    eval $useradd_cmd
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "User created successfully: $username"
        
        # Set initial password
        print_status "INFO" "Setting initial password..."
        echo "$username:password123" | chpasswd
        
        # Force password change on first login
        chage -d 0 "$username"
        
        log_message "INFO" "User created: $username"
        return 0
    else
        print_status "ERROR" "Failed to create user: $username"
        log_message "ERROR" "Failed to create user: $username"
        return 1
    fi
}

# Function to delete user
delete_user() {
    local username="$1"
    local remove_home="${2:-false}"
    
    print_status "HEADER" "Deleting User Account"
    
    # Check if user exists
    if ! id "$username" >/dev/null 2>&1; then
        print_status "ERROR" "User does not exist: $username"
        return 1
    fi
    
    # Check if user is currently logged in
    if who | grep -q "$username"; then
        print_status "WARNING" "User is currently logged in: $username"
        print_status "INFO" "Consider forcing logout before deletion"
    fi
    
    print_status "INFO" "Deleting user: $username"
    
    # Build userdel command
    local userdel_cmd="userdel"
    if [[ "$remove_home" == "true" ]]; then
        userdel_cmd="$userdel_cmd -r"
        print_status "INFO" "Removing home directory and mail spool"
    fi
    
    userdel_cmd="$userdel_cmd $username"
    
    # Execute user deletion
    eval $userdel_cmd
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "User deleted successfully: $username"
        log_message "INFO" "User deleted: $username"
        return 0
    else
        print_status "ERROR" "Failed to delete user: $username"
        log_message "ERROR" "Failed to delete user: $username"
        return 1
    fi
}

# Function to modify user
modify_user() {
    local username="$1"
    local shell="${2:-}"
    local home_dir="${3:-}"
    local primary_group="${4:-}"
    local additional_groups="${5:-}"
    local expiry_date="${6:-}"
    local comment="${7:-}"
    
    print_status "HEADER" "Modifying User Account"
    
    # Check if user exists
    if ! id "$username" >/dev/null 2>&1; then
        print_status "ERROR" "User does not exist: $username"
        return 1
    fi
    
    print_status "INFO" "Modifying user: $username"
    
    # Build usermod command
    local usermod_cmd="usermod"
    
    if [[ -n "$shell" ]]; then
        usermod_cmd="$usermod_cmd -s $shell"
        print_status "INFO" "Setting shell: $shell"
    fi
    
    if [[ -n "$home_dir" ]]; then
        usermod_cmd="$usermod_cmd -d $home_dir"
        print_status "INFO" "Setting home directory: $home_dir"
    fi
    
    if [[ -n "$primary_group" ]]; then
        usermod_cmd="$usermod_cmd -g $primary_group"
        print_status "INFO" "Setting primary group: $primary_group"
    fi
    
    if [[ -n "$additional_groups" ]]; then
        usermod_cmd="$usermod_cmd -G $additional_groups"
        print_status "INFO" "Setting additional groups: $additional_groups"
    fi
    
    if [[ -n "$expiry_date" ]]; then
        usermod_cmd="$usermod_cmd -e $expiry_date"
        print_status "INFO" "Setting expiry date: $expiry_date"
    fi
    
    if [[ -n "$comment" ]]; then
        usermod_cmd="$usermod_cmd -c '$comment'"
        print_status "INFO" "Setting comment: $comment"
    fi
    
    usermod_cmd="$usermod_cmd $username"
    
    # Execute user modification
    eval $usermod_cmd
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "User modified successfully: $username"
        log_message "INFO" "User modified: $username"
        return 0
    else
        print_status "ERROR" "Failed to modify user: $username"
        log_message "ERROR" "Failed to modify user: $username"
        return 1
    fi
}

# Function to list users
list_users() {
    local show_inactive="${1:-false}"
    local show_locked="${2:-false}"
    
    print_status "HEADER" "User Account Listing"
    
    if [[ "$show_inactive" == "true" ]]; then
        print_status "INFO" "Showing inactive users (no login in 90 days)"
    fi
    
    if [[ "$show_locked" == "true" ]]; then
        print_status "INFO" "Showing locked accounts"
    fi
    
    echo ""
    printf "%-15s %-10s %-15s %-20s %-15s %-10s\n" "Username" "UID" "Primary Group" "Home Directory" "Shell" "Status"
    echo "--------------------------------------------------------------------------------"
    
    # Get user list
    local users=($(cut -d: -f1 /etc/passwd | sort))
    
    for user in "${users[@]}"; do
        # Skip system users (UID < 1000)
        local uid=$(id -u "$user" 2>/dev/null)
        if [[ $uid -lt 1000 ]]; then
            continue
        fi
        
        # Get user information
        local primary_group=$(id -gn "$user" 2>/dev/null)
        local home_dir=$(eval echo ~$user)
        local shell=$(grep "^$user:" /etc/passwd | cut -d: -f7)
        
        # Check account status
        local status="Active"
        if [[ -f /etc/shadow ]]; then
            local locked=$(sudo passwd -S "$user" 2>/dev/null | awk '{print $2}')
            if [[ "$locked" == "L" ]]; then
                status="Locked"
            elif [[ "$locked" == "NP" ]]; then
                status="No Password"
            fi
        fi
        
        # Check if account is expired
        local expiry=$(chage -l "$user" 2>/dev/null | grep "Account expires" | awk '{print $4}')
        if [[ "$expiry" == "never" ]]; then
            expiry="Never"
        else
            local expiry_date=$(date -d "$expiry" +%s 2>/dev/null)
            local current_date=$(date +%s)
            if [[ $expiry_date -lt $current_date ]]; then
                status="Expired"
            fi
        fi
        
        # Check last login
        local last_login=$(lastlog -u "$user" 2>/dev/null | tail -1 | awk '{print $5, $6, $7}')
        if [[ "$last_login" == "**Never logged in**" ]]; then
            status="Never Logged In"
        fi
        
        printf "%-15s %-10s %-15s %-20s %-15s %-10s\n" "$user" "$uid" "$primary_group" "$home_dir" "$shell" "$status"
    done
}

# Function to lock user
lock_user() {
    local username="$1"
    
    print_status "HEADER" "Locking User Account"
    
    # Check if user exists
    if ! id "$username" >/dev/null 2>&1; then
        print_status "ERROR" "User does not exist: $username"
        return 1
    fi
    
    print_status "INFO" "Locking user account: $username"
    
    # Lock the account
    passwd -l "$username"
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "User account locked: $username"
        log_message "INFO" "User account locked: $username"
        return 0
    else
        print_status "ERROR" "Failed to lock user account: $username"
        log_message "ERROR" "Failed to lock user account: $username"
        return 1
    fi
}

# Function to unlock user
unlock_user() {
    local username="$1"
    
    print_status "HEADER" "Unlocking User Account"
    
    # Check if user exists
    if ! id "$username" >/dev/null 2>&1; then
        print_status "ERROR" "User does not exist: $username"
        return 1
    fi
    
    print_status "INFO" "Unlocking user account: $username"
    
    # Unlock the account
    passwd -u "$username"
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "User account unlocked: $username"
        log_message "INFO" "User account unlocked: $username"
        return 0
    else
        print_status "ERROR" "Failed to unlock user account: $username"
        log_message "ERROR" "Failed to unlock user account: $username"
        return 1
    fi
}

# Function to change password
change_password() {
    local username="$1"
    local new_password="${2:-}"
    
    print_status "HEADER" "Changing User Password"
    
    # Check if user exists
    if ! id "$username" >/dev/null 2>&1; then
        print_status "ERROR" "User does not exist: $username"
        return 1
    fi
    
    print_status "INFO" "Changing password for user: $username"
    
    if [[ -n "$new_password" ]]; then
        # Set password directly
        echo "$username:$new_password" | chpasswd
    else
        # Interactive password change
        passwd "$username"
    fi
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "Password changed successfully: $username"
        log_message "INFO" "Password changed for user: $username"
        return 0
    else
        print_status "ERROR" "Failed to change password: $username"
        log_message "ERROR" "Failed to change password for user: $username"
        return 1
    fi
}

# Function to set password expiry
set_password_expiry() {
    local username="$1"
    local days="${2:-$PASSWORD_EXPIRY_DAYS}"
    
    print_status "HEADER" "Setting Password Expiry"
    
    # Check if user exists
    if ! id "$username" >/dev/null 2>&1; then
        print_status "ERROR" "User does not exist: $username"
        return 1
    fi
    
    print_status "INFO" "Setting password expiry for user: $username"
    print_status "INFO" "Expiry days: $days"
    
    # Set password expiry
    chage -M "$days" "$username"
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "Password expiry set successfully: $username"
        log_message "INFO" "Password expiry set for user: $username ($days days)"
        return 0
    else
        print_status "ERROR" "Failed to set password expiry: $username"
        log_message "ERROR" "Failed to set password expiry for user: $username"
        return 1
    fi
}

# Function to show user groups
show_user_groups() {
    local username="$1"
    
    print_status "HEADER" "User Groups"
    
    # Check if user exists
    if ! id "$username" >/dev/null 2>&1; then
        print_status "ERROR" "User does not exist: $username"
        return 1
    fi
    
    print_status "INFO" "Groups for user: $username"
    
    # Get user groups
    local groups=$(id -Gn "$username" 2>/dev/null)
    local primary_group=$(id -gn "$username" 2>/dev/null)
    
    echo ""
    echo "Primary Group: $primary_group"
    echo "All Groups: $groups"
    echo ""
    
    # Show detailed group information
    echo "Detailed Group Information:"
    echo "------------------------"
    for group in $groups; do
        local gid=$(getent group "$group" | cut -d: -f3)
        local members=$(getent group "$group" | cut -d: -f4)
        echo "  $group (GID: $gid) - Members: $members"
    done
}

# Function to add user to group
add_user_to_group() {
    local username="$1"
    local group="$2"
    
    print_status "HEADER" "Adding User to Group"
    
    # Check if user exists
    if ! id "$username" >/dev/null 2>&1; then
        print_status "ERROR" "User does not exist: $username"
        return 1
    fi
    
    # Check if group exists
    if ! getent group "$group" >/dev/null 2>&1; then
        print_status "ERROR" "Group does not exist: $group"
        return 1
    fi
    
    # Check if user is already in group
    if id -Gn "$username" 2>/dev/null | grep -q "\b$group\b"; then
        print_status "WARNING" "User is already in group: $username -> $group"
        return 0
    fi
    
    print_status "INFO" "Adding user to group: $username -> $group"
    
    # Add user to group
    usermod -a -G "$group" "$username"
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "User added to group successfully: $username -> $group"
        log_message "INFO" "User added to group: $username -> $group"
        return 0
    else
        print_status "ERROR" "Failed to add user to group: $username -> $group"
        log_message "ERROR" "Failed to add user to group: $username -> $group"
        return 1
    fi
}

# Function to remove user from group
remove_user_from_group() {
    local username="$1"
    local group="$2"
    
    print_status "HEADER" "Removing User from Group"
    
    # Check if user exists
    if ! id "$username" >/dev/null 2>&1; then
        print_status "ERROR" "User does not exist: $username"
        return 1
    fi
    
    # Check if group exists
    if ! getent group "$group" >/dev/null 2>&1; then
        print_status "ERROR" "Group does not exist: $group"
        return 1
    fi
    
    # Check if user is in group
    if ! id -Gn "$username" 2>/dev/null | grep -q "\b$group\b"; then
        print_status "WARNING" "User is not in group: $username -> $group"
        return 0
    fi
    
    print_status "INFO" "Removing user from group: $username -> $group"
    
    # Remove user from group
    gpasswd -d "$username" "$group"
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "User removed from group successfully: $username -> $group"
        log_message "INFO" "User removed from group: $username -> $group"
        return 0
    else
        print_status "ERROR" "Failed to remove user from group: $username -> $group"
        log_message "ERROR" "Failed to remove user from group: $username -> $group"
        return 1
    fi
}

# Function to audit user accounts
audit_user_accounts() {
    print_status "HEADER" "User Account Audit"
    
    local total_users=0
    local active_users=0
    local locked_users=0
    local expired_users=0
    local never_logged_in=0
    local users_without_password=0
    
    echo ""
    echo "User Account Audit Report"
    echo "========================="
    echo ""
    
    # Get all users
    local users=($(cut -d: -f1 /etc/passwd | sort))
    
    for user in "${users[@]}"; do
        # Skip system users (UID < 1000)
        local uid=$(id -u "$user" 2>/dev/null)
        if [[ $uid -lt 1000 ]]; then
            continue
        fi
        
        ((total_users++))
        
        # Check account status
        local status=$(passwd -S "$user" 2>/dev/null | awk '{print $2}')
        local last_login=$(lastlog -u "$user" 2>/dev/null | tail -1)
        
        case $status in
            "L")
                ((locked_users++))
                echo "  [LOCKED] $user"
                ;;
            "NP")
                ((users_without_password++))
                echo "  [NO PASSWORD] $user"
                ;;
            *)
                ((active_users++))
                ;;
        esac
        
        # Check for never logged in
        if [[ "$last_login" == *"**Never logged in**"* ]]; then
            ((never_logged_in++))
            echo "  [NEVER LOGGED IN] $user"
        fi
        
        # Check for expired accounts
        local expiry=$(chage -l "$user" 2>/dev/null | grep "Account expires" | awk '{print $4}')
        if [[ "$expiry" != "never" ]]; then
            local expiry_date=$(date -d "$expiry" +%s 2>/dev/null)
            local current_date=$(date +%s)
            if [[ $expiry_date -lt $current_date ]]; then
                ((expired_users++))
                echo "  [EXPIRED] $user"
            fi
        fi
    done
    
    echo ""
    echo "Summary:"
    echo "  Total Users: $total_users"
    echo "  Active Users: $active_users"
    echo "  Locked Users: $locked_users"
    echo "  Expired Users: $expired_users"
    echo "  Never Logged In: $never_logged_in"
    echo "  Users Without Password: $users_without_password"
    echo ""
    
    log_message "INFO" "User audit completed - Total: $total_users, Active: $active_users, Locked: $locked_users"
}

# Function to cleanup inactive accounts
cleanup_inactive_accounts() {
    local days="${1:-90}"
    
    print_status "HEADER" "Cleaning Up Inactive Accounts"
    
    print_status "INFO" "Looking for accounts inactive for $days days"
    
    local removed_count=0
    
    # Get all users
    local users=($(cut -d: -f1 /etc/passwd | sort))
    
    for user in "${users[@]}"; do
        # Skip system users (UID < 1000)
        local uid=$(id -u "$user" 2>/dev/null)
        if [[ $uid -lt 1000 ]]; then
            continue
        fi
        
        # Check last login
        local last_login=$(lastlog -u "$user" 2>/dev/null | tail -1)
        
        if [[ "$last_login" != *"**Never logged in**"* ]]; then
            # Extract last login date
            local login_date=$(echo "$last_login" | awk '{print $5, $6, $7}')
            local login_timestamp=$(date -d "$login_date" +%s 2>/dev/null)
            local current_timestamp=$(date +%s)
            local days_since_login=$(( (current_timestamp - login_timestamp) / 86400 ))
            
            if [[ $days_since_login -gt $days ]]; then
                print_status "WARNING" "Inactive user found: $user (last login: $login_date)"
                print_status "INFO" "Days since last login: $days_since_login"
                
                # Lock the account instead of deleting
                passwd -l "$user" 2>/dev/null
                if [[ $? -eq 0 ]]; then
                    print_status "SUCCESS" "Locked inactive account: $user"
                    ((removed_count++))
                    log_message "INFO" "Locked inactive account: $user (inactive for $days_since_login days)"
                fi
            fi
        fi
    done
    
    if [[ $removed_count -gt 0 ]]; then
        print_status "SUCCESS" "Cleanup completed - locked $removed_count inactive account(s)"
    else
        print_status "INFO" "No inactive accounts found"
    fi
}

# Main function
main() {
    local command=""
    local args=()
    local quiet_mode=false
    local force_mode=false
    
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
            -q|--quiet)
                quiet_mode=true
                shift
                ;;
            -f|--force)
                force_mode=true
                shift
                ;;
            create|delete|modify|list|lock|unlock|password|expire|groups|addgroup|removegroup|audit|cleanup)
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
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/user-management.log"
    log_message "INFO" "Script started with command: $command"
    
    # Show header
    if [[ "$quiet_mode" == false ]]; then
        show_header
    fi
    
    # Execute command
    case $command in
        create)
            if [[ ${#args[@]} -lt 1 ]]; then
                print_status "ERROR" "create command requires username"
                exit 1
            fi
            create_user "${args[0]}" "${args[1]}" "${args[2]}" "${args[3]}" "${args[4]}" "${args[5]}" "${args[6]}"
            ;;
        delete)
            if [[ ${#args[@]} -lt 1 ]]; then
                print_status "ERROR" "delete command requires username"
                exit 1
            fi
            delete_user "${args[0]}" "${args[1]}"
            ;;
        modify)
            if [[ ${#args[@]} -lt 1 ]]; then
                print_status "ERROR" "modify command requires username"
                exit 1
            fi
            modify_user "${args[0]}" "${args[1]}" "${args[2]}" "${args[3]}" "${args[4]}" "${args[5]}" "${args[6]}"
            ;;
        list)
            list_users "${args[0]}" "${args[1]}"
            ;;
        lock)
            if [[ ${#args[@]} -lt 1 ]]; then
                print_status "ERROR" "lock command requires username"
                exit 1
            fi
            lock_user "${args[0]}"
            ;;
        unlock)
            if [[ ${#args[@]} -lt 1 ]]; then
                print_status "ERROR" "unlock command requires username"
                exit 1
            fi
            unlock_user "${args[0]}"
            ;;
        password)
            if [[ ${#args[@]} -lt 1 ]]; then
                print_status "ERROR" "password command requires username"
                exit 1
            fi
            change_password "${args[0]}" "${args[1]}"
            ;;
        expire)
            if [[ ${#args[@]} -lt 1 ]]; then
                print_status "ERROR" "expire command requires username"
                exit 1
            fi
            set_password_expiry "${args[0]}" "${args[1]}"
            ;;
        groups)
            if [[ ${#args[@]} -lt 1 ]]; then
                print_status "ERROR" "groups command requires username"
                exit 1
            fi
            show_user_groups "${args[0]}"
            ;;
        addgroup)
            if [[ ${#args[@]} -lt 2 ]]; then
                print_status "ERROR" "addgroup command requires username and group"
                exit 1
            fi
            add_user_to_group "${args[0]}" "${args[1]}"
            ;;
        removegroup)
            if [[ ${#args[@]} -lt 2 ]]; then
                print_status "ERROR" "removegroup command requires username and group"
                exit 1
            fi
            remove_user_from_group "${args[0]}" "${args[1]}"
            ;;
        audit)
            audit_user_accounts
            ;;
        cleanup)
            cleanup_inactive_accounts "${args[0]}"
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