#!/bin/bash

# =============================================================================
# Backup Manager Script
# =============================================================================
# Purpose: Comprehensive backup management and automation
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
SCRIPT_NAME="backup-manager.sh"
VERSION="1.0.0"
CONFIG_FILE="/etc/backup-manager.conf"
LOG_FILE="/var/log/backup-manager.log"
BACKUP_ROOT="/var/backups"
RETENTION_DAYS=30
COMPRESSION_LEVEL=6

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
    echo "║                    Backup Manager Script                     ║"
    echo "║                        Version $VERSION                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to display help
show_help() {
    echo "Usage: $SCRIPT_NAME [OPTIONS] [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  create [SOURCE] [DESTINATION]  Create a new backup"
    echo "  list                           List existing backups"
    echo "  restore [BACKUP] [DESTINATION] Restore from backup"
    echo "  verify [BACKUP]                Verify backup integrity"
    echo "  cleanup                        Remove old backups"
    echo "  status                         Show backup status"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -v, --version       Show version information"
    echo "  -c, --config FILE   Use specified config file"
    echo "  -l, --log FILE      Use specified log file"
    echo "  -q, --quiet         Suppress verbose output"
    echo "  -f, --force         Force operation without confirmation"
    echo "  -r, --retention N   Set retention days (default: $RETENTION_DAYS)"
    echo "  -z, --compression N Set compression level (1-9, default: $COMPRESSION_LEVEL)"
    echo ""
    echo "Examples:"
    echo "  $SCRIPT_NAME create /home/user /backups/user"
    echo "  $SCRIPT_NAME list"
    echo "  $SCRIPT_NAME restore /backups/user-20231201.tar.gz /home/user"
    echo "  $SCRIPT_NAME cleanup -r 7"
}

# Function to create backup
create_backup() {
    local source="$1"
    local destination="$2"
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local backup_name="backup-$(basename "$source")-$timestamp.tar.gz"
    local backup_path="$destination/$backup_name"
    
    print_status "HEADER" "Creating Backup"
    
    # Validate source
    if [[ ! -e "$source" ]]; then
        print_status "ERROR" "Source does not exist: $source"
        log_message "ERROR" "Backup failed - source not found: $source"
        return 1
    fi
    
    # Create destination directory if it doesn't exist
    mkdir -p "$destination" || {
        print_status "ERROR" "Cannot create destination directory: $destination"
        log_message "ERROR" "Backup failed - cannot create destination: $destination"
        return 1
    }
    
    # Check available space
    local source_size=$(du -sb "$source" 2>/dev/null | cut -f1)
    local available_space=$(df "$destination" | awk 'NR==2 {print $4}')
    
    if [[ $source_size -gt $available_space ]]; then
        print_status "WARNING" "Insufficient space for backup"
        print_status "INFO" "Source size: $(numfmt --to=iec $source_size)"
        print_status "INFO" "Available space: $(numfmt --to=iec $available_space)"
        log_message "WARNING" "Insufficient space for backup"
    fi
    
    print_status "INFO" "Creating backup: $backup_path"
    print_status "INFO" "Source: $source"
    print_status "INFO" "Compression level: $COMPRESSION_LEVEL"
    
    # Create backup with progress
    if command_exists pv; then
        tar -czf - "$source" | pv | gzip -$COMPRESSION_LEVEL > "$backup_path"
    else
        tar -czf "$backup_path" -C "$(dirname "$source")" "$(basename "$source")"
    fi
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "Backup created successfully"
        
        # Calculate backup size
        local backup_size=$(stat -c%s "$backup_path" 2>/dev/null || echo "0")
        print_status "INFO" "Backup size: $(numfmt --to=iec $backup_size)"
        
        # Create checksum
        sha256sum "$backup_path" > "$backup_path.sha256"
        
        log_message "INFO" "Backup created: $backup_path (size: $backup_size bytes)"
        return 0
    else
        print_status "ERROR" "Backup creation failed"
        log_message "ERROR" "Backup creation failed: $backup_path"
        return 1
    fi
}

# Function to list backups
list_backups() {
    print_status "HEADER" "Backup Listing"
    
    if [[ ! -d "$BACKUP_ROOT" ]]; then
        print_status "WARNING" "Backup directory does not exist: $BACKUP_ROOT"
        return 1
    fi
    
    echo "Backup Directory: $BACKUP_ROOT"
    echo ""
    
    # Find all backup files
    local backups=($(find "$BACKUP_ROOT" -name "*.tar.gz" -type f 2>/dev/null))
    
    if [[ ${#backups[@]} -eq 0 ]]; then
        print_status "INFO" "No backups found"
        return 0
    fi
    
    echo "Found ${#backups[@]} backup(s):"
    echo ""
    printf "%-50s %-15s %-20s %-10s\n" "Backup File" "Size" "Date" "Status"
    echo "--------------------------------------------------------------------------------"
    
    for backup in "${backups[@]}"; do
        local filename=$(basename "$backup")
        local size=$(stat -c%s "$backup" 2>/dev/null || echo "0")
        local date=$(stat -c%y "$backup" 2>/dev/null | cut -d' ' -f1)
        local checksum_file="$backup.sha256"
        
        local status="OK"
        if [[ -f "$checksum_file" ]]; then
            if sha256sum -c "$checksum_file" >/dev/null 2>&1; then
                status="✓"
            else
                status="✗"
            fi
        else
            status="?"
        fi
        
        printf "%-50s %-15s %-20s %-10s\n" "$filename" "$(numfmt --to=iec $size)" "$date" "$status"
    done
}

# Function to restore backup
restore_backup() {
    local backup_file="$1"
    local destination="$2"
    
    print_status "HEADER" "Restoring Backup"
    
    # Validate backup file
    if [[ ! -f "$backup_file" ]]; then
        print_status "ERROR" "Backup file not found: $backup_file"
        log_message "ERROR" "Restore failed - backup not found: $backup_file"
        return 1
    fi
    
    # Check if backup is compressed
    if [[ "$backup_file" != *.tar.gz ]]; then
        print_status "ERROR" "Invalid backup format. Expected .tar.gz file"
        return 1
    fi
    
    # Verify checksum if available
    local checksum_file="$backup_file.sha256"
    if [[ -f "$checksum_file" ]]; then
        print_status "INFO" "Verifying backup integrity..."
        if ! sha256sum -c "$checksum_file" >/dev/null 2>&1; then
            print_status "ERROR" "Backup integrity check failed"
            log_message "ERROR" "Restore failed - integrity check failed: $backup_file"
            return 1
        fi
        print_status "SUCCESS" "Backup integrity verified"
    else
        print_status "WARNING" "No checksum file found - skipping integrity check"
    fi
    
    # Create destination directory
    mkdir -p "$destination" || {
        print_status "ERROR" "Cannot create destination directory: $destination"
        return 1
    }
    
    print_status "INFO" "Restoring from: $backup_file"
    print_status "INFO" "Destination: $destination"
    
    # Restore backup
    if command_exists pv; then
        pv "$backup_file" | tar -xzf - -C "$destination"
    else
        tar -xzf "$backup_file" -C "$destination"
    fi
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "Backup restored successfully"
        log_message "INFO" "Backup restored: $backup_file -> $destination"
        return 0
    else
        print_status "ERROR" "Backup restoration failed"
        log_message "ERROR" "Backup restoration failed: $backup_file"
        return 1
    fi
}

# Function to verify backup
verify_backup() {
    local backup_file="$1"
    
    print_status "HEADER" "Verifying Backup"
    
    if [[ ! -f "$backup_file" ]]; then
        print_status "ERROR" "Backup file not found: $backup_file"
        return 1
    fi
    
    # Check if file is readable
    if [[ ! -r "$backup_file" ]]; then
        print_status "ERROR" "Cannot read backup file: $backup_file"
        return 1
    fi
    
    # Check file size
    local size=$(stat -c%s "$backup_file" 2>/dev/null || echo "0")
    if [[ $size -eq 0 ]]; then
        print_status "ERROR" "Backup file is empty: $backup_file"
        return 1
    fi
    
    print_status "INFO" "Backup file size: $(numfmt --to=iec $size)"
    
    # Verify checksum if available
    local checksum_file="$backup_file.sha256"
    if [[ -f "$checksum_file" ]]; then
        print_status "INFO" "Verifying checksum..."
        if sha256sum -c "$checksum_file" >/dev/null 2>&1; then
            print_status "SUCCESS" "Checksum verification passed"
        else
            print_status "ERROR" "Checksum verification failed"
            return 1
        fi
    else
        print_status "WARNING" "No checksum file found"
    fi
    
    # Test archive integrity
    print_status "INFO" "Testing archive integrity..."
    if tar -tzf "$backup_file" >/dev/null 2>&1; then
        print_status "SUCCESS" "Archive integrity verified"
        
        # List contents
        local file_count=$(tar -tzf "$backup_file" | wc -l)
        print_status "INFO" "Archive contains $file_count files/directories"
        
        return 0
    else
        print_status "ERROR" "Archive integrity check failed"
        return 1
    fi
}

# Function to cleanup old backups
cleanup_backups() {
    print_status "HEADER" "Cleaning Up Old Backups"
    
    if [[ ! -d "$BACKUP_ROOT" ]]; then
        print_status "WARNING" "Backup directory does not exist: $BACKUP_ROOT"
        return 1
    fi
    
    print_status "INFO" "Removing backups older than $RETENTION_DAYS days"
    
    local removed_count=0
    local freed_space=0
    
    # Find old backup files
    while IFS= read -r -d '' file; do
        local file_age=$(( ($(date +%s) - $(stat -c%Y "$file")) / 86400 ))
        
        if [[ $file_age -gt $RETENTION_DAYS ]]; then
            local file_size=$(stat -c%s "$file" 2>/dev/null || echo "0")
            
            print_status "INFO" "Removing old backup: $(basename "$file") (age: ${file_age} days)"
            
            # Remove backup and checksum file
            rm -f "$file" "$file.sha256"
            
            if [[ $? -eq 0 ]]; then
                ((removed_count++))
                ((freed_space += file_size))
                log_message "INFO" "Removed old backup: $file"
            else
                print_status "ERROR" "Failed to remove: $file"
                log_message "ERROR" "Failed to remove old backup: $file"
            fi
        fi
    done < <(find "$BACKUP_ROOT" -name "*.tar.gz" -type f -print0 2>/dev/null)
    
    if [[ $removed_count -gt 0 ]]; then
        print_status "SUCCESS" "Cleanup completed"
        print_status "INFO" "Removed $removed_count backup(s)"
        print_status "INFO" "Freed space: $(numfmt --to=iec $freed_space)"
        log_message "INFO" "Cleanup completed - removed $removed_count backups, freed $freed_space bytes"
    else
        print_status "INFO" "No old backups found to remove"
    fi
}

# Function to show backup status
show_backup_status() {
    print_status "HEADER" "Backup Status"
    
    echo "Configuration:"
    echo "  Backup Root: $BACKUP_ROOT"
    echo "  Retention Days: $RETENTION_DAYS"
    echo "  Compression Level: $COMPRESSION_LEVEL"
    echo "  Log File: $LOG_FILE"
    echo ""
    
    # Check backup directory
    if [[ -d "$BACKUP_ROOT" ]]; then
        local total_size=$(du -sb "$BACKUP_ROOT" 2>/dev/null | cut -f1 || echo "0")
        local backup_count=$(find "$BACKUP_ROOT" -name "*.tar.gz" -type f 2>/dev/null | wc -l)
        
        echo "Backup Directory Status:"
        echo "  Directory: $BACKUP_ROOT"
        echo "  Total Size: $(numfmt --to=iec $total_size)"
        echo "  Backup Count: $backup_count"
        echo "  Available Space: $(df "$BACKUP_ROOT" | awk 'NR==2 {print $4}')"
        echo ""
        
        # Show recent backups
        if [[ $backup_count -gt 0 ]]; then
            echo "Recent Backups:"
            find "$BACKUP_ROOT" -name "*.tar.gz" -type f -printf "%T@ %p\n" 2>/dev/null | \
                sort -nr | head -5 | while read timestamp file; do
                local date=$(date -d "@$timestamp" '+%Y-%m-%d %H:%M:%S')
                local size=$(stat -c%s "$file" 2>/dev/null || echo "0")
                echo "  $(basename "$file") - $date ($(numfmt --to=iec $size))"
            done
        fi
    else
        print_status "WARNING" "Backup directory does not exist: $BACKUP_ROOT"
    fi
}

# Main function
main() {
    local command=""
    local args=()
    local quiet_mode=false
    local force_mode=false
    
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
            -r|--retention)
                RETENTION_DAYS="$2"
                shift 2
                ;;
            -z|--compression)
                COMPRESSION_LEVEL="$2"
                shift 2
                ;;
            create|list|restore|verify|cleanup|status)
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
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/backup-manager.log"
    log_message "INFO" "Script started with command: $command"
    
    # Show header
    if [[ "$quiet_mode" == false ]]; then
        show_header
    fi
    
    # Execute command
    case $command in
        create)
            if [[ ${#args[@]} -lt 2 ]]; then
                print_status "ERROR" "create command requires source and destination"
                exit 1
            fi
            create_backup "${args[0]}" "${args[1]}"
            ;;
        list)
            list_backups
            ;;
        restore)
            if [[ ${#args[@]} -lt 2 ]]; then
                print_status "ERROR" "restore command requires backup file and destination"
                exit 1
            fi
            restore_backup "${args[0]}" "${args[1]}"
            ;;
        verify)
            if [[ ${#args[@]} -lt 1 ]]; then
                print_status "ERROR" "verify command requires backup file"
                exit 1
            fi
            verify_backup "${args[0]}"
            ;;
        cleanup)
            cleanup_backups
            ;;
        status)
            show_backup_status
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