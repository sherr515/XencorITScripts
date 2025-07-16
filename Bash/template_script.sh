#!/bin/bash
# =============================================================================
# Script Name: template_script.sh
# Description: Template for Bash scripts with standard structure
# Author: [Your Name]
# Date: $(date +%Y-%m-%d)
# Version: 1.0
# =============================================================================

# =============================================================================
# Configuration
# =============================================================================

# Set strict error handling
set -euo pipefail

# Colors for output
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly RED='\033[0;31m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m' # No Color

# Script configuration
readonly SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_FILE="${SCRIPT_DIR}/script.log"

# =============================================================================
# Functions
# =============================================================================

print_color() {
    local message="$1"
    local color="${2:-$NC}"
    echo -e "${color}${message}${NC}"
}

log_message() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

check_prerequisites() {
    print_color "Checking prerequisites..." "$CYAN"
    
    # Add your prerequisite checks here
    # Example: Check if a command exists
    # if ! command -v required_command &> /dev/null; then
    #     print_color "Required command 'required_command' is not installed" "$RED"
    #     return 1
    # fi
    
    # Example: Check if a file exists
    # if [[ ! -f "required_file" ]]; then
    #     print_color "Required file 'required_file' does not exist" "$RED"
    #     return 1
    # fi
    
    print_color "✓ Prerequisites check passed" "$GREEN"
    return 0
}

main_function() {
    local input_parameter="$1"
    
    print_color "Processing: $input_parameter" "$CYAN"
    
    # Add your main logic here
    
    print_color "Processing completed successfully!" "$GREEN"
}

validate_parameters() {
    local parameter_name="$1"
    
    if [[ -z "$parameter_name" ]]; then
        print_color "Parameter name cannot be empty" "$RED"
        return 1
    fi
    
    return 0
}

show_usage() {
    cat << EOF
Usage: $SCRIPT_NAME [OPTIONS]

Description:
    Brief description of what the script does.

Options:
    -p, --parameter-name VALUE    Description of the parameter (default: default_value)
    -v, --verbose                Enable verbose output
    -h, --help                   Show this help message

Examples:
    $SCRIPT_NAME --parameter-name "value"
    $SCRIPT_NAME --verbose

EOF
}

# =============================================================================
# Main Execution
# =============================================================================

main() {
    local parameter_name="default_value"
    local verbose=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -p|--parameter-name)
                parameter_name="$2"
                shift 2
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                print_color "Unknown option: $1" "$RED"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Initialize logging
    log_message "INFO" "Script started"
    
    try {
        print_color "Script started at $(date)" "$CYAN"
        print_color "================================================" "$CYAN"
        
        # Check prerequisites
        if ! check_prerequisites; then
            exit 1
        fi
        
        # Validate parameters
        if ! validate_parameters "$parameter_name"; then
            exit 1
        fi
        
        # Execute main function
        main_function "$parameter_name"
        
        print_color "Script completed successfully!" "$GREEN"
        log_message "INFO" "Script completed successfully"
        
    } catch {
        local exit_code=$?
        print_color "Script failed with exit code: $exit_code" "$RED"
        log_message "ERROR" "Script failed with exit code: $exit_code"
        exit $exit_code
    } finally {
        print_color "Script ended at $(date)" "$CYAN"
        log_message "INFO" "Script ended"
    }
}

# Trap to handle script interruption
trap 'print_color "Script interrupted by user" "$YELLOW"; exit 1' INT TERM

# Execute main function
main "$@" 