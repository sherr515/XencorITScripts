#!/bin/bash

# =============================================================================
# Docker Container Manager Script
# =============================================================================
# Purpose: Comprehensive Docker container management and administration
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
SCRIPT_NAME="container-manager.sh"
VERSION="1.0.0"
CONFIG_FILE="/etc/container-manager.conf"
LOG_FILE="/var/log/container-manager.log"
DOCKER_SOCKET="/var/run/docker.sock"
BACKUP_DIR="/var/backups/containers"
RETENTION_DAYS=30

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

# Function to check if Docker is available
check_docker() {
    if ! command_exists docker; then
        print_status "ERROR" "Docker is not installed or not in PATH"
        return 1
    fi
    
    if ! docker info >/dev/null 2>&1; then
        print_status "ERROR" "Docker daemon is not running or not accessible"
        return 1
    fi
    
    return 0
}

# Function to display script header
show_header() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                Docker Container Manager                      ║"
    echo "║                        Version $VERSION                        ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Function to display help
show_help() {
    echo "Usage: $SCRIPT_NAME [OPTIONS] [COMMAND]"
    echo ""
    echo "Commands:"
    echo "  list [OPTIONS]               List containers"
    echo "  start CONTAINER              Start a container"
    echo "  stop CONTAINER               Stop a container"
    echo "  restart CONTAINER            Restart a container"
    echo "  remove CONTAINER             Remove a container"
    echo "  logs CONTAINER [LINES]       Show container logs"
    echo "  exec CONTAINER COMMAND       Execute command in container"
    echo "  inspect CONTAINER            Inspect container details"
    echo "  stats [CONTAINER]            Show container statistics"
    echo "  backup CONTAINER [PATH]      Backup container data"
    echo "  restore CONTAINER BACKUP     Restore container from backup"
    echo "  cleanup [DAYS]               Clean up old containers/images"
    echo "  health [CONTAINER]           Check container health"
    echo "  monitor [DURATION]           Monitor containers"
    echo "  report                       Generate container report"
    echo ""
    echo "Options:"
    echo "  -h, --help          Show this help message"
    echo "  -v, --version       Show version information"
    echo "  -c, --config FILE   Use specified config file"
    echo "  -l, --log FILE      Use specified log file"
    echo "  -q, --quiet         Suppress verbose output"
    echo "  -f, --force         Force operation without confirmation"
    echo "  -a, --all           Apply to all containers"
    echo "  -r, --running       Show only running containers"
    echo "  -s, --stopped       Show only stopped containers"
    echo ""
    echo "Examples:"
    echo "  $SCRIPT_NAME list                    # List all containers"
    echo "  $SCRIPT_NAME start myapp             # Start container"
    echo "  $SCRIPT_NAME logs myapp 100          # Show last 100 log lines"
    echo "  $SCRIPT_NAME backup myapp            # Backup container"
    echo "  $SCRIPT_NAME cleanup 7               # Clean up containers older than 7 days"
}

# Function to list containers
list_containers() {
    local show_running="${1:-false}"
    local show_stopped="${2:-false}"
    
    print_status "HEADER" "Container Listing"
    
    if ! check_docker; then
        return 1
    fi
    
    local filter=""
    if [[ "$show_running" == "true" ]]; then
        filter="--filter status=running"
    elif [[ "$show_stopped" == "true" ]]; then
        filter="--filter status=exited"
    fi
    
    echo "Containers:"
    echo ""
    
    # Get container list
    local containers=$(docker ps -a --format "table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}" $filter 2>/dev/null)
    
    if [[ -n "$containers" ]]; then
        echo "$containers"
    else
        print_status "INFO" "No containers found"
    fi
    
    # Show summary
    local total_containers=$(docker ps -aq | wc -l)
    local running_containers=$(docker ps -q | wc -l)
    local stopped_containers=$((total_containers - running_containers))
    
    echo ""
    echo "Summary:"
    echo "  Total Containers: $total_containers"
    echo "  Running: $running_containers"
    echo "  Stopped: $stopped_containers"
}

# Function to start container
start_container() {
    local container="$1"
    
    print_status "HEADER" "Starting Container"
    
    if ! check_docker; then
        return 1
    fi
    
    # Check if container exists
    if ! docker ps -aq --filter "name=^$container$" | grep -q .; then
        print_status "ERROR" "Container does not exist: $container"
        return 1
    fi
    
    # Check if container is already running
    if docker ps -q --filter "name=^$container$" --filter "status=running" | grep -q .; then
        print_status "WARNING" "Container is already running: $container"
        return 0
    fi
    
    print_status "INFO" "Starting container: $container"
    
    # Start container
    docker start "$container"
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "Container started successfully: $container"
        log_message "INFO" "Container started: $container"
        return 0
    else
        print_status "ERROR" "Failed to start container: $container"
        log_message "ERROR" "Failed to start container: $container"
        return 1
    fi
}

# Function to stop container
stop_container() {
    local container="$1"
    local timeout="${2:-10}"
    
    print_status "HEADER" "Stopping Container"
    
    if ! check_docker; then
        return 1
    fi
    
    # Check if container exists
    if ! docker ps -aq --filter "name=^$container$" | grep -q .; then
        print_status "ERROR" "Container does not exist: $container"
        return 1
    fi
    
    # Check if container is running
    if ! docker ps -q --filter "name=^$container$" --filter "status=running" | grep -q .; then
        print_status "WARNING" "Container is not running: $container"
        return 0
    fi
    
    print_status "INFO" "Stopping container: $container (timeout: ${timeout}s)"
    
    # Stop container
    docker stop -t "$timeout" "$container"
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "Container stopped successfully: $container"
        log_message "INFO" "Container stopped: $container"
        return 0
    else
        print_status "ERROR" "Failed to stop container: $container"
        log_message "ERROR" "Failed to stop container: $container"
        return 1
    fi
}

# Function to restart container
restart_container() {
    local container="$1"
    local timeout="${2:-10}"
    
    print_status "HEADER" "Restarting Container"
    
    if ! check_docker; then
        return 1
    fi
    
    # Check if container exists
    if ! docker ps -aq --filter "name=^$container$" | grep -q .; then
        print_status "ERROR" "Container does not exist: $container"
        return 1
    fi
    
    print_status "INFO" "Restarting container: $container"
    
    # Restart container
    docker restart -t "$timeout" "$container"
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "Container restarted successfully: $container"
        log_message "INFO" "Container restarted: $container"
        return 0
    else
        print_status "ERROR" "Failed to restart container: $container"
        log_message "ERROR" "Failed to restart container: $container"
        return 1
    fi
}

# Function to remove container
remove_container() {
    local container="$1"
    local force="${2:-false}"
    
    print_status "HEADER" "Removing Container"
    
    if ! check_docker; then
        return 1
    fi
    
    # Check if container exists
    if ! docker ps -aq --filter "name=^$container$" | grep -q .; then
        print_status "ERROR" "Container does not exist: $container"
        return 1
    fi
    
    # Check if container is running
    if docker ps -q --filter "name=^$container$" --filter "status=running" | grep -q .; then
        if [[ "$force" != "true" ]]; then
            print_status "WARNING" "Container is running. Use --force to remove running container"
            return 1
        fi
        print_status "WARNING" "Removing running container: $container"
    fi
    
    print_status "INFO" "Removing container: $container"
    
    # Remove container
    docker rm -f "$container"
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "Container removed successfully: $container"
        log_message "INFO" "Container removed: $container"
        return 0
    else
        print_status "ERROR" "Failed to remove container: $container"
        log_message "ERROR" "Failed to remove container: $container"
        return 1
    fi
}

# Function to show container logs
show_logs() {
    local container="$1"
    local lines="${2:-50}"
    
    print_status "HEADER" "Container Logs"
    
    if ! check_docker; then
        return 1
    fi
    
    # Check if container exists
    if ! docker ps -aq --filter "name=^$container$" | grep -q .; then
        print_status "ERROR" "Container does not exist: $container"
        return 1
    fi
    
    print_status "INFO" "Showing logs for container: $container (last $lines lines)"
    
    # Show logs
    docker logs --tail "$lines" "$container" 2>/dev/null
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "Logs displayed successfully"
    else
        print_status "ERROR" "Failed to display logs"
    fi
}

# Function to execute command in container
exec_command() {
    local container="$1"
    local command="${2:-/bin/bash}"
    
    print_status "HEADER" "Executing Command in Container"
    
    if ! check_docker; then
        return 1
    fi
    
    # Check if container exists
    if ! docker ps -aq --filter "name=^$container$" | grep -q .; then
        print_status "ERROR" "Container does not exist: $container"
        return 1
    fi
    
    # Check if container is running
    if ! docker ps -q --filter "name=^$container$" --filter "status=running" | grep -q .; then
        print_status "ERROR" "Container is not running: $container"
        return 1
    fi
    
    print_status "INFO" "Executing command in container: $container"
    print_status "INFO" "Command: $command"
    
    # Execute command
    docker exec -it "$container" $command
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "Command executed successfully"
        log_message "INFO" "Command executed in container: $container - $command"
    else
        print_status "ERROR" "Failed to execute command"
        log_message "ERROR" "Failed to execute command in container: $container - $command"
    fi
}

# Function to inspect container
inspect_container() {
    local container="$1"
    
    print_status "HEADER" "Container Inspection"
    
    if ! check_docker; then
        return 1
    fi
    
    # Check if container exists
    if ! docker ps -aq --filter "name=^$container$" | grep -q .; then
        print_status "ERROR" "Container does not exist: $container"
        return 1
    fi
    
    print_status "INFO" "Inspecting container: $container"
    
    # Get container details
    local container_id=$(docker ps -aq --filter "name=^$container$" | head -1)
    
    echo "Container Information:"
    echo "====================="
    echo ""
    
    # Basic info
    echo "Basic Information:"
    docker inspect --format "Name: {{.Name}}
Image: {{.Config.Image}}
Status: {{.State.Status}}
Created: {{.Created}}
Started: {{.State.StartedAt}}
Finished: {{.State.FinishedAt}}
Exit Code: {{.State.ExitCode}}
" "$container_id"
    
    echo ""
    echo "Network Information:"
    docker inspect --format "IP Address: {{.NetworkSettings.IPAddress}}
Gateway: {{.NetworkSettings.Gateway}}
Ports: {{.NetworkSettings.Ports}}
" "$container_id"
    
    echo ""
    echo "Resource Limits:"
    docker inspect --format "Memory: {{.HostConfig.Memory}}
CPU Shares: {{.HostConfig.CpuShares}}
CPU Period: {{.HostConfig.CpuPeriod}}
CPU Quota: {{.HostConfig.CpuQuota}}
" "$container_id"
    
    echo ""
    echo "Mounts:"
    docker inspect --format "{{range .Mounts}}{{.Source}} -> {{.Destination}} ({{.Type}})
{{end}}" "$container_id"
}

# Function to show container statistics
show_stats() {
    local container="${1:-}"
    
    print_status "HEADER" "Container Statistics"
    
    if ! check_docker; then
        return 1
    fi
    
    if [[ -n "$container" ]]; then
        # Check if container exists
        if ! docker ps -aq --filter "name=^$container$" | grep -q .; then
            print_status "ERROR" "Container does not exist: $container"
            return 1
        fi
        
        print_status "INFO" "Showing statistics for container: $container"
        docker stats "$container" --no-stream
    else
        print_status "INFO" "Showing statistics for all running containers"
        docker stats --no-stream
    fi
}

# Function to backup container
backup_container() {
    local container="$1"
    local backup_path="${2:-$BACKUP_DIR}"
    
    print_status "HEADER" "Backing Up Container"
    
    if ! check_docker; then
        return 1
    fi
    
    # Check if container exists
    if ! docker ps -aq --filter "name=^$container$" | grep -q .; then
        print_status "ERROR" "Container does not exist: $container"
        return 1
    fi
    
    # Create backup directory
    mkdir -p "$backup_path" || {
        print_status "ERROR" "Cannot create backup directory: $backup_path"
        return 1
    }
    
    local timestamp=$(date +%Y%m%d-%H%M%S)
    local backup_file="$backup_path/${container}-${timestamp}.tar"
    
    print_status "INFO" "Creating backup: $backup_file"
    
    # Create backup
    docker export "$container" > "$backup_file"
    
    if [[ $? -eq 0 ]]; then
        local backup_size=$(stat -c%s "$backup_file" 2>/dev/null || echo "0")
        print_status "SUCCESS" "Backup created successfully: $backup_file"
        print_status "INFO" "Backup size: $(numfmt --to=iec $backup_size)"
        log_message "INFO" "Container backup created: $container -> $backup_file"
        return 0
    else
        print_status "ERROR" "Failed to create backup: $container"
        log_message "ERROR" "Failed to create container backup: $container"
        return 1
    fi
}

# Function to restore container
restore_container() {
    local container="$1"
    local backup_file="$2"
    local image="${3:-}"
    
    print_status "HEADER" "Restoring Container"
    
    if ! check_docker; then
        return 1
    fi
    
    # Check if backup file exists
    if [[ ! -f "$backup_file" ]]; then
        print_status "ERROR" "Backup file does not exist: $backup_file"
        return 1
    fi
    
    # Check if container already exists
    if docker ps -aq --filter "name=^$container$" | grep -q .; then
        print_status "ERROR" "Container already exists: $container"
        return 1
    fi
    
    print_status "INFO" "Restoring container from backup: $backup_file"
    
    # Import backup
    local image_name="${image:-$container-restored}"
    docker import "$backup_file" "$image_name"
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "Container restored successfully: $container"
        print_status "INFO" "Image created: $image_name"
        log_message "INFO" "Container restored from backup: $backup_file -> $container"
        return 0
    else
        print_status "ERROR" "Failed to restore container: $container"
        log_message "ERROR" "Failed to restore container from backup: $backup_file"
        return 1
    fi
}

# Function to cleanup containers
cleanup_containers() {
    local days="${1:-$RETENTION_DAYS}"
    
    print_status "HEADER" "Cleaning Up Containers"
    
    if ! check_docker; then
        return 1
    fi
    
    print_status "INFO" "Removing containers older than $days days"
    
    local removed_count=0
    
    # Remove old containers
    docker container prune -f --filter "until=${days}d"
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "Container cleanup completed"
        log_message "INFO" "Container cleanup completed - removed containers older than $days days"
    else
        print_status "ERROR" "Container cleanup failed"
        log_message "ERROR" "Container cleanup failed"
        return 1
    fi
    
    # Remove unused images
    print_status "INFO" "Removing unused images"
    docker image prune -f --filter "until=${days}d"
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "Image cleanup completed"
        log_message "INFO" "Image cleanup completed"
    else
        print_status "ERROR" "Image cleanup failed"
        log_message "ERROR" "Image cleanup failed"
    fi
    
    # Remove unused volumes
    print_status "INFO" "Removing unused volumes"
    docker volume prune -f
    
    if [[ $? -eq 0 ]]; then
        print_status "SUCCESS" "Volume cleanup completed"
        log_message "INFO" "Volume cleanup completed"
    else
        print_status "ERROR" "Volume cleanup failed"
        log_message "ERROR" "Volume cleanup failed"
    fi
}

# Function to check container health
check_health() {
    local container="${1:-}"
    
    print_status "HEADER" "Container Health Check"
    
    if ! check_docker; then
        return 1
    fi
    
    if [[ -n "$container" ]]; then
        # Check specific container
        if ! docker ps -aq --filter "name=^$container$" | grep -q .; then
            print_status "ERROR" "Container does not exist: $container"
            return 1
        fi
        
        print_status "INFO" "Checking health for container: $container"
        
        # Check if container is running
        if docker ps -q --filter "name=^$container$" --filter "status=running" | grep -q .; then
            print_status "SUCCESS" "Container is running: $container"
            
            # Check health status if available
            local health_status=$(docker inspect --format "{{.State.Health.Status}}" "$container" 2>/dev/null)
            if [[ -n "$health_status" && "$health_status" != "<nil>" ]]; then
                echo "Health Status: $health_status"
            fi
        else
            print_status "ERROR" "Container is not running: $container"
        fi
    else
        # Check all containers
        print_status "INFO" "Checking health for all containers"
        
        local containers=($(docker ps -aq))
        local healthy_count=0
        local unhealthy_count=0
        
        for container_id in "${containers[@]}"; do
            local container_name=$(docker inspect --format "{{.Name}}" "$container_id" | sed 's/\///')
            local status=$(docker inspect --format "{{.State.Status}}" "$container_id")
            local health_status=$(docker inspect --format "{{.State.Health.Status}}" "$container_id" 2>/dev/null)
            
            if [[ "$status" == "running" ]]; then
                if [[ -n "$health_status" && "$health_status" != "<nil>" ]]; then
                    if [[ "$health_status" == "healthy" ]]; then
                        print_status "SUCCESS" "$container_name: $health_status"
                        ((healthy_count++))
                    else
                        print_status "WARNING" "$container_name: $health_status"
                        ((unhealthy_count++))
                    fi
                else
                    print_status "INFO" "$container_name: running (no health check)"
                    ((healthy_count++))
                fi
            else
                print_status "ERROR" "$container_name: $status"
                ((unhealthy_count++))
            fi
        done
        
        echo ""
        echo "Health Summary:"
        echo "  Healthy: $healthy_count"
        echo "  Unhealthy: $unhealthy_count"
    fi
}

# Function to monitor containers
monitor_containers() {
    local duration="${1:-300}"
    local interval="${2:-10}"
    
    print_status "HEADER" "Container Monitoring"
    
    if ! check_docker; then
        return 1
    fi
    
    print_status "INFO" "Monitoring containers for $duration seconds (interval: ${interval}s)"
    print_status "INFO" "Press Ctrl+C to stop"
    
    local end_time=$((SECONDS + duration))
    
    while [[ $SECONDS -lt $end_time ]]; do
        echo ""
        echo "=== $(date) ==="
        
        # Show container status
        docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
        
        # Show resource usage
        echo ""
        echo "Resource Usage:"
        docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"
        
        # Wait for next interval
        sleep $interval
    done
    
    print_status "SUCCESS" "Monitoring completed"
}

# Function to generate report
generate_report() {
    print_status "HEADER" "Container Report"
    
    if ! check_docker; then
        return 1
    fi
    
    local report_file="container-report-$(date +%Y%m%d-%H%M%S).txt"
    
    {
        echo "Docker Container Report"
        echo "Generated on: $(date)"
        echo "========================================"
        echo ""
        
        echo "Docker Information:"
        docker version --format "Client: {{.Client.Version}}
Server: {{.Server.Version}}
API Version: {{.Server.APIVersion}}
" 2>/dev/null
        echo ""
        
        echo "Container Statistics:"
        local total_containers=$(docker ps -aq | wc -l)
        local running_containers=$(docker ps -q | wc -l)
        local stopped_containers=$((total_containers - running_containers))
        echo "  Total Containers: $total_containers"
        echo "  Running: $running_containers"
        echo "  Stopped: $stopped_containers"
        echo ""
        
        echo "Image Statistics:"
        local total_images=$(docker images -q | wc -l)
        local dangling_images=$(docker images -f "dangling=true" -q | wc -l)
        echo "  Total Images: $total_images"
        echo "  Dangling Images: $dangling_images"
        echo ""
        
        echo "Volume Statistics:"
        local total_volumes=$(docker volume ls -q | wc -l)
        echo "  Total Volumes: $total_volumes"
        echo ""
        
        echo "Network Statistics:"
        local total_networks=$(docker network ls -q | wc -l)
        echo "  Total Networks: $total_networks"
        echo ""
        
        echo "Container Details:"
        docker ps -a --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
        echo ""
        
        echo "Resource Usage:"
        docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"
        
    } > "$report_file"
    
    print_status "SUCCESS" "Report generated: $report_file"
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
            list|start|stop|restart|remove|logs|exec|inspect|stats|backup|restore|cleanup|health|monitor|report)
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
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/container-manager.log"
    log_message "INFO" "Script started with command: $command"
    
    # Show header
    if [[ "$quiet_mode" == false ]]; then
        show_header
    fi
    
    # Execute command
    case $command in
        list)
            list_containers "${args[0]}" "${args[1]}"
            ;;
        start)
            if [[ ${#args[@]} -lt 1 ]]; then
                print_status "ERROR" "start command requires container name"
                exit 1
            fi
            start_container "${args[0]}"
            ;;
        stop)
            if [[ ${#args[@]} -lt 1 ]]; then
                print_status "ERROR" "stop command requires container name"
                exit 1
            fi
            stop_container "${args[0]}" "${args[1]}"
            ;;
        restart)
            if [[ ${#args[@]} -lt 1 ]]; then
                print_status "ERROR" "restart command requires container name"
                exit 1
            fi
            restart_container "${args[0]}" "${args[1]}"
            ;;
        remove)
            if [[ ${#args[@]} -lt 1 ]]; then
                print_status "ERROR" "remove command requires container name"
                exit 1
            fi
            remove_container "${args[0]}" "$force_mode"
            ;;
        logs)
            if [[ ${#args[@]} -lt 1 ]]; then
                print_status "ERROR" "logs command requires container name"
                exit 1
            fi
            show_logs "${args[0]}" "${args[1]}"
            ;;
        exec)
            if [[ ${#args[@]} -lt 1 ]]; then
                print_status "ERROR" "exec command requires container name"
                exit 1
            fi
            exec_command "${args[0]}" "${args[1]}"
            ;;
        inspect)
            if [[ ${#args[@]} -lt 1 ]]; then
                print_status "ERROR" "inspect command requires container name"
                exit 1
            fi
            inspect_container "${args[0]}"
            ;;
        stats)
            show_stats "${args[0]}"
            ;;
        backup)
            if [[ ${#args[@]} -lt 1 ]]; then
                print_status "ERROR" "backup command requires container name"
                exit 1
            fi
            backup_container "${args[0]}" "${args[1]}"
            ;;
        restore)
            if [[ ${#args[@]} -lt 2 ]]; then
                print_status "ERROR" "restore command requires container name and backup file"
                exit 1
            fi
            restore_container "${args[0]}" "${args[1]}" "${args[2]}"
            ;;
        cleanup)
            cleanup_containers "${args[0]}"
            ;;
        health)
            check_health "${args[0]}"
            ;;
        monitor)
            monitor_containers "${args[0]}" "${args[1]}"
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