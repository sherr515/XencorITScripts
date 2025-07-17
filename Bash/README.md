# Bash Administration Scripts

This directory contains comprehensive Bash scripts for Linux system administration and management. Each script is designed with modern Bash practices, error handling, and security best practices.

## Directory Structure

```
Bash/
├── [Docker/](#docker-scripts)
│   └── [container-manager.sh](#container-managersh)
├── [Linux/](#linux-scripts)
│   └── [security-audit.sh](#security-auditsh)
├── [Monitoring/](#monitoring-scripts)
│   └── [system-monitor.sh](#system-monitorsh)
├── [Utilities/](#bash-utilities)
│   ├── [system-info.sh](#system-infosh)
│   ├── [backup-manager.sh](#backup-managersh)
│   └── [user-management.sh](#user-managementsh)
├── template_script.sh
└── README.md
```

*Click on any folder or script name above to jump to its description below.*

## Docker Scripts {#docker-scripts}

### container-manager.sh {#container-managersh}
**Purpose**: Comprehensive Docker container management and administration script

**Key Features**:
- Container lifecycle management (create, start, stop, restart, remove)
- Container monitoring and health checking
- Backup and restore functionality
- Resource usage monitoring
- Container inspection and debugging
- Cleanup and maintenance operations

**Usage Scenarios**:
- Docker container administration
- Container deployment and management
- Backup and disaster recovery
- Performance monitoring
- Container troubleshooting

**Functions**:
- `list_containers`: List all containers with status
- `start_container`: Start a stopped container
- `stop_container`: Stop a running container
- `restart_container`: Restart a container
- `remove_container`: Remove a container
- `show_logs`: Display container logs
- `exec_command`: Execute commands in containers
- `inspect_container`: Detailed container inspection
- `show_stats`: Container resource statistics
- `backup_container`: Backup container data
- `restore_container`: Restore from backup
- `cleanup_containers`: Remove old containers/images
- `check_health`: Container health monitoring
- `monitor_containers`: Continuous monitoring
- `generate_report`: Generate container report

## Linux Scripts {#linux-scripts}

### security-audit.sh {#security-auditsh}
**Purpose**: Comprehensive Linux system security auditing and assessment script

**Key Features**:
- User account and password security auditing
- File permission and ownership checking
- Service and daemon security analysis
- Network configuration auditing
- Firewall rule verification
- System log analysis
- Package security assessment
- Kernel security configuration
- Compliance standards checking

**Usage Scenarios**:
- Security compliance auditing
- System hardening
- Security assessment
- Compliance reporting
- Security monitoring

**Functions**:
- `audit_users`: Check user accounts and passwords
- `audit_files`: Verify file permissions and ownership
- `audit_services`: Analyze running services
- `audit_network`: Check network configuration
- `audit_firewall`: Verify firewall rules
- `audit_logs`: Analyze system logs
- `audit_packages`: Check installed packages
- `audit_kernel`: Verify kernel configuration
- `check_compliance`: Compliance standards check
- `generate_report`: Generate security report
- `fix_issues`: Fix identified security issues

## Monitoring Scripts {#monitoring-scripts}

### system-monitor.sh {#system-monitorsh}
**Purpose**: Comprehensive system monitoring and health checking script

**Key Features**:
- Real-time system resource monitoring
- CPU, memory, and disk usage tracking
- Network activity monitoring
- Process and service monitoring
- Performance metrics collection
- Alert generation and logging
- Continuous monitoring mode
- Health status reporting

**Usage Scenarios**:
- System performance monitoring
- Resource usage tracking
- Performance troubleshooting
- Capacity planning
- Health monitoring

**Functions**:
- `get_cpu_usage`: Monitor CPU utilization
- `get_memory_usage`: Track memory usage
- `get_disk_usage`: Monitor disk space
- `get_network_usage`: Track network activity
- `get_load_average`: System load monitoring
- `monitor_cpu`: CPU-specific monitoring
- `monitor_memory`: Memory-specific monitoring
- `monitor_disk`: Disk-specific monitoring
- `monitor_network`: Network-specific monitoring
- `monitor_processes`: Process monitoring
- `monitor_services`: Service monitoring
- `show_system_status`: Overall system status
- `show_alerts`: Display recent alerts
- `generate_report`: Generate monitoring report
- `continuous_monitor`: Continuous monitoring mode

## Bash Utilities {#bash-utilities}

### system-info.sh {#system-infosh}
**Purpose**: Comprehensive system information gathering and reporting script

**Key Features**:
- Detailed system information collection
- Hardware and software inventory
- Performance metrics gathering
- Security configuration analysis
- Network configuration details
- Process and service information
- Hardware component details
- Security status checking

**Usage Scenarios**:
- System documentation
- Inventory management
- Troubleshooting
- Performance analysis
- Security assessment

**Functions**:
- `get_cpu_info`: CPU information collection
- `get_memory_info`: Memory usage details
- `get_disk_info`: Disk space and I/O statistics
- `get_network_info`: Network configuration
- `get_process_info`: Process statistics
- `get_service_info`: Service status
- `get_system_info`: Basic system information
- `get_hardware_info`: Hardware details
- `get_security_info`: Security configuration

### backup-manager.sh {#backup-managersh}
**Purpose**: Comprehensive backup management and automation script

**Key Features**:
- Automated backup creation and management
- Backup scheduling and automation
- Retention policy management
- Backup verification and integrity checking
- Cross-region backup replication
- Disaster recovery procedures
- Backup cleanup and optimization

**Usage Scenarios**:
- Regular backup operations
- Disaster recovery planning
- Compliance requirements
- Data protection
- System migration

**Functions**:
- `create_backup`: Create new backups
- `list_backups`: List existing backups
- `restore_backup`: Restore from backup
- `verify_backup`: Verify backup integrity
- `cleanup_backups`: Remove old backups
- `show_backup_status`: Backup status reporting

### user-management.sh {#user-managementsh}
**Purpose**: Comprehensive user account management and administration script

**Key Features**:
- User account lifecycle management
- Password policy enforcement
- Group membership management
- Account security auditing
- User activity monitoring
- Account cleanup and maintenance
- Security compliance checking

**Usage Scenarios**:
- User account administration
- Security compliance
- Access control management
- Account lifecycle management
- Security auditing

**Functions**:
- `create_user`: Create new user accounts
- `delete_user`: Remove user accounts
- `modify_user`: Modify user properties
- `list_users`: List user accounts
- `lock_user`: Lock user accounts
- `unlock_user`: Unlock user accounts
- `change_password`: Password management
- `set_password_expiry`: Password aging
- `show_user_groups`: Group membership
- `add_user_to_group`: Group management
- `remove_user_from_group`: Group removal
- `audit_user_accounts`: Account auditing
- `cleanup_inactive_accounts`: Account cleanup

## Common Features Across All Scripts

### Modern Bash Design
- Uses Bash 4+ features
- Modern parameter handling
- Structured error handling
- Color-coded output
- Progress indicators

### Error Handling
- Comprehensive error checking
- Graceful error recovery
- Detailed error messages
- Logging capabilities
- Error reporting

### Security Focus
- Input validation
- Path sanitization
- Permission checking
- Security best practices
- Audit capabilities

### Automation Ready
- Dry-run capabilities
- Batch operations
- Scheduled execution
- Integration friendly
- API-driven operations

### Usage Examples
Each script includes detailed usage examples and help documentation to guide users through common scenarios.

## Prerequisites

- Bash 4.0 or higher
- Root privileges for most operations
- Required system tools (varies by script)
- Network connectivity for remote operations

## Installation

1. Clone or download the scripts to your local machine
2. Ensure appropriate permissions are set
3. Verify Bash 4+ is available
4. Test with dry-run mode before production use

## Usage

Each script can be run independently with appropriate parameters. Use the `-h` or `--help` parameter to see usage information.

Example:
```bash
# System information
./Utilities/system-info.sh

# Security audit
sudo ./Linux/security-audit.sh audit all

# Container management
./Docker/container-manager.sh list

# System monitoring
./Monitoring/system-monitor.sh status
```

## Security Notes

- Always use least privilege principles
- Test scripts in non-production environments first
- Review and audit script permissions regularly
- Monitor script execution and results
- Keep scripts updated with security patches

## Contributing

When adding new scripts or modifying existing ones:
- Follow the established documentation pattern
- Include comprehensive error handling
- Add usage examples
- Test with dry-run mode
- Update this README with new script information

## Support

For issues or questions:
1. Check the script's built-in help and usage examples
2. Review system documentation for specific tools
3. Test with dry-run mode to understand script behavior
4. Verify system permissions and requirements

## Script Categories

### Docker Management
Scripts for managing Docker containers, images, and orchestration.

### Linux Security
Scripts for auditing and securing Linux systems.

### System Monitoring
Scripts for monitoring system performance and health.

### Utilities
General-purpose system administration utilities.

## Best Practices

1. **Regular Audits**: Run security audits regularly
2. **Monitoring**: Implement continuous monitoring
3. **Backups**: Maintain regular backups
4. **Updates**: Keep scripts and systems updated
5. **Documentation**: Document all customizations
6. **Testing**: Test in staging environments first
7. **Logging**: Maintain comprehensive logs
8. **Access Control**: Use appropriate permissions 