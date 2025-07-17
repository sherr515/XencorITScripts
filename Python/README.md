# Python Admin Scripts

This directory contains comprehensive Python scripts for system administration, automation, and data processing tasks. Each script is designed with modern Python practices, detailed documentation, and robust error handling.

## 📁 Directory Structure

```
Python/
├── API/
│   └── rest_api_server.py          # Comprehensive REST API server
├── Automation/
│   └── backup_manager.py           # Backup and recovery system
├── AWS/
│   └── aws_manager.py              # AWS resource management
├── DataProcessing/
│   └── data_processor.py           # Data processing and analysis
├── Utilities/
│   └── system_monitor.py           # System monitoring and health checks
└── template_script.py              # Template for new scripts
```

## 🚀 Scripts Overview

### API/rest_api_server.py
**Comprehensive REST API Framework**

**Purpose:** Provides a complete REST API server with authentication, database integration, and monitoring capabilities.

**Features:**
- FastAPI-based REST API framework
- JWT authentication and authorization
- Database integration (SQLite, PostgreSQL, MySQL)
- API documentation (Swagger/OpenAPI)
- Rate limiting and security
- Logging and monitoring
- CORS support
- Health checks and status endpoints
- File upload/download capabilities
- Prometheus metrics integration

**Usage Scenarios:**
- Building internal admin APIs
- Creating service endpoints for automation
- Providing data access APIs
- Monitoring system health
- File management services

**Key Functions:**
- `register()` - User registration
- `login()` - User authentication
- `get_current_user()` - User session management
- `create_item()` - CRUD operations
- `upload_file()` - File upload handling
- `get_system_info()` - System monitoring

**Prerequisites:**
```bash
pip install fastapi uvicorn sqlalchemy psycopg2-binary mysql-connector-python
pip install python-jose[cryptography] passlib[bcrypt] python-multipart
pip install prometheus-client redis
```

**Usage:**
```bash
# Start the API server
python rest_api_server.py --host 0.0.0.0 --port 8000

# With configuration file
python rest_api_server.py --config config.json

# Enable auto-reload for development
python rest_api_server.py --reload
```

### Automation/backup_manager.py
**Comprehensive Backup and Recovery System**

**Purpose:** Manages file, database, and system backups with cloud storage integration.

**Features:**
- File and directory backup with compression
- Database backup (MySQL, PostgreSQL, SQLite)
- Incremental and differential backups
- Backup verification and integrity checks
- Automated backup scheduling
- Cloud storage integration (AWS S3, Google Cloud)
- Backup encryption and security
- Recovery and restore operations

**Usage Scenarios:**
- Automated system backups
- Database backup management
- Cloud storage synchronization
- Disaster recovery planning
- Backup verification and testing

**Key Functions:**
- `backup_files()` - File system backups
- `backup_mysql_database()` - MySQL database backup
- `backup_postgresql_database()` - PostgreSQL database backup
- `upload_to_s3()` - Cloud storage upload
- `verify_backup()` - Backup integrity verification
- `restore_backup()` - Backup restoration

**Prerequisites:**
```bash
pip install boto3 google-cloud-storage schedule psutil
```

**Usage:**
```bash
# Backup files
python backup_manager.py --backup-files /path/to/files --backup-name "daily_backup"

# Backup MySQL database
python backup_manager.py --mysql-database mydb

# List available backups
python backup_manager.py --list

# Restore backup
python backup_manager.py --restore backup.tar.gz --restore-path /restore/location

# Schedule daily backup
python backup_manager.py --schedule "02:00" --backup-files /important/data
```

### AWS/aws_manager.py
**Comprehensive AWS Resource Management**

**Purpose:** Manages AWS resources including EC2, S3, IAM, Lambda, and CloudFormation.

**Features:**
- EC2 instance management (create, start, stop, terminate)
- S3 bucket operations (create, list, upload, download)
- IAM user and role management
- Lambda function deployment and management
- CloudFormation stack operations
- Cost analysis and reporting
- Security group management
- CloudWatch monitoring and alerts

**Usage Scenarios:**
- AWS infrastructure management
- Automated resource provisioning
- Cost optimization and analysis
- Security compliance monitoring
- Disaster recovery automation

**Key Functions:**
- `list_instances()` - EC2 instance inventory
- `create_instance()` - EC2 instance creation
- `list_buckets()` - S3 bucket management
- `create_user()` - IAM user management
- `list_functions()` - Lambda function management
- `get_cost_analysis()` - Cost reporting
- `generate_report()` - Comprehensive reporting

**Prerequisites:**
```bash
pip install boto3 pyyaml
# Configure AWS credentials: aws configure
```

**Usage:**
```bash
# List all EC2 instances
python aws_manager.py --list-instances

# Create EC2 instance
python aws_manager.py --create-instance instance_config.json

# List S3 buckets
python aws_manager.py --list-buckets

# Upload file to S3
python aws_manager.py --upload-file mybucket myfile.txt s3key

# Generate cost analysis
python aws_manager.py --cost-analysis 2024-01-01 2024-01-31

# Generate comprehensive report
python aws_manager.py --report summary
```

### DataProcessing/data_processor.py
**Comprehensive Data Processing and Analysis**

**Purpose:** Processes and analyzes data from various sources with statistical analysis and visualization.

**Features:**
- CSV, JSON, XML, Excel file processing
- Data cleaning and validation
- Data transformation and aggregation
- Statistical analysis and reporting
- Data visualization generation
- Database operations (SQLite, PostgreSQL, MySQL)
- Big data processing with pandas and numpy
- Machine learning data preparation
- Data export in multiple formats

**Usage Scenarios:**
- Data analysis and reporting
- ETL (Extract, Transform, Load) processes
- Statistical analysis
- Data visualization creation
- Database data processing
- Machine learning data preparation

**Key Functions:**
- `load_csv()` - CSV file loading
- `clean_data()` - Data cleaning and preprocessing
- `transform_data()` - Data transformation
- `analyze_data()` - Statistical analysis
- `create_visualizations()` - Data visualization
- `export_data()` - Multi-format export
- `process_pipeline()` - Complete processing pipeline

**Prerequisites:**
```bash
pip install pandas numpy matplotlib seaborn scikit-learn
pip install psycopg2-binary mysql-connector-python
pip install openpyxl pyyaml
```

**Usage:**
```bash
# Process CSV file with cleaning and analysis
python data_processor.py --input data.csv --input-type csv --clean --analyze

# Create visualizations
python data_processor.py --input data.csv --input-type csv --visualize

# Export to different format
python data_processor.py --input data.csv --input-type csv --output data.json --output-format json

# Run complete pipeline
python data_processor.py --config pipeline_config.json
```

### Utilities/system_monitor.py
**System Monitoring and Health Checks**

**Purpose:** Monitors system resources and provides comprehensive health reporting.

**Features:**
- CPU, memory, and disk usage monitoring
- Network interface statistics
- Process monitoring and management
- System service status
- Log file monitoring
- Performance metrics collection
- Alert generation and reporting
- Temperature and battery monitoring

**Usage Scenarios:**
- System health monitoring
- Performance analysis
- Resource utilization tracking
- Alert generation
- Capacity planning
- Troubleshooting support

**Key Functions:**
- `get_cpu_info()` - CPU monitoring
- `get_memory_info()` - Memory monitoring
- `get_disk_info()` - Disk usage monitoring
- `get_network_info()` - Network monitoring
- `get_process_info()` - Process monitoring
- `check_alerts()` - Alert generation
- `generate_report()` - Health reporting

**Prerequisites:**
```bash
pip install psutil requests
```

**Usage:**
```bash
# Monitor system once
python system_monitor.py --once

# Continuous monitoring
python system_monitor.py --interval 60

# Save metrics to file
python system_monitor.py --once --save

# Monitor for specific duration
python system_monitor.py --duration 3600 --interval 30
```

## 📋 Prerequisites

### System Requirements
- Python 3.8 or higher
- pip package manager
- Git for version control

### Common Dependencies
```bash
# Core dependencies
pip install requests psutil pandas numpy

# Database connectors
pip install psycopg2-binary mysql-connector-python sqlite3

# AWS and cloud services
pip install boto3 google-cloud-storage

# Web framework
pip install fastapi uvicorn

# Data processing
pip install matplotlib seaborn scikit-learn

# Utilities
pip install pyyaml schedule
```

## 🔧 Installation

1. **Clone the repository:**
```bash
git clone <repository-url>
cd GitHub/Python
```

2. **Install dependencies:**
```bash
# Install all dependencies
pip install -r requirements.txt

# Or install individually for specific scripts
pip install psutil requests  # For system_monitor.py
pip install boto3  # For aws_manager.py
pip install fastapi uvicorn  # For rest_api_server.py
```

3. **Configure credentials:**
```bash
# AWS credentials
aws configure

# Database connections (update config files)
# Edit config.json files in each script directory
```

## 🚀 Usage Examples

### Quick Start
```bash
# System monitoring
python Utilities/system_monitor.py --once

# AWS resource listing
python AWS/aws_manager.py --list-instances

# Data processing
python DataProcessing/data_processor.py --input data.csv --input-type csv --analyze

# Start API server
python API/rest_api_server.py --host 0.0.0.0 --port 8000
```

### Configuration Files
Each script supports configuration files for customization:

```json
{
  "database": {
    "type": "postgresql",
    "host": "localhost",
    "port": 5432,
    "database": "admin_db",
    "user": "admin",
    "password": "password"
  },
  "aws": {
    "default_region": "us-east-1",
    "default_vpc_id": "vpc-12345678"
  },
  "monitoring": {
    "alert_thresholds": {
      "cpu_percent": 80.0,
      "memory_percent": 85.0
    }
  }
}
```

## 🔒 Security Considerations

### Authentication and Authorization
- All API endpoints require proper authentication
- JWT tokens are used for session management
- Role-based access control implemented
- Secure password hashing with bcrypt

### Data Protection
- Sensitive data is encrypted at rest
- Database connections use SSL/TLS
- API communications are secured with HTTPS
- Backup files can be encrypted

### AWS Security
- Use IAM roles and policies for least privilege access
- Enable CloudTrail for audit logging
- Implement proper security groups and NACLs
- Regular security group reviews

### Best Practices
- Never hardcode credentials in scripts
- Use environment variables for sensitive data
- Regularly rotate access keys and passwords
- Monitor and log all administrative actions
- Keep dependencies updated for security patches

## 📊 Monitoring and Logging

### Logging Configuration
All scripts include comprehensive logging:
- Console and file logging
- Structured log format
- Different log levels (DEBUG, INFO, WARNING, ERROR)
- Log rotation and retention

### Metrics Collection
- Prometheus metrics for API server
- System resource monitoring
- Performance metrics tracking
- Custom business metrics

### Alerting
- Threshold-based alerting
- Email and webhook notifications
- Escalation procedures
- Alert history and acknowledgment

## 🛠️ Troubleshooting

### Common Issues

**AWS Credentials Error:**
```bash
# Configure AWS credentials
aws configure
# Or set environment variables
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
```

**Database Connection Error:**
```bash
# Check database service status
sudo systemctl status postgresql
# Verify connection parameters in config file
```

**Permission Denied:**
```bash
# Ensure proper file permissions
chmod +x *.py
# Check user permissions for system monitoring
sudo usermod -a -G systemd-resolve $USER
```

**Missing Dependencies:**
```bash
# Install missing packages
pip install <package_name>
# Or install all requirements
pip install -r requirements.txt
```

### Debug Mode
Enable debug logging for troubleshooting:
```python
# In script configuration
logging.getLogger().setLevel(logging.DEBUG)
```

## 🤝 Contributing

### Development Guidelines
1. Follow PEP 8 style guidelines
2. Add comprehensive docstrings
3. Include type hints for all functions
4. Write unit tests for new features
5. Update documentation for changes

### Code Structure
```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script Name - Brief Description

Detailed description of functionality, features, and usage.

Author: Your Name
Version: 1.0.0
Date: YYYY-MM-DD
"""

import standard_library_modules
import third_party_modules
from typing import TypeHints

class MainClass:
    """Class description with comprehensive docstring."""
    
    def __init__(self, config: Dict = None):
        """Initialize with configuration."""
        pass
    
    def main_method(self) -> ReturnType:
        """Main method with detailed documentation."""
        pass

def main():
    """Main function with argument parsing."""
    pass

if __name__ == "__main__":
    main()
```

### Testing
```bash
# Run unit tests
python -m pytest tests/

# Run with coverage
python -m pytest --cov=. tests/

# Run specific test
python -m pytest tests/test_system_monitor.py
```

## 📚 Documentation

### API Documentation
- Swagger/OpenAPI documentation available at `/docs`
- Interactive API testing interface
- Request/response examples
- Authentication documentation

### Code Documentation
- Comprehensive docstrings for all functions
- Type hints for better IDE support
- Usage examples in docstrings
- Configuration file examples

### User Guides
- Step-by-step setup instructions
- Common use case examples
- Troubleshooting guides
- Best practices documentation

## 🔄 Version History

### v1.0.0 (2024-01-01)
- Initial release of Python admin scripts
- Comprehensive system monitoring
- AWS resource management
- Data processing and analysis
- REST API server framework
- Backup and recovery system

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- FastAPI team for the excellent web framework
- AWS SDK team for comprehensive cloud integration
- Python community for excellent libraries and tools
- Contributors and maintainers

## 📞 Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the documentation
- Contact the development team

---

**Note:** These scripts are designed for system administration and should be used responsibly. Always test in a development environment before deploying to production systems. 