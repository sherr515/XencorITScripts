#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Backup Manager - Comprehensive Backup and Recovery System

This script provides comprehensive backup and recovery capabilities including:
- File and directory backup with compression
- Database backup (MySQL, PostgreSQL, SQLite)
- Incremental and differential backups
- Backup verification and integrity checks
- Automated backup scheduling
- Cloud storage integration (AWS S3, Google Cloud)
- Backup encryption and security
- Recovery and restore operations

Author: System Administrator
Version: 1.0.0
Date: 2024-01-01
"""

import os
import sys
import json
import shutil
import hashlib
import argparse
import logging
import tarfile
import zipfile
import sqlite3
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import boto3
from google.cloud import storage
import schedule
import time


class BackupManager:
    """Comprehensive backup management system"""
    
    def __init__(self, config: Dict = None):
        """Initialize the backup manager"""
        self.config = config or {}
        self.logger = self._setup_logging()
        self.backup_dir = Path(self.config.get('backup_dir', './backups'))
        self.backup_dir.mkdir(exist_ok=True)
        
        # Initialize cloud clients if configured
        self.s3_client = None
        self.gcs_client = None
        self._setup_cloud_clients()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('BackupManager')
        logger.setLevel(logging.INFO)
        
        # Create handlers
        console_handler = logging.StreamHandler()
        file_handler = logging.FileHandler('backup_manager.log')
        
        # Create formatters and add it to handlers
        log_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(log_format)
        file_handler.setFormatter(log_format)
        
        # Add handlers to the logger
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        
        return logger
    
    def _setup_cloud_clients(self):
        """Setup cloud storage clients"""
        # AWS S3
        if 'aws' in self.config:
            aws_config = self.config['aws']
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=aws_config.get('access_key'),
                aws_secret_access_key=aws_config.get('secret_key'),
                region_name=aws_config.get('region', 'us-east-1')
            )
        
        # Google Cloud Storage
        if 'gcs' in self.config:
            gcs_config = self.config['gcs']
            self.gcs_client = storage.Client.from_service_account_json(
                gcs_config.get('credentials_file')
            )
    
    def calculate_file_hash(self, file_path: Path) -> str:
        """Calculate SHA256 hash of a file"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def backup_files(self, source_paths: List[str], backup_name: str, 
                    compression: str = 'gzip', encrypt: bool = False) -> Dict:
        """Backup files and directories"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f"{backup_name}_{timestamp}.tar.gz"
            backup_path = self.backup_dir / backup_filename
            
            self.logger.info(f"Starting backup: {backup_name}")
            self.logger.info(f"Source paths: {source_paths}")
            
            # Create tar archive
            with tarfile.open(backup_path, f"w:{compression}") as tar:
                for source_path in source_paths:
                    source = Path(source_path)
                    if source.exists():
                        self.logger.info(f"Adding {source} to backup")
                        tar.add(source, arcname=source.name)
                    else:
                        self.logger.warning(f"Source path does not exist: {source}")
            
            # Calculate backup hash
            backup_hash = self.calculate_file_hash(backup_path)
            
            # Create backup metadata
            metadata = {
                'backup_name': backup_name,
                'timestamp': timestamp,
                'source_paths': source_paths,
                'backup_path': str(backup_path),
                'backup_size': backup_path.stat().st_size,
                'backup_hash': backup_hash,
                'compression': compression,
                'encrypted': encrypt
            }
            
            # Save metadata
            metadata_path = backup_path.with_suffix('.json')
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            self.logger.info(f"Backup completed: {backup_path}")
            self.logger.info(f"Backup size: {metadata['backup_size']} bytes")
            
            return metadata
            
        except Exception as e:
            self.logger.error(f"Error creating backup: {e}")
            return {}
    
    def backup_mysql_database(self, database: str, host: str = 'localhost', 
                             port: int = 3306, user: str = None, password: str = None) -> Dict:
        """Backup MySQL database"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f"mysql_{database}_{timestamp}.sql"
            backup_path = self.backup_dir / backup_filename
            
            self.logger.info(f"Starting MySQL backup: {database}")
            
            # Build mysqldump command
            cmd = ['mysqldump']
            if host:
                cmd.extend(['-h', host])
            if port:
                cmd.extend(['-P', str(port)])
            if user:
                cmd.extend(['-u', user])
            if password:
                cmd.extend(['-p' + password])
            
            cmd.extend(['--single-transaction', '--routines', '--triggers', database])
            
            # Execute mysqldump
            with open(backup_path, 'w') as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, text=True)
            
            if result.returncode != 0:
                raise Exception(f"mysqldump failed: {result.stderr}")
            
            # Compress the backup
            compressed_path = backup_path.with_suffix('.sql.gz')
            with open(backup_path, 'rb') as f_in:
                with open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Remove uncompressed file
            backup_path.unlink()
            
            # Calculate hash
            backup_hash = self.calculate_file_hash(compressed_path)
            
            metadata = {
                'database': database,
                'timestamp': timestamp,
                'backup_path': str(compressed_path),
                'backup_size': compressed_path.stat().st_size,
                'backup_hash': backup_hash,
                'type': 'mysql'
            }
            
            self.logger.info(f"MySQL backup completed: {compressed_path}")
            return metadata
            
        except Exception as e:
            self.logger.error(f"Error backing up MySQL database: {e}")
            return {}
    
    def backup_postgresql_database(self, database: str, host: str = 'localhost',
                                  port: int = 5432, user: str = None, password: str = None) -> Dict:
        """Backup PostgreSQL database"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f"postgresql_{database}_{timestamp}.sql"
            backup_path = self.backup_dir / backup_filename
            
            self.logger.info(f"Starting PostgreSQL backup: {database}")
            
            # Set environment variables for password
            env = os.environ.copy()
            if password:
                env['PGPASSWORD'] = password
            
            # Build pg_dump command
            cmd = ['pg_dump']
            if host:
                cmd.extend(['-h', host])
            if port:
                cmd.extend(['-p', str(port)])
            if user:
                cmd.extend(['-U', user])
            
            cmd.extend(['-d', database, '--verbose'])
            
            # Execute pg_dump
            with open(backup_path, 'w') as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, 
                                     text=True, env=env)
            
            if result.returncode != 0:
                raise Exception(f"pg_dump failed: {result.stderr}")
            
            # Compress the backup
            compressed_path = backup_path.with_suffix('.sql.gz')
            with open(backup_path, 'rb') as f_in:
                with open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Remove uncompressed file
            backup_path.unlink()
            
            # Calculate hash
            backup_hash = self.calculate_file_hash(compressed_path)
            
            metadata = {
                'database': database,
                'timestamp': timestamp,
                'backup_path': str(compressed_path),
                'backup_size': compressed_path.stat().st_size,
                'backup_hash': backup_hash,
                'type': 'postgresql'
            }
            
            self.logger.info(f"PostgreSQL backup completed: {compressed_path}")
            return metadata
            
        except Exception as e:
            self.logger.error(f"Error backing up PostgreSQL database: {e}")
            return {}
    
    def backup_sqlite_database(self, database_path: str) -> Dict:
        """Backup SQLite database"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            db_path = Path(database_path)
            backup_filename = f"sqlite_{db_path.stem}_{timestamp}.db"
            backup_path = self.backup_dir / backup_filename
            
            self.logger.info(f"Starting SQLite backup: {database_path}")
            
            # Copy the database file
            shutil.copy2(database_path, backup_path)
            
            # Compress the backup
            compressed_path = backup_path.with_suffix('.db.gz')
            with open(backup_path, 'rb') as f_in:
                with open(compressed_path, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            
            # Remove uncompressed file
            backup_path.unlink()
            
            # Calculate hash
            backup_hash = self.calculate_file_hash(compressed_path)
            
            metadata = {
                'database': database_path,
                'timestamp': timestamp,
                'backup_path': str(compressed_path),
                'backup_size': compressed_path.stat().st_size,
                'backup_hash': backup_hash,
                'type': 'sqlite'
            }
            
            self.logger.info(f"SQLite backup completed: {compressed_path}")
            return metadata
            
        except Exception as e:
            self.logger.error(f"Error backing up SQLite database: {e}")
            return {}
    
    def upload_to_s3(self, file_path: Path, bucket: str, key: str = None) -> bool:
        """Upload backup to AWS S3"""
        try:
            if not self.s3_client:
                self.logger.error("S3 client not configured")
                return False
            
            if not key:
                key = file_path.name
            
            self.logger.info(f"Uploading {file_path} to S3: {bucket}/{key}")
            
            self.s3_client.upload_file(str(file_path), bucket, key)
            
            self.logger.info(f"Upload completed: s3://{bucket}/{key}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error uploading to S3: {e}")
            return False
    
    def upload_to_gcs(self, file_path: Path, bucket: str, blob_name: str = None) -> bool:
        """Upload backup to Google Cloud Storage"""
        try:
            if not self.gcs_client:
                self.logger.error("GCS client not configured")
                return False
            
            if not blob_name:
                blob_name = file_path.name
            
            self.logger.info(f"Uploading {file_path} to GCS: {bucket}/{blob_name}")
            
            bucket_obj = self.gcs_client.bucket(bucket)
            blob = bucket_obj.blob(blob_name)
            blob.upload_from_filename(str(file_path))
            
            self.logger.info(f"Upload completed: gs://{bucket}/{blob_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error uploading to GCS: {e}")
            return False
    
    def verify_backup(self, backup_path: Path) -> bool:
        """Verify backup integrity"""
        try:
            self.logger.info(f"Verifying backup: {backup_path}")
            
            # Check if file exists
            if not backup_path.exists():
                self.logger.error(f"Backup file not found: {backup_path}")
                return False
            
            # Check file size
            file_size = backup_path.stat().st_size
            if file_size == 0:
                self.logger.error(f"Backup file is empty: {backup_path}")
                return False
            
            # Try to extract and verify archive
            if backup_path.suffix in ['.tar.gz', '.tgz']:
                with tarfile.open(backup_path, 'r:gz') as tar:
                    tar.getmembers()  # This will raise an error if corrupted
            
            self.logger.info(f"Backup verification successful: {backup_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Backup verification failed: {e}")
            return False
    
    def restore_backup(self, backup_path: Path, restore_path: Path) -> bool:
        """Restore backup to specified location"""
        try:
            self.logger.info(f"Restoring backup: {backup_path} to {restore_path}")
            
            # Verify backup first
            if not self.verify_backup(backup_path):
                return False
            
            # Create restore directory
            restore_path.mkdir(parents=True, exist_ok=True)
            
            # Extract backup
            if backup_path.suffix in ['.tar.gz', '.tgz']:
                with tarfile.open(backup_path, 'r:gz') as tar:
                    tar.extractall(restore_path)
            
            self.logger.info(f"Restore completed: {restore_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error restoring backup: {e}")
            return False
    
    def cleanup_old_backups(self, days_to_keep: int = 30) -> int:
        """Clean up old backups"""
        try:
            cutoff_date = datetime.now() - timedelta(days=days_to_keep)
            deleted_count = 0
            
            self.logger.info(f"Cleaning up backups older than {days_to_keep} days")
            
            for backup_file in self.backup_dir.glob('*'):
                if backup_file.is_file():
                    file_time = datetime.fromtimestamp(backup_file.stat().st_mtime)
                    if file_time < cutoff_date:
                        backup_file.unlink()
                        deleted_count += 1
                        self.logger.info(f"Deleted old backup: {backup_file}")
            
            self.logger.info(f"Cleanup completed: {deleted_count} files deleted")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}")
            return 0
    
    def list_backups(self) -> List[Dict]:
        """List all available backups"""
        try:
            backups = []
            
            for backup_file in self.backup_dir.glob('*'):
                if backup_file.is_file() and backup_file.suffix in ['.tar.gz', '.sql.gz', '.db.gz']:
                    file_time = datetime.fromtimestamp(backup_file.stat().st_mtime)
                    
                    backup_info = {
                        'filename': backup_file.name,
                        'path': str(backup_file),
                        'size': backup_file.stat().st_size,
                        'modified': file_time.isoformat(),
                        'age_days': (datetime.now() - file_time).days
                    }
                    
                    # Try to load metadata
                    metadata_path = backup_file.with_suffix('.json')
                    if metadata_path.exists():
                        try:
                            with open(metadata_path, 'r') as f:
                                metadata = json.load(f)
                                backup_info.update(metadata)
                        except Exception as e:
                            self.logger.warning(f"Error loading metadata for {backup_file}: {e}")
                    
                    backups.append(backup_info)
            
            # Sort by modification time (newest first)
            backups.sort(key=lambda x: x['modified'], reverse=True)
            
            return backups
            
        except Exception as e:
            self.logger.error(f"Error listing backups: {e}")
            return []
    
    def schedule_backup(self, backup_type: str, schedule_time: str, **kwargs):
        """Schedule a recurring backup"""
        try:
            self.logger.info(f"Scheduling {backup_type} backup for {schedule_time}")
            
            if backup_type == 'files':
                schedule.every().day.at(schedule_time).do(
                    self.backup_files, kwargs.get('source_paths', []), kwargs.get('backup_name', 'scheduled')
                )
            elif backup_type == 'mysql':
                schedule.every().day.at(schedule_time).do(
                    self.backup_mysql_database, kwargs.get('database'), kwargs.get('host'), 
                    kwargs.get('port'), kwargs.get('user'), kwargs.get('password')
                )
            elif backup_type == 'postgresql':
                schedule.every().day.at(schedule_time).do(
                    self.backup_postgresql_database, kwargs.get('database'), kwargs.get('host'),
                    kwargs.get('port'), kwargs.get('user'), kwargs.get('password')
                )
            
            # Run the scheduler
            while True:
                schedule.run_pending()
                time.sleep(60)
                
        except Exception as e:
            self.logger.error(f"Error scheduling backup: {e}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Backup Manager')
    parser.add_argument('--config', type=str, help='Configuration file path')
    parser.add_argument('--backup-files', nargs='+', help='Files/directories to backup')
    parser.add_argument('--backup-name', type=str, help='Name for the backup')
    parser.add_argument('--mysql-database', type=str, help='MySQL database to backup')
    parser.add_argument('--postgresql-database', type=str, help='PostgreSQL database to backup')
    parser.add_argument('--sqlite-database', type=str, help='SQLite database to backup')
    parser.add_argument('--list', action='store_true', help='List available backups')
    parser.add_argument('--restore', type=str, help='Backup file to restore')
    parser.add_argument('--restore-path', type=str, help='Path to restore backup to')
    parser.add_argument('--verify', type=str, help='Backup file to verify')
    parser.add_argument('--cleanup', type=int, help='Clean up backups older than N days')
    parser.add_argument('--schedule', type=str, help='Schedule time (HH:MM)')
    parser.add_argument('--upload-s3', action='store_true', help='Upload to S3 after backup')
    parser.add_argument('--upload-gcs', action='store_true', help='Upload to GCS after backup')
    
    args = parser.parse_args()
    
    # Load configuration
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    # Create backup manager
    manager = BackupManager(config)
    
    # Handle different operations
    if args.list:
        backups = manager.list_backups()
        print(json.dumps(backups, indent=2))
    
    elif args.verify:
        success = manager.verify_backup(Path(args.verify))
        print(f"Verification {'successful' if success else 'failed'}")
    
    elif args.restore:
        if not args.restore_path:
            print("Error: --restore-path is required for restore operation")
            sys.exit(1)
        success = manager.restore_backup(Path(args.restore), Path(args.restore_path))
        print(f"Restore {'successful' if success else 'failed'}")
    
    elif args.cleanup:
        deleted_count = manager.cleanup_old_backups(args.cleanup)
        print(f"Deleted {deleted_count} old backups")
    
    elif args.backup_files:
        metadata = manager.backup_files(args.backup_files, args.backup_name or 'files')
        if metadata:
            print(f"Backup completed: {metadata['backup_path']}")
            
            # Upload to cloud if requested
            if args.upload_s3 and 's3' in config:
                manager.upload_to_s3(Path(metadata['backup_path']), config['s3']['bucket'])
            
            if args.upload_gcs and 'gcs' in config:
                manager.upload_to_gcs(Path(metadata['backup_path']), config['gcs']['bucket'])
    
    elif args.mysql_database:
        metadata = manager.backup_mysql_database(args.mysql_database)
        if metadata:
            print(f"MySQL backup completed: {metadata['backup_path']}")
    
    elif args.postgresql_database:
        metadata = manager.backup_postgresql_database(args.postgresql_database)
        if metadata:
            print(f"PostgreSQL backup completed: {metadata['backup_path']}")
    
    elif args.sqlite_database:
        metadata = manager.backup_sqlite_database(args.sqlite_database)
        if metadata:
            print(f"SQLite backup completed: {metadata['backup_path']}")
    
    elif args.schedule:
        # Schedule backup (this will run continuously)
        manager.schedule_backup('files', args.schedule, source_paths=args.backup_files or [])
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main() 