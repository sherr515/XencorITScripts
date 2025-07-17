#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
System Monitor - Comprehensive System Monitoring and Health Check

This script provides comprehensive system monitoring capabilities including:
- CPU, memory, and disk usage monitoring
- Network interface statistics
- Process monitoring and management
- System service status
- Log file monitoring
- Performance metrics collection
- Alert generation and reporting

Author: System Administrator
Version: 1.0.0
Date: 2024-01-01
"""

import os
import sys
import time
import json
import logging
import argparse
import platform
import subprocess
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import psutil
import requests
from dataclasses import dataclass, asdict
from pathlib import Path


@dataclass
class SystemMetrics:
    """Data class for system metrics"""
    timestamp: str
    cpu_percent: float
    memory_percent: float
    disk_usage_percent: float
    network_io: Dict[str, int]
    process_count: int
    uptime: float
    load_average: Tuple[float, float, float]
    temperature: Optional[float] = None
    battery_percent: Optional[float] = None


class SystemMonitor:
    """Comprehensive system monitoring class"""
    
    def __init__(self, config: Dict = None):
        """Initialize the system monitor"""
        self.config = config or {}
        self.logger = self._setup_logging()
        self.alert_thresholds = {
            'cpu_percent': 80.0,
            'memory_percent': 85.0,
            'disk_percent': 90.0,
            'temperature': 80.0
        }
        self.metrics_history = []
        self.max_history_size = 1000
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('SystemMonitor')
        logger.setLevel(logging.INFO)
        
        # Create handlers
        console_handler = logging.StreamHandler()
        file_handler = logging.FileHandler('system_monitor.log')
        
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
    
    def get_cpu_info(self) -> Dict:
        """Get comprehensive CPU information"""
        try:
            cpu_info = {
                'percent': psutil.cpu_percent(interval=1),
                'count': psutil.cpu_count(),
                'count_logical': psutil.cpu_count(logical=True),
                'freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else {},
                'stats': psutil.cpu_stats()._asdict(),
                'load_avg': psutil.getloadavg() if hasattr(psutil, 'getloadavg') else (0, 0, 0)
            }
            return cpu_info
        except Exception as e:
            self.logger.error(f"Error getting CPU info: {e}")
            return {}
    
    def get_memory_info(self) -> Dict:
        """Get comprehensive memory information"""
        try:
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            memory_info = {
                'total': memory.total,
                'available': memory.available,
                'used': memory.used,
                'free': memory.free,
                'percent': memory.percent,
                'swap_total': swap.total,
                'swap_used': swap.used,
                'swap_free': swap.free,
                'swap_percent': swap.percent
            }
            return memory_info
        except Exception as e:
            self.logger.error(f"Error getting memory info: {e}")
            return {}
    
    def get_disk_info(self) -> Dict:
        """Get comprehensive disk information"""
        try:
            disk_info = {}
            disk_usage = psutil.disk_usage('/')
            
            disk_info['root'] = {
                'total': disk_usage.total,
                'used': disk_usage.used,
                'free': disk_usage.free,
                'percent': disk_usage.percent
            }
            
            # Get all disk partitions
            partitions = psutil.disk_partitions()
            for partition in partitions:
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    disk_info[partition.device] = {
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    }
                except PermissionError:
                    continue
            
            # Get disk I/O statistics
            disk_io = psutil.disk_io_counters()
            if disk_io:
                disk_info['io_stats'] = disk_io._asdict()
            
            return disk_info
        except Exception as e:
            self.logger.error(f"Error getting disk info: {e}")
            return {}
    
    def get_network_info(self) -> Dict:
        """Get comprehensive network information"""
        try:
            network_info = {}
            
            # Get network interfaces
            interfaces = psutil.net_if_addrs()
            for interface, addresses in interfaces.items():
                network_info[interface] = {
                    'addresses': [addr._asdict() for addr in addresses]
                }
            
            # Get network I/O statistics
            net_io = psutil.net_io_counters()
            if net_io:
                network_info['io_stats'] = net_io._asdict()
            
            # Get network connections
            connections = psutil.net_connections()
            network_info['connections'] = {
                'total': len(connections),
                'established': len([c for c in connections if c.status == 'ESTABLISHED']),
                'listening': len([c for c in connections if c.status == 'LISTEN'])
            }
            
            return network_info
        except Exception as e:
            self.logger.error(f"Error getting network info: {e}")
            return {}
    
    def get_process_info(self) -> List[Dict]:
        """Get information about running processes"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    process_info = proc.info
                    process_info['create_time'] = proc.create_time()
                    processes.append(process_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Sort by CPU usage
            processes.sort(key=lambda x: x.get('cpu_percent', 0), reverse=True)
            return processes[:20]  # Return top 20 processes
        except Exception as e:
            self.logger.error(f"Error getting process info: {e}")
            return []
    
    def get_system_info(self) -> Dict:
        """Get general system information"""
        try:
            system_info = {
                'platform': platform.platform(),
                'system': platform.system(),
                'release': platform.release(),
                'version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'python_version': platform.python_version(),
                'boot_time': psutil.boot_time(),
                'uptime': time.time() - psutil.boot_time()
            }
            return system_info
        except Exception as e:
            self.logger.error(f"Error getting system info: {e}")
            return {}
    
    def get_temperature(self) -> Optional[float]:
        """Get system temperature if available"""
        try:
            # Try to get temperature from various sources
            if platform.system() == "Linux":
                # Try reading from thermal zone
                for i in range(10):
                    temp_file = f"/sys/class/thermal/thermal_zone{i}/temp"
                    if os.path.exists(temp_file):
                        with open(temp_file, 'r') as f:
                            temp = float(f.read().strip()) / 1000.0
                            return temp
            
            # Try using psutil if available
            if hasattr(psutil, 'sensors_temperatures'):
                temps = psutil.sensors_temperatures()
                if temps:
                    for name, entries in temps.items():
                        for entry in entries:
                            if entry.current > 0:
                                return entry.current
            
            return None
        except Exception as e:
            self.logger.debug(f"Could not get temperature: {e}")
            return None
    
    def get_battery_info(self) -> Optional[Dict]:
        """Get battery information if available"""
        try:
            if hasattr(psutil, 'sensors_battery'):
                battery = psutil.sensors_battery()
                if battery:
                    return {
                        'percent': battery.percent,
                        'power_plugged': battery.power_plugged,
                        'time_left': battery.secsleft if battery.secsleft != -1 else None
                    }
            return None
        except Exception as e:
            self.logger.debug(f"Could not get battery info: {e}")
            return None
    
    def collect_metrics(self) -> SystemMetrics:
        """Collect all system metrics"""
        try:
            cpu_info = self.get_cpu_info()
            memory_info = self.get_memory_info()
            disk_info = self.get_disk_info()
            network_info = self.get_network_info()
            process_info = self.get_process_info()
            system_info = self.get_system_info()
            
            # Get network I/O
            network_io = {}
            if 'io_stats' in network_info:
                network_io = network_info['io_stats']
            
            metrics = SystemMetrics(
                timestamp=datetime.now().isoformat(),
                cpu_percent=cpu_info.get('percent', 0),
                memory_percent=memory_info.get('percent', 0),
                disk_usage_percent=disk_info.get('root', {}).get('percent', 0),
                network_io=network_io,
                process_count=len(process_info),
                uptime=system_info.get('uptime', 0),
                load_average=cpu_info.get('load_avg', (0, 0, 0)),
                temperature=self.get_temperature(),
                battery_percent=self.get_battery_info().get('percent') if self.get_battery_info() else None
            )
            
            # Store in history
            self.metrics_history.append(metrics)
            if len(self.metrics_history) > self.max_history_size:
                self.metrics_history.pop(0)
            
            return metrics
            
        except Exception as e:
            self.logger.error(f"Error collecting metrics: {e}")
            return SystemMetrics(
                timestamp=datetime.now().isoformat(),
                cpu_percent=0,
                memory_percent=0,
                disk_usage_percent=0,
                network_io={},
                process_count=0,
                uptime=0,
                load_average=(0, 0, 0)
            )
    
    def check_alerts(self, metrics: SystemMetrics) -> List[str]:
        """Check for alert conditions"""
        alerts = []
        
        if metrics.cpu_percent > self.alert_thresholds['cpu_percent']:
            alerts.append(f"High CPU usage: {metrics.cpu_percent:.1f}%")
        
        if metrics.memory_percent > self.alert_thresholds['memory_percent']:
            alerts.append(f"High memory usage: {metrics.memory_percent:.1f}%")
        
        if metrics.disk_usage_percent > self.alert_thresholds['disk_percent']:
            alerts.append(f"High disk usage: {metrics.disk_usage_percent:.1f}%")
        
        if metrics.temperature and metrics.temperature > self.alert_thresholds['temperature']:
            alerts.append(f"High temperature: {metrics.temperature:.1f}°C")
        
        return alerts
    
    def generate_report(self, metrics: SystemMetrics) -> Dict:
        """Generate a comprehensive system report"""
        alerts = self.check_alerts(metrics)
        
        report = {
            'timestamp': metrics.timestamp,
            'metrics': asdict(metrics),
            'alerts': alerts,
            'status': 'WARNING' if alerts else 'OK',
            'summary': {
                'cpu_usage': f"{metrics.cpu_percent:.1f}%",
                'memory_usage': f"{metrics.memory_percent:.1f}%",
                'disk_usage': f"{metrics.disk_usage_percent:.1f}%",
                'processes': metrics.process_count,
                'uptime': f"{metrics.uptime / 3600:.1f} hours"
            }
        }
        
        return report
    
    def save_metrics(self, filename: str = None):
        """Save metrics to file"""
        if not filename:
            filename = f"system_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        try:
            with open(filename, 'w') as f:
                json.dump([asdict(m) for m in self.metrics_history], f, indent=2)
            self.logger.info(f"Metrics saved to {filename}")
        except Exception as e:
            self.logger.error(f"Error saving metrics: {e}")
    
    def monitor_continuously(self, interval: int = 60, duration: int = None):
        """Monitor system continuously"""
        self.logger.info(f"Starting continuous monitoring (interval: {interval}s)")
        
        start_time = time.time()
        iteration = 0
        
        try:
            while True:
                iteration += 1
                self.logger.info(f"Collecting metrics (iteration {iteration})")
                
                metrics = self.collect_metrics()
                report = self.generate_report(metrics)
                
                # Print summary
                print(f"\n{'='*50}")
                print(f"System Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"{'='*50}")
                print(f"CPU Usage: {report['summary']['cpu_usage']}")
                print(f"Memory Usage: {report['summary']['memory_usage']}")
                print(f"Disk Usage: {report['summary']['disk_usage']}")
                print(f"Processes: {report['summary']['processes']}")
                print(f"Uptime: {report['summary']['uptime']}")
                
                if report['alerts']:
                    print(f"\n⚠️  ALERTS:")
                    for alert in report['alerts']:
                        print(f"  - {alert}")
                
                # Check if duration exceeded
                if duration and (time.time() - start_time) > duration:
                    self.logger.info("Monitoring duration completed")
                    break
                
                time.sleep(interval)
                
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
        except Exception as e:
            self.logger.error(f"Error in continuous monitoring: {e}")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='System Monitor')
    parser.add_argument('--interval', type=int, default=60, help='Monitoring interval in seconds')
    parser.add_argument('--duration', type=int, help='Monitoring duration in seconds')
    parser.add_argument('--save', action='store_true', help='Save metrics to file')
    parser.add_argument('--once', action='store_true', help='Collect metrics once and exit')
    parser.add_argument('--config', type=str, help='Configuration file path')
    
    args = parser.parse_args()
    
    # Load configuration
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    # Create monitor instance
    monitor = SystemMonitor(config)
    
    if args.once:
        # Collect metrics once
        metrics = monitor.collect_metrics()
        report = monitor.generate_report(metrics)
        print(json.dumps(report, indent=2))
        
        if args.save:
            monitor.save_metrics()
    else:
        # Continuous monitoring
        monitor.monitor_continuously(args.interval, args.duration)
        
        if args.save:
            monitor.save_metrics()


if __name__ == "__main__":
    main() 