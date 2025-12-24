#!/usr/bin/env python3
"""
Advanced Monitoring System - Enterprise-grade Infrastructure Monitoring
Comprehensive monitoring solution for distributed systems and applications.

Use of this code is at your own risk.
Author bears no responsibility for any damages caused by the code.
"""

import os
import sys
import json
import time
import asyncio
import logging
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, asdict, field
from enum import Enum
import statistics
import subprocess
import psutil
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

class MetricType(Enum):
    """Types of metrics that can be collected."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"

class AlertSeverity(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"

class MonitoringTarget(Enum):
    """Types of monitoring targets."""
    SYSTEM = "system"
    APPLICATION = "application"
    NETWORK = "network"
    DATABASE = "database"
    CONTAINER = "container"
    KUBERNETES = "kubernetes"
    CUSTOM = "custom"

@dataclass
class Metric:
    """Metric data structure."""
    name: str
    type: MetricType
    value: Union[int, float]
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)
    unit: str = ""
    description: str = ""

@dataclass
class Alert:
    """Alert data structure."""
    id: str
    name: str
    severity: AlertSeverity
    message: str
    timestamp: datetime
    source: str
    labels: Dict[str, str] = field(default_factory=dict)
    resolved: bool = False
    resolved_at: Optional[datetime] = None

@dataclass
class MonitoringRule:
    """Monitoring rule configuration."""
    id: str
    name: str
    target_type: MonitoringTarget
    metric_name: str
    condition: str  # e.g., "> 80", "< 10", "== 0"
    threshold: Union[int, float]
    duration: int  # seconds
    severity: AlertSeverity
    enabled: bool = True
    labels: Dict[str, str] = field(default_factory=dict)

@dataclass
class MonitoringEndpoint:
    """Monitoring endpoint configuration."""
    id: str
    name: str
    url: str
    type: MonitoringTarget
    check_interval: int = 60
    timeout: int = 30
    expected_status: int = 200
    enabled: bool = True
    headers: Dict[str, str] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)

class AdvancedMonitoringSystem:
    """Enterprise-grade monitoring system."""
    
    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.metrics_store = {}
        self.alerts = {}
        self.rules = {}
        self.endpoints = {}
        self.collectors = {}
        self.logger = self._setup_logging()
        self.executor = ThreadPoolExecutor(max_workers=self.config.get("max_workers", 20))
        self.running = False
        self.collection_threads = []
        
    def _load_config(self, config_path: str) -> Dict:
        """Load monitoring system configuration."""
        default_config = {
            "collection_interval": 60,
            "retention_days": 30,
            "max_workers": 20,
            "alert_channels": {
                "email": {
                    "enabled": False,
                    "smtp_server": "",
                    "smtp_port": 587,
                    "username": "",
                    "password": "",
                    "recipients": []
                },
                "slack": {
                    "enabled": False,
                    "webhook_url": "",
                    "channels": ["#alerts"]
                },
                "webhook": {
                    "enabled": False,
                    "url": "",
                    "headers": {}
                }
            },
            "storage": {
                "type": "memory",  # memory, file, database
                "path": "/tmp/monitoring_data",
                "max_size_mb": 1000
            },
            "dashboards": {
                "enabled": True,
                "port": 8080,
                "refresh_interval": 30
            },
            "exporters": {
                "prometheus": {
                    "enabled": False,
                    "port": 9090,
                    "path": "/metrics"
                },
                "graphite": {
                    "enabled": False,
                    "host": "localhost",
                    "port": 2003
                }
            }
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                default_config = self._deep_merge(default_config, user_config)
        
        return default_config
    
    def _deep_merge(self, base: Dict, update: Dict) -> Dict:
        """Deep merge two dictionaries."""
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                base[key] = self._deep_merge(base[key], value)
            else:
                base[key] = value
        return base
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger('AdvancedMonitoringSystem')
        logger.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
        
        # File handler
        log_dir = self.config["storage"]["path"]
        os.makedirs(log_dir, exist_ok=True)
        file_handler = logging.FileHandler(os.path.join(log_dir, 'monitoring.log'))
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
        
        return logger
    
    def add_monitoring_rule(self, rule: MonitoringRule):
        """Add monitoring rule."""
        self.rules[rule.id] = rule
        self.logger.info(f"Added monitoring rule: {rule.name}")
    
    def add_monitoring_endpoint(self, endpoint: MonitoringEndpoint):
        """Add monitoring endpoint."""
        self.endpoints[endpoint.id] = endpoint
        self.logger.info(f"Added monitoring endpoint: {endpoint.name}")
    
    def start_monitoring(self):
        """Start the monitoring system."""
        if self.running:
            self.logger.warning("Monitoring system is already running")
            return
        
        self.running = True
        self.logger.info("Starting monitoring system")
        
        # Start system metrics collection
        system_thread = threading.Thread(target=self._collect_system_metrics_loop)
        system_thread.daemon = True
        system_thread.start()
        self.collection_threads.append(system_thread)
        
        # Start endpoint monitoring
        endpoint_thread = threading.Thread(target=self._monitor_endpoints_loop)
        endpoint_thread.daemon = True
        endpoint_thread.start()
        self.collection_threads.append(endpoint_thread)
        
        # Start alert evaluation
        alert_thread = threading.Thread(target=self._evaluate_alerts_loop)
        alert_thread.daemon = True
        alert_thread.start()
        self.collection_threads.append(alert_thread)
        
        # Start cleanup task
        cleanup_thread = threading.Thread(target=self._cleanup_old_data_loop)
        cleanup_thread.daemon = True
        cleanup_thread.start()
        self.collection_threads.append(cleanup_thread)
        
        self.logger.info("Monitoring system started successfully")
    
    def stop_monitoring(self):
        """Stop the monitoring system."""
        if not self.running:
            return
        
        self.running = False
        self.logger.info("Stopping monitoring system")
        
        # Wait for threads to finish
        for thread in self.collection_threads:
            thread.join(timeout=5)
        
        self.collection_threads.clear()
        self.logger.info("Monitoring system stopped")
    
    def _collect_system_metrics_loop(self):
        """Continuously collect system metrics."""
        while self.running:
            try:
                self._collect_system_metrics()
                time.sleep(self.config["collection_interval"])
            except Exception as e:
                self.logger.error(f"Error collecting system metrics: {e}")
                time.sleep(10)
    
    def _collect_system_metrics(self):
        """Collect system performance metrics."""
        timestamp = datetime.now()
        
        # Memory leak detection
        self._detect_memory_leaks()
        
        # CPU metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        self._store_metric(Metric(
            name="system_cpu_usage_percent",
            type=MetricType.GAUGE,
            value=cpu_percent,
            timestamp=timestamp,
            labels={"host": socket.gethostname()},
            unit="percent",
            description="CPU usage percentage"
        ))
        
        # Memory metrics
        memory = psutil.virtual_memory()
        self._store_metric(Metric(
            name="system_memory_usage_percent",
            type=MetricType.GAUGE,
            value=memory.percent,
            timestamp=timestamp,
            labels={"host": socket.gethostname()},
            unit="percent",
            description="Memory usage percentage"
        ))
        
        self._store_metric(Metric(
            name="system_memory_available_bytes",
            type=MetricType.GAUGE,
            value=memory.available,
            timestamp=timestamp,
            labels={"host": socket.gethostname()},
            unit="bytes",
            description="Available memory in bytes"
        ))
        
        # Disk metrics
        disk = psutil.disk_usage('/')
        self._store_metric(Metric(
            name="system_disk_usage_percent",
            type=MetricType.GAUGE,
            value=(disk.used / disk.total) * 100,
            timestamp=timestamp,
            labels={"host": socket.gethostname(), "mount": "/"},
            unit="percent",
            description="Disk usage percentage"
        ))
        
        # Network metrics
        network = psutil.net_io_counters()
        self._store_metric(Metric(
            name="system_network_bytes_sent",
            type=MetricType.COUNTER,
            value=network.bytes_sent,
            timestamp=timestamp,
            labels={"host": socket.gethostname()},
            unit="bytes",
            description="Total bytes sent over network"
        ))
        
        self._store_metric(Metric(
            name="system_network_bytes_received",
            type=MetricType.COUNTER,
            value=network.bytes_recv,
            timestamp=timestamp,
            labels={"host": socket.gethostname()},
            unit="bytes",
            description="Total bytes received over network"
        ))
        
        # Load average (Unix-like systems)
        try:
            load_avg = os.getloadavg()
            for i, period in enumerate(['1m', '5m', '15m']):
                self._store_metric(Metric(
                    name=f"system_load_average_{period}",
                    type=MetricType.GAUGE,
                    value=load_avg[i],
                    timestamp=timestamp,
                    labels={"host": socket.gethostname()},
                    description=f"System load average over {period}"
                ))
        except (OSError, AttributeError):
            # Not available on Windows
            pass
        
        # Process count
        process_count = len(psutil.pids())
        self._store_metric(Metric(
            name="system_process_count",
            type=MetricType.GAUGE,
            value=process_count,
            timestamp=timestamp,
            labels={"host": socket.gethostname()},
            description="Number of running processes"
        ))
    
    def _monitor_endpoints_loop(self):
        """Continuously monitor endpoints."""
        while self.running:
            try:
                futures = []
                for endpoint in self.endpoints.values():
                    if endpoint.enabled:
                        future = self.executor.submit(self._check_endpoint, endpoint)
                        futures.append(future)
                
                # Wait for all checks to complete
                for future in as_completed(futures, timeout=60):
                    try:
                        future.result()
                    except Exception as e:
                        self.logger.error(f"Endpoint check failed: {e}")
                
                time.sleep(min([ep.check_interval for ep in self.endpoints.values()] + [60]))
                
            except Exception as e:
                self.logger.error(f"Error in endpoint monitoring loop: {e}")
                time.sleep(30)
    
    def _check_endpoint(self, endpoint: MonitoringEndpoint):
        """Check individual endpoint health."""
        start_time = time.time()
        timestamp = datetime.now()
        
        try:
            response = requests.get(
                endpoint.url,
                headers=endpoint.headers,
                timeout=endpoint.timeout
            )
            
            response_time = (time.time() - start_time) * 1000  # milliseconds
            
            # Store response time metric
            self._store_metric(Metric(
                name="endpoint_response_time_ms",
                type=MetricType.HISTOGRAM,
                value=response_time,
                timestamp=timestamp,
                labels={
                    "endpoint": endpoint.name,
                    "url": endpoint.url,
                    **endpoint.labels
                },
                unit="milliseconds",
                description="HTTP endpoint response time"
            ))
            
            # Store status code metric
            self._store_metric(Metric(
                name="endpoint_status_code",
                type=MetricType.GAUGE,
                value=response.status_code,
                timestamp=timestamp,
                labels={
                    "endpoint": endpoint.name,
                    "url": endpoint.url,
                    **endpoint.labels
                },
                description="HTTP endpoint status code"
            ))
            
            # Store availability metric
            is_available = 1 if response.status_code == endpoint.expected_status else 0
            self._store_metric(Metric(
                name="endpoint_availability",
                type=MetricType.GAUGE,
                value=is_available,
                timestamp=timestamp,
                labels={
                    "endpoint": endpoint.name,
                    "url": endpoint.url,
                    **endpoint.labels
                },
                description="Endpoint availability (1=up, 0=down)"
            ))
            
        except requests.exceptions.RequestException as e:
            # Store failed request metric
            self._store_metric(Metric(
                name="endpoint_availability",
                type=MetricType.GAUGE,
                value=0,
                timestamp=timestamp,
                labels={
                    "endpoint": endpoint.name,
                    "url": endpoint.url,
                    "error": str(e),
                    **endpoint.labels
                },
                description="Endpoint availability (1=up, 0=down)"
            ))
            
            self.logger.warning(f"Endpoint {endpoint.name} check failed: {e}")
    
    def _evaluate_alerts_loop(self):
        """Continuously evaluate alert rules."""
        while self.running:
            try:
                for rule in self.rules.values():
                    if rule.enabled:
                        self._evaluate_alert_rule(rule)
                
                time.sleep(30)  # Check alerts every 30 seconds
                
            except Exception as e:
                self.logger.error(f"Error in alert evaluation loop: {e}")
                time.sleep(60)
    
    def _evaluate_alert_rule(self, rule: MonitoringRule):
        """Evaluate individual alert rule."""
        # Get recent metrics for the rule
        recent_metrics = self._get_recent_metrics(
            rule.metric_name, 
            timedelta(seconds=rule.duration)
        )
        
        if not recent_metrics:
            return
        
        # Evaluate condition
        triggered = False
        latest_value = recent_metrics[-1].value
        
        if rule.condition.startswith('>'):
            triggered = latest_value > rule.threshold
        elif rule.condition.startswith('<'):
            triggered = latest_value < rule.threshold
        elif rule.condition.startswith('=='):
            triggered = latest_value == rule.threshold
        elif rule.condition.startswith('!='):
            triggered = latest_value != rule.threshold
        elif rule.condition.startswith('>='):
            triggered = latest_value >= rule.threshold
        elif rule.condition.startswith('<='):
            triggered = latest_value <= rule.threshold
        
        alert_id = f"alert_{rule.id}_{int(time.time())}"
        
        if triggered:
            # Check if alert already exists and is not resolved
            existing_alert = None
            for alert in self.alerts.values():
                if (alert.source == rule.id and not alert.resolved):
                    existing_alert = alert
                    break
            
            if not existing_alert:
                # Create new alert
                alert = Alert(
                    id=alert_id,
                    name=rule.name,
                    severity=rule.severity,
                    message=f"{rule.name}: {rule.metric_name} {rule.condition} {rule.threshold} (current: {latest_value})",
                    timestamp=datetime.now(),
                    source=rule.id,
                    labels=rule.labels
                )
                
                self.alerts[alert_id] = alert
                self._send_alert_notification(alert)
                self.logger.warning(f"Alert triggered: {alert.message}")
        else:
            # Check if there's an existing alert to resolve
            for alert in self.alerts.values():
                if (alert.source == rule.id and not alert.resolved):
                    alert.resolved = True
                    alert.resolved_at = datetime.now()
                    self._send_alert_resolution_notification(alert)
                    self.logger.info(f"Alert resolved: {alert.message}")
    
    def _store_metric(self, metric: Metric):
        """Store metric in the metrics store."""
        metric_key = f"{metric.name}_{hash(str(metric.labels))}"
        
        if metric_key not in self.metrics_store:
            self.metrics_store[metric_key] = []
        
        self.metrics_store[metric_key].append(metric)
        
        # Limit stored metrics to prevent memory issues
        max_metrics_per_key = 1000
        if len(self.metrics_store[metric_key]) > max_metrics_per_key:
            self.metrics_store[metric_key] = self.metrics_store[metric_key][-max_metrics_per_key:]
    
    def _get_recent_metrics(self, metric_name: str, duration: timedelta) -> List[Metric]:
        """Get recent metrics for a specific metric name."""
        cutoff_time = datetime.now() - duration
        recent_metrics = []
        
        for metric_key, metrics in self.metrics_store.items():
            if metric_name in metric_key:
                for metric in metrics:
                    if metric.timestamp >= cutoff_time:
                        recent_metrics.append(metric)
        
        return sorted(recent_metrics, key=lambda x: x.timestamp)
    
    def _send_alert_notification(self, alert: Alert):
        """Send alert notification through configured channels."""
        # Email notification
        if self.config["alert_channels"]["email"]["enabled"]:
            self._send_email_alert(alert)
        
        # Slack notification
        if self.config["alert_channels"]["slack"]["enabled"]:
            self._send_slack_alert(alert)
        
        # Webhook notification
        if self.config["alert_channels"]["webhook"]["enabled"]:
            self._send_webhook_alert(alert)
    
    def _send_alert_resolution_notification(self, alert: Alert):
        """Send alert resolution notification."""
        resolution_message = f"RESOLVED: {alert.message}"
        self.logger.info(f"Sending resolution notification: {resolution_message}")
        # Implementation would send actual notifications
    
    def _send_email_alert(self, alert: Alert):
        """Send email alert notification."""
        self.logger.info(f"Sending email alert: {alert.message}")
        # Implementation would use SMTP to send email
    
    def _send_slack_alert(self, alert: Alert):
        """Send Slack alert notification."""
        self.logger.info(f"Sending Slack alert: {alert.message}")
        # Implementation would use Slack webhook
    
    def _send_webhook_alert(self, alert: Alert):
        """Send webhook alert notification."""
        self.logger.info(f"Sending webhook alert: {alert.message}")
        # Implementation would send HTTP POST to webhook URL
    
    def _cleanup_old_data_loop(self):
        """Continuously clean up old monitoring data."""
        while self.running:
            try:
                self._cleanup_old_metrics()
                self._cleanup_old_alerts()
                time.sleep(3600)  # Run cleanup every hour
            except Exception as e:
                self.logger.error(f"Error in cleanup loop: {e}")
                time.sleep(3600)
    
    def _cleanup_old_metrics(self):
        """Clean up old metrics based on retention policy."""
        retention_days = self.config.get("retention_days", 30)
        cutoff_time = datetime.now() - timedelta(days=retention_days)
        
        metrics_removed = 0
        for metric_key in list(self.metrics_store.keys()):
            metrics = self.metrics_store[metric_key]
            filtered_metrics = [m for m in metrics if m.timestamp >= cutoff_time]
            
            if len(filtered_metrics) != len(metrics):
                metrics_removed += len(metrics) - len(filtered_metrics)
                self.metrics_store[metric_key] = filtered_metrics
                
                # Remove empty metric keys
                if not filtered_metrics:
                    del self.metrics_store[metric_key]
        
        if metrics_removed > 0:
            self.logger.info(f"Cleaned up {metrics_removed} old metrics")
    
    def _cleanup_old_alerts(self):
        """Clean up old resolved alerts."""
        retention_days = self.config.get("retention_days", 30)
        cutoff_time = datetime.now() - timedelta(days=retention_days)
        
        alerts_removed = 0
        for alert_id in list(self.alerts.keys()):
            alert = self.alerts[alert_id]
            if alert.resolved and alert.resolved_at and alert.resolved_at < cutoff_time:
                del self.alerts[alert_id]
                alerts_removed += 1
        
        if alerts_removed > 0:
            self.logger.info(f"Cleaned up {alerts_removed} old alerts")
    
    def get_metrics(self, metric_name: str = None, 
                   start_time: datetime = None, 
                   end_time: datetime = None,
                   labels: Dict[str, str] = None) -> List[Metric]:
        """Query metrics with optional filtering."""
        if end_time is None:
            end_time = datetime.now()
        if start_time is None:
            start_time = end_time - timedelta(hours=1)
        
        filtered_metrics = []
        
        for metric_key, metrics in self.metrics_store.items():
            for metric in metrics:
                # Filter by time range
                if not (start_time <= metric.timestamp <= end_time):
                    continue
                
                # Filter by metric name
                if metric_name and metric.name != metric_name:
                    continue
                
                # Filter by labels
                if labels:
                    if not all(metric.labels.get(k) == v for k, v in labels.items()):
                        continue
                
                filtered_metrics.append(metric)
        
        return sorted(filtered_metrics, key=lambda x: x.timestamp)
    
    def get_alerts(self, severity: AlertSeverity = None, 
                  resolved: bool = None,
                  start_time: datetime = None,
                  end_time: datetime = None) -> List[Alert]:
        """Query alerts with optional filtering."""
        filtered_alerts = []
        
        for alert in self.alerts.values():
            # Filter by severity
            if severity and alert.severity != severity:
                continue
            
            # Filter by resolved status
            if resolved is not None and alert.resolved != resolved:
                continue
            
            # Filter by time range
            if start_time and alert.timestamp < start_time:
                continue
            if end_time and alert.timestamp > end_time:
                continue
            
            filtered_alerts.append(alert)
        
        return sorted(filtered_alerts, key=lambda x: x.timestamp, reverse=True)
    
    def get_system_health_summary(self) -> Dict:
        """Get overall system health summary."""
        now = datetime.now()
        last_hour = now - timedelta(hours=1)
        
        # Get recent system metrics
        cpu_metrics = self.get_metrics("system_cpu_usage_percent", last_hour, now)
        memory_metrics = self.get_metrics("system_memory_usage_percent", last_hour, now)
        disk_metrics = self.get_metrics("system_disk_usage_percent", last_hour, now)
        
        # Calculate averages
        avg_cpu = statistics.mean([m.value for m in cpu_metrics]) if cpu_metrics else 0
        avg_memory = statistics.mean([m.value for m in memory_metrics]) if memory_metrics else 0
        avg_disk = statistics.mean([m.value for m in disk_metrics]) if disk_metrics else 0
        
        # Get active alerts
        active_alerts = self.get_alerts(resolved=False)
        critical_alerts = [a for a in active_alerts if a.severity == AlertSeverity.CRITICAL]
        warning_alerts = [a for a in active_alerts if a.severity == AlertSeverity.WARNING]
        
        # Determine overall health status
        if critical_alerts:
            health_status = "critical"
        elif warning_alerts or avg_cpu > 90 or avg_memory > 90 or avg_disk > 95:
            health_status = "warning"
        elif avg_cpu > 70 or avg_memory > 70 or avg_disk > 80:
            health_status = "degraded"
        else:
            health_status = "healthy"
        
        return {
            "timestamp": now.isoformat(),
            "health_status": health_status,
            "system_metrics": {
                "cpu_usage_percent": round(avg_cpu, 2),
                "memory_usage_percent": round(avg_memory, 2),
                "disk_usage_percent": round(avg_disk, 2)
            },
            "alerts": {
                "total_active": len(active_alerts),
                "critical": len(critical_alerts),
                "warning": len(warning_alerts),
                "info": len([a for a in active_alerts if a.severity == AlertSeverity.INFO])
            },
            "endpoints": {
                "total": len(self.endpoints),
                "enabled": len([ep for ep in self.endpoints.values() if ep.enabled])
            },
            "monitoring_rules": {
                "total": len(self.rules),
                "enabled": len([r for r in self.rules.values() if r.enabled])
            }
        }
    
    def generate_monitoring_report(self, hours: int = 24) -> Dict:
        """Generate comprehensive monitoring report."""
        end_time = datetime.now()
        start_time = end_time - timedelta(hours=hours)
        
        # Get metrics for the time period
        all_metrics = self.get_metrics(start_time=start_time, end_time=end_time)
        alerts = self.get_alerts(start_time=start_time, end_time=end_time)
        
        # Group metrics by name
        metrics_by_name = {}
        for metric in all_metrics:
            if metric.name not in metrics_by_name:
                metrics_by_name[metric.name] = []
            metrics_by_name[metric.name].append(metric)
        
        # Calculate statistics for each metric
        metric_stats = {}
        for metric_name, metrics in metrics_by_name.items():
            values = [m.value for m in metrics]
            if values:
                metric_stats[metric_name] = {
                    "count": len(values),
                    "min": min(values),
                    "max": max(values),
                    "avg": statistics.mean(values),
                    "median": statistics.median(values)
                }
                
                if len(values) > 1:
                    metric_stats[metric_name]["stddev"] = statistics.stdev(values)
        
        # Alert statistics
        alert_stats = {
            "total": len(alerts),
            "by_severity": {
                "critical": len([a for a in alerts if a.severity == AlertSeverity.CRITICAL]),
                "warning": len([a for a in alerts if a.severity == AlertSeverity.WARNING]),
                "info": len([a for a in alerts if a.severity == AlertSeverity.INFO])
            },
            "resolved": len([a for a in alerts if a.resolved]),
            "active": len([a for a in alerts if not a.resolved])
        }
        
        return {
            "report_period": {
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_hours": hours
            },
            "metric_statistics": metric_stats,
            "alert_statistics": alert_stats,
            "system_health": self.get_system_health_summary(),
            "generated_at": datetime.now().isoformat()
        }


def main():
    """Main function for CLI usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced Monitoring System")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--action", choices=["start", "status", "report", "alerts"], 
                       default="status", help="Action to perform")
    parser.add_argument("--hours", type=int, default=24, help="Hours for report generation")
    parser.add_argument("--daemon", action="store_true", help="Run as daemon")
    
    args = parser.parse_args()
    
    monitoring = AdvancedMonitoringSystem(args.config)
    
    if args.action == "start":
        # Add some default monitoring rules
        monitoring.add_monitoring_rule(MonitoringRule(
            id="high_cpu_usage",
            name="High CPU Usage",
            target_type=MonitoringTarget.SYSTEM,
            metric_name="system_cpu_usage_percent",
            condition="> 80",
            threshold=80,
            duration=300,
            severity=AlertSeverity.WARNING
        ))
        
        monitoring.add_monitoring_rule(MonitoringRule(
            id="high_memory_usage",
            name="High Memory Usage",
            target_type=MonitoringTarget.SYSTEM,
            metric_name="system_memory_usage_percent",
            condition="> 90",
            threshold=90,
            duration=300,
            severity=AlertSeverity.CRITICAL
        ))
        
        # Add sample endpoint
        monitoring.add_monitoring_endpoint(MonitoringEndpoint(
            id="local_health",
            name="Local Health Check",
            url="http://localhost:8080/health",
            type=MonitoringTarget.APPLICATION,
            check_interval=60
        ))
        
        monitoring.start_monitoring()
        
        if args.daemon:
            try:
                while True:
                    time.sleep(60)
            except KeyboardInterrupt:
                monitoring.stop_monitoring()
        else:
            print("Monitoring started. Press Ctrl+C to stop.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                monitoring.stop_monitoring()
    
    elif args.action == "status":
        health = monitoring.get_system_health_summary()
        print(json.dumps(health, indent=2))
    
    elif args.action == "report":
        report = monitoring.generate_monitoring_report(args.hours)
        print(json.dumps(report, indent=2))
    
    elif args.action == "alerts":
        alerts = monitoring.get_alerts()
        print(f"Found {len(alerts)} alerts:")
        for alert in alerts[:20]:  # Show last 20 alerts
            status = "RESOLVED" if alert.resolved else "ACTIVE"
            print(f"  [{alert.severity.value.upper()}] {status}: {alert.message} ({alert.timestamp})")


if __name__ == "__main__":
    main()
    def _detect_memory_leaks(self):
        """Detect potential memory leaks in running processes."""
        try:
            # Track memory usage over time for leak detection
            current_memory = psutil.virtual_memory().percent
            
            # Store memory history for trend analysis
            if not hasattr(self, '_memory_history'):
                self._memory_history = []
            
            self._memory_history.append({
                'timestamp': datetime.now(),
                'memory_percent': current_memory
            })
            
            # Keep only last 100 measurements
            if len(self._memory_history) > 100:
                self._memory_history = self._memory_history[-100:]
            
            # Detect memory leak pattern (consistent increase over time)
            if len(self._memory_history) >= 10:
                recent_values = [m['memory_percent'] for m in self._memory_history[-10:]]
                if all(recent_values[i] <= recent_values[i+1] for i in range(len(recent_values)-1)):
                    # Consistent increase detected
                    increase_rate = (recent_values[-1] - recent_values[0]) / len(recent_values)
                    if increase_rate > 0.5:  # More than 0.5% per measurement
                        self.logger.warning(f"Potential memory leak detected: {increase_rate:.2f}% increase rate")
                        
        except Exception as e:
            self.logger.error(f"Memory leak detection failed: {e}")