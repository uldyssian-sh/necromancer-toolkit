# Necromancer Toolkit API Reference

## Overview

The Necromancer Toolkit provides enterprise-grade automation and monitoring capabilities through a comprehensive Python API. This reference documents all available classes, methods, and configuration options.

## Table of Contents

- [Advanced Monitoring System](#advanced-monitoring-system)
- [Infrastructure Adapter](#infrastructure-adapter)
- [Configuration](#configuration)
- [Examples](#examples)
- [Error Handling](#error-handling)

## Advanced Monitoring System

### Class: `AdvancedMonitoringSystem`

Enterprise-grade monitoring system for distributed applications and infrastructure.

#### Constructor

```python
AdvancedMonitoringSystem(config_path: str = None)
```

**Parameters:**
- `config_path` (str, optional): Path to configuration file

#### Methods

##### `start_monitoring()`

Starts the monitoring system with all configured collectors and alert evaluators.

```python
system = AdvancedMonitoringSystem()
system.start_monitoring()
```

**Returns:** None

**Raises:**
- `RuntimeError`: If system is already running
- `ConfigurationError`: If configuration is invalid

##### `stop_monitoring()`

Stops the monitoring system and cleans up resources.

```python
system.stop_monitoring()
```

##### `add_monitoring_rule(rule: MonitoringRule)`

Adds a new monitoring rule for alert evaluation.

```python
rule = MonitoringRule(
    id="high_cpu",
    name="High CPU Usage",
    target_type=MonitoringTarget.SYSTEM,
    metric_name="system_cpu_usage_percent",
    condition="> 80",
    threshold=80,
    duration=300,
    severity=AlertSeverity.WARNING
)
system.add_monitoring_rule(rule)
```

**Parameters:**
- `rule` (MonitoringRule): Monitoring rule configuration

##### `add_monitoring_endpoint(endpoint: MonitoringEndpoint)`

Adds an HTTP endpoint for health monitoring.

```python
endpoint = MonitoringEndpoint(
    id="api_health",
    name="API Health Check",
    url="https://api.example.com/health",
    type=MonitoringTarget.APPLICATION,
    check_interval=60
)
system.add_monitoring_endpoint(endpoint)
```

##### `get_metrics(metric_name: str = None, start_time: datetime = None, end_time: datetime = None) -> List[Metric]`

Retrieves metrics with optional filtering.

```python
# Get all metrics from last hour
metrics = system.get_metrics(
    start_time=datetime.now() - timedelta(hours=1)
)

# Get specific metric
cpu_metrics = system.get_metrics(metric_name="system_cpu_usage_percent")
```

**Parameters:**
- `metric_name` (str, optional): Filter by metric name
- `start_time` (datetime, optional): Start time for filtering
- `end_time` (datetime, optional): End time for filtering

**Returns:** List of Metric objects

##### `get_alerts(severity: AlertSeverity = None, resolved: bool = None) -> List[Alert]`

Retrieves alerts with optional filtering.

```python
# Get all critical alerts
critical_alerts = system.get_alerts(severity=AlertSeverity.CRITICAL)

# Get unresolved alerts
active_alerts = system.get_alerts(resolved=False)
```

##### `get_system_health_summary() -> Dict[str, Any]`

Returns overall system health summary.

```python
health = system.get_system_health_summary()
print(f"Health Status: {health['health_status']}")
print(f"CPU Usage: {health['system_metrics']['cpu_usage_percent']}%")
```

**Returns:** Dictionary with health information

### Data Classes

#### `Metric`

Represents a single metric data point.

```python
@dataclass
class Metric:
    name: str
    type: MetricType
    value: Union[int, float]
    timestamp: datetime
    labels: Dict[str, str] = field(default_factory=dict)
    unit: str = ""
    description: str = ""
```

#### `Alert`

Represents an alert instance.

```python
@dataclass
class Alert:
    id: str
    name: str
    severity: AlertSeverity
    message: str
    timestamp: datetime
    source: str
    labels: Dict[str, str] = field(default_factory=dict)
    resolved: bool = False
    resolved_at: Optional[datetime] = None
```

#### `MonitoringRule`

Configuration for monitoring rules.

```python
@dataclass
class MonitoringRule:
    id: str
    name: str
    target_type: MonitoringTarget
    metric_name: str
    condition: str
    threshold: Union[int, float]
    duration: int
    severity: AlertSeverity
    enabled: bool = True
    labels: Dict[str, str] = field(default_factory=dict)
```

### Enums

#### `MetricType`

```python
class MetricType(Enum):
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"
```

#### `AlertSeverity`

```python
class AlertSeverity(Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
```

#### `MonitoringTarget`

```python
class MonitoringTarget(Enum):
    SYSTEM = "system"
    APPLICATION = "application"
    NETWORK = "network"
    DATABASE = "database"
    CONTAINER = "container"
    KUBERNETES = "kubernetes"
    CUSTOM = "custom"
```

## Infrastructure Adapter

### Class: `InfrastructureAdapter`

Adapter for integrating infrastructure orchestration capabilities.

#### Constructor

```python
InfrastructureAdapter(config: Dict[str, Any] = None)
```

#### Methods

##### `integrate_orchestration_capabilities() -> Dict[str, Any]`

Integrates infrastructure orchestration capabilities.

```python
adapter = InfrastructureAdapter()
result = await adapter.integrate_orchestration_capabilities()
print(f"Integration Status: {result['status']}")
```

##### `deploy_infrastructure(deployment_spec: Dict[str, Any]) -> Dict[str, Any]`

Deploys infrastructure based on specification.

```python
spec = {
    'name': 'web-application',
    'resources': [
        {'name': 'web-server', 'type': 'compute', 'provider': 'aws'},
        {'name': 'database', 'type': 'database', 'provider': 'aws'}
    ]
}

result = await adapter.deploy_infrastructure(spec)
```

##### `get_infrastructure_status() -> Dict[str, Any]`

Returns current infrastructure status.

```python
status = adapter.get_infrastructure_status()
print(f"Total Resources: {status['summary']['total_resources']}")
```

## Configuration

### Monitoring System Configuration

```json
{
  "collection_interval": 60,
  "retention_days": 30,
  "max_workers": 20,
  "alert_channels": {
    "email": {
      "enabled": true,
      "smtp_server": "smtp.example.com",
      "recipients": ["admin@example.com"]
    },
    "slack": {
      "enabled": true,
      "webhook_url": "https://hooks.slack.com/...",
      "channels": ["#alerts"]
    }
  },
  "storage": {
    "type": "memory",
    "max_size_mb": 1000
  }
}
```

### Infrastructure Adapter Configuration

```json
{
  "supported_providers": ["aws", "azure", "gcp", "vmware"],
  "orchestration_features": {
    "multi_cloud_deployment": true,
    "automated_scaling": true,
    "disaster_recovery": true,
    "cost_optimization": true
  },
  "integration_settings": {
    "sync_interval": 300,
    "retry_attempts": 3,
    "timeout": 60
  }
}
```

## Examples

### Basic Monitoring Setup

```python
import asyncio
from necromancer_toolkit import AdvancedMonitoringSystem, MonitoringRule, AlertSeverity, MonitoringTarget

async def main():
    # Initialize monitoring system
    system = AdvancedMonitoringSystem()
    
    # Add monitoring rules
    cpu_rule = MonitoringRule(
        id="high_cpu",
        name="High CPU Usage",
        target_type=MonitoringTarget.SYSTEM,
        metric_name="system_cpu_usage_percent",
        condition="> 80",
        threshold=80,
        duration=300,
        severity=AlertSeverity.WARNING
    )
    system.add_monitoring_rule(cpu_rule)
    
    # Start monitoring
    system.start_monitoring()
    
    try:
        # Run for 1 hour
        await asyncio.sleep(3600)
    finally:
        system.stop_monitoring()

if __name__ == "__main__":
    asyncio.run(main())
```

### Infrastructure Deployment

```python
import asyncio
from necromancer_toolkit import InfrastructureAdapter

async def deploy_web_app():
    adapter = InfrastructureAdapter()
    
    # Integration
    integration_result = await adapter.integrate_orchestration_capabilities()
    if integration_result['status'] != 'success':
        print("Integration failed")
        return
    
    # Deployment specification
    deployment_spec = {
        'name': 'web-application',
        'resources': [
            {
                'name': 'web-server-01',
                'type': 'compute',
                'provider': 'aws',
                'region': 'us-east-1',
                'metadata': {
                    'instance_type': 't3.medium',
                    'ami': 'ami-12345678'
                }
            },
            {
                'name': 'database-01',
                'type': 'database',
                'provider': 'aws',
                'region': 'us-east-1',
                'metadata': {
                    'engine': 'postgresql',
                    'version': '13.7'
                }
            }
        ]
    }
    
    # Deploy infrastructure
    result = await adapter.deploy_infrastructure(deployment_spec)
    print(f"Deployment Status: {result['status']}")
    print(f"Resources Created: {len(result['resources_created'])}")

if __name__ == "__main__":
    asyncio.run(deploy_web_app())
```

## Error Handling

### Common Exceptions

#### `ConfigurationError`

Raised when configuration is invalid or missing required parameters.

```python
try:
    system = AdvancedMonitoringSystem("invalid_config.json")
except ConfigurationError as e:
    print(f"Configuration error: {e}")
```

#### `ConnectionError`

Raised when unable to connect to external services.

```python
try:
    await adapter.integrate_orchestration_capabilities()
except ConnectionError as e:
    print(f"Connection failed: {e}")
```

#### `ValidationError`

Raised when input validation fails.

```python
try:
    system.add_monitoring_rule(invalid_rule)
except ValidationError as e:
    print(f"Validation failed: {e}")
```

### Best Practices

1. **Always use try-catch blocks** for external operations
2. **Validate configuration** before starting services
3. **Implement proper cleanup** in finally blocks
4. **Use logging** for debugging and monitoring
5. **Handle timeouts** for long-running operations

## Performance Considerations

### Monitoring System

- **Collection Interval**: Balance between accuracy and performance
- **Retention Period**: Longer retention requires more memory
- **Worker Threads**: More workers improve concurrency but use more resources
- **Alert Rules**: Complex rules impact evaluation performance

### Infrastructure Adapter

- **Connection Pooling**: Reuse connections for better performance
- **Batch Operations**: Group multiple operations when possible
- **Caching**: Cache frequently accessed data
- **Async Operations**: Use async/await for I/O operations

## Security Considerations

1. **Credential Management**: Never hardcode credentials
2. **SSL/TLS**: Always use encrypted connections
3. **Input Validation**: Validate all user inputs
4. **Access Control**: Implement proper authentication and authorization
5. **Audit Logging**: Log all security-relevant events

---

**Use of this code is at your own risk.**
**Author bears no responsibility for any damages caused by the code.**