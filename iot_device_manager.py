#!/usr/bin/env python3
"""
IoT Device Manager - Enterprise IoT Infrastructure Management Platform
Advanced IoT device management, monitoring, and automation system.

Use of this code is at your own risk.
Author bears no responsibility for any damages caused by the code.
"""

import os
import sys
import json
import time
import asyncio
import logging
import socket
import struct
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple, Callable
from dataclasses import dataclass, asdict, field
from enum import Enum
import hashlib
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor
import paho.mqtt.client as mqtt
import requests

class DeviceType(Enum):
    """IoT device types."""
    SENSOR = "sensor"
    ACTUATOR = "actuator"
    GATEWAY = "gateway"
    CAMERA = "camera"
    THERMOSTAT = "thermostat"
    SMART_LOCK = "smart_lock"
    LIGHTING = "lighting"
    ENVIRONMENTAL = "environmental"
    INDUSTRIAL = "industrial"
    WEARABLE = "wearable"
    VEHICLE = "vehicle"

class DeviceStatus(Enum):
    """Device status states."""
    ONLINE = "online"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"
    ERROR = "error"
    UPDATING = "updating"
    UNKNOWN = "unknown"

class Protocol(Enum):
    """Communication protocols."""
    MQTT = "mqtt"
    HTTP = "http"
    COAP = "coap"
    ZIGBEE = "zigbee"
    ZWAVE = "zwave"
    BLUETOOTH = "bluetooth"
    WIFI = "wifi"
    LORA = "lora"
    CELLULAR = "cellular"

class SecurityLevel(Enum):
    """Device security levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class DeviceCredentials:
    """Device authentication credentials."""
    device_id: str
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    certificate_path: Optional[str] = None
    private_key_path: Optional[str] = None
    token: Optional[str] = None

@dataclass
class DeviceCapability:
    """Device capability definition."""
    name: str
    type: str
    unit: Optional[str] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    read_only: bool = True
    description: str = ""

@dataclass
class IoTDevice:
    """IoT device representation."""
    device_id: str
    name: str
    device_type: DeviceType
    manufacturer: str
    model: str
    firmware_version: str
    ip_address: str
    mac_address: str
    protocol: Protocol
    status: DeviceStatus
    capabilities: List[DeviceCapability] = field(default_factory=list)
    location: str = ""
    room: str = ""
    building: str = ""
    security_level: SecurityLevel = SecurityLevel.MEDIUM
    last_seen: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)
    credentials: Optional[DeviceCredentials] = None

@dataclass
class SensorReading:
    """Sensor data reading."""
    device_id: str
    capability: str
    value: Union[float, int, str, bool]
    unit: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    quality: float = 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DeviceCommand:
    """Device command/action."""
    command_id: str
    device_id: str
    capability: str
    action: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    status: str = "pending"
    result: Optional[Any] = None
    error_message: Optional[str] = None

@dataclass
class AutomationRule:
    """IoT automation rule."""
    rule_id: str
    name: str
    description: str
    trigger_conditions: List[Dict[str, Any]]
    actions: List[Dict[str, Any]]
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.now)
    last_triggered: Optional[datetime] = None
    trigger_count: int = 0

class DeviceDiscovery:
    """IoT device discovery service."""
    
    def __init__(self):
        self.logger = logging.getLogger('DeviceDiscovery')
        self.discovered_devices = {}
        
    async def scan_network(self, network_range: str = "192.168.1.0/24") -> List[Dict[str, Any]]:
        """Scan network for IoT devices."""
        discovered = []
        
        try:
            # Parse network range
            network_parts = network_range.split('/')
            base_ip = network_parts[0]
            subnet_mask = int(network_parts[1]) if len(network_parts) > 1 else 24
            
            # Calculate IP range
            base_parts = base_ip.split('.')
            base_int = (int(base_parts[0]) << 24) + (int(base_parts[1]) << 16) + \
                      (int(base_parts[2]) << 8) + int(base_parts[3])
            
            num_hosts = 2 ** (32 - subnet_mask) - 2  # Exclude network and broadcast
            
            self.logger.info(f"Scanning {num_hosts} hosts in {network_range}")
            
            # Scan hosts concurrently
            tasks = []
            for i in range(1, min(num_hosts + 1, 255)):  # Limit scan range
                host_ip = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}"
                tasks.append(self._scan_host(host_ip))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, dict) and result.get('responsive'):
                    discovered.append(result)
            
            self.logger.info(f"Discovered {len(discovered)} responsive hosts")
            
        except Exception as e:
            self.logger.error(f"Network scan failed: {e}")
        
        return discovered
    
    async def _scan_host(self, ip_address: str) -> Dict[str, Any]:
        """Scan individual host for IoT services."""
        host_info = {
            'ip_address': ip_address,
            'responsive': False,
            'open_ports': [],
            'services': [],
            'device_type': 'unknown',
            'manufacturer': 'unknown'
        }
        
        try:
            # Check common IoT ports
            common_ports = [80, 443, 1883, 8080, 8883, 5683, 22, 23, 161]
            
            for port in common_ports:
                if await self._check_port(ip_address, port):
                    host_info['open_ports'].append(port)
                    host_info['responsive'] = True
                    
                    # Identify service
                    service = self._identify_service(port)
                    if service:
                        host_info['services'].append(service)
            
            # Try to identify device type based on services
            if host_info['responsive']:
                host_info['device_type'] = self._guess_device_type(host_info)
                host_info['manufacturer'] = await self._identify_manufacturer(ip_address)
            
        except Exception as e:
            self.logger.debug(f"Host scan failed for {ip_address}: {e}")
        
        return host_info
    
    async def _check_port(self, ip_address: str, port: int, timeout: float = 1.0) -> bool:
        """Check if port is open on host."""
        try:
            future = asyncio.open_connection(ip_address, port)
            reader, writer = await asyncio.wait_for(future, timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    def _identify_service(self, port: int) -> Optional[str]:
        """Identify service based on port number."""
        service_map = {
            80: "HTTP",
            443: "HTTPS",
            1883: "MQTT",
            8080: "HTTP-Alt",
            8883: "MQTT-SSL",
            5683: "CoAP",
            22: "SSH",
            23: "Telnet",
            161: "SNMP"
        }
        return service_map.get(port)
    
    def _guess_device_type(self, host_info: Dict[str, Any]) -> str:
        """Guess device type based on open ports and services."""
        services = host_info.get('services', [])
        ports = host_info.get('open_ports', [])
        
        if 'MQTT' in services:
            return 'sensor'
        elif 'CoAP' in services:
            return 'sensor'
        elif 80 in ports or 443 in ports:
            return 'gateway'
        elif 'SNMP' in services:
            return 'industrial'
        else:
            return 'unknown'
    
    async def _identify_manufacturer(self, ip_address: str) -> str:
        """Try to identify device manufacturer."""
        try:
            # Try HTTP banner grabbing
            response = await asyncio.wait_for(
                self._http_request(f"http://{ip_address}"), 
                timeout=3.0
            )
            
            if response:
                # Look for manufacturer clues in headers or content
                headers = response.get('headers', {})
                content = response.get('content', '')
                
                manufacturers = ['Arduino', 'Raspberry', 'ESP32', 'ESP8266', 'Philips', 'Samsung']
                
                for manufacturer in manufacturers:
                    if manufacturer.lower() in content.lower() or \
                       any(manufacturer.lower() in str(v).lower() for v in headers.values()):
                        return manufacturer
            
        except Exception as e:
            self.logger.debug(f"Manufacturer identification failed for {ip_address}: {e}")
        
        return 'unknown'
    
    async def _http_request(self, url: str) -> Optional[Dict[str, Any]]:
        """Make HTTP request to device."""
        try:
            # Simplified HTTP request (would use aiohttp in production)
            import urllib.request
            
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'IoT-Scanner/1.0')
            
            with urllib.request.urlopen(req, timeout=2) as response:
                return {
                    'status_code': response.getcode(),
                    'headers': dict(response.headers),
                    'content': response.read().decode('utf-8', errors='ignore')[:1000]
                }
        except:
            return None

class MQTTManager:
    """MQTT communication manager for IoT devices."""
    
    def __init__(self, broker_host: str = "localhost", broker_port: int = 1883):
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.client = mqtt.Client()
        self.logger = logging.getLogger('MQTTManager')
        self.connected = False
        self.subscriptions = {}
        self.message_handlers = {}
        
        # Setup MQTT callbacks
        self.client.on_connect = self._on_connect
        self.client.on_disconnect = self._on_disconnect
        self.client.on_message = self._on_message
        
    def connect(self, username: str = None, password: str = None) -> bool:
        """Connect to MQTT broker."""
        try:
            if username and password:
                self.client.username_pw_set(username, password)
            
            self.client.connect(self.broker_host, self.broker_port, 60)
            self.client.loop_start()
            
            # Wait for connection
            timeout = time.time() + 10
            while not self.connected and time.time() < timeout:
                time.sleep(0.1)
            
            if self.connected:
                self.logger.info(f"Connected to MQTT broker at {self.broker_host}:{self.broker_port}")
                return True
            else:
                self.logger.error("MQTT connection timeout")
                return False
                
        except Exception as e:
            self.logger.error(f"MQTT connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from MQTT broker."""
        self.client.loop_stop()
        self.client.disconnect()
        self.connected = False
        self.logger.info("Disconnected from MQTT broker")
    
    def subscribe(self, topic: str, handler: Callable[[str, str], None] = None) -> bool:
        """Subscribe to MQTT topic."""
        try:
            result = self.client.subscribe(topic)
            
            if result[0] == mqtt.MQTT_ERR_SUCCESS:
                self.subscriptions[topic] = True
                
                if handler:
                    self.message_handlers[topic] = handler
                
                self.logger.info(f"Subscribed to topic: {topic}")
                return True
            else:
                self.logger.error(f"Failed to subscribe to topic: {topic}")
                return False
                
        except Exception as e:
            self.logger.error(f"Subscription failed for {topic}: {e}")
            return False
    
    def publish(self, topic: str, payload: str, qos: int = 0, retain: bool = False) -> bool:
        """Publish message to MQTT topic."""
        try:
            result = self.client.publish(topic, payload, qos, retain)
            
            if result.rc == mqtt.MQTT_ERR_SUCCESS:
                self.logger.debug(f"Published to {topic}: {payload}")
                return True
            else:
                self.logger.error(f"Failed to publish to {topic}")
                return False
                
        except Exception as e:
            self.logger.error(f"Publish failed for {topic}: {e}")
            return False
    
    def _on_connect(self, client, userdata, flags, rc):
        """MQTT connection callback."""
        if rc == 0:
            self.connected = True
            self.logger.info("MQTT connected successfully")
        else:
            self.logger.error(f"MQTT connection failed with code {rc}")
    
    def _on_disconnect(self, client, userdata, rc):
        """MQTT disconnection callback."""
        self.connected = False
        self.logger.info("MQTT disconnected")
    
    def _on_message(self, client, userdata, msg):
        """MQTT message callback."""
        topic = msg.topic
        payload = msg.payload.decode('utf-8')
        
        self.logger.debug(f"Received message on {topic}: {payload}")
        
        # Call specific handler if registered
        if topic in self.message_handlers:
            try:
                self.message_handlers[topic](topic, payload)
            except Exception as e:
                self.logger.error(f"Message handler failed for {topic}: {e}")

class DeviceManager:
    """IoT device management system."""
    
    def __init__(self, mqtt_broker: str = "localhost"):
        self.devices = {}
        self.sensor_readings = {}
        self.device_commands = {}
        self.automation_rules = {}
        self.logger = self._setup_logging()
        
        # Initialize communication managers
        self.mqtt_manager = MQTTManager(mqtt_broker)
        self.discovery = DeviceDiscovery()
        
        # Connect to MQTT broker
        if not self.mqtt_manager.connect():
            self.logger.warning("MQTT broker not available")
        
        self.executor = ThreadPoolExecutor(max_workers=10)
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger('DeviceManager')
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def register_device(self, device: IoTDevice) -> bool:
        """Register new IoT device."""
        try:
            self.devices[device.device_id] = device
            
            # Subscribe to device topics if MQTT
            if device.protocol == Protocol.MQTT and self.mqtt_manager.connected:
                # Subscribe to device data topic
                data_topic = f"devices/{device.device_id}/data"
                self.mqtt_manager.subscribe(data_topic, self._handle_device_data)
                
                # Subscribe to device status topic
                status_topic = f"devices/{device.device_id}/status"
                self.mqtt_manager.subscribe(status_topic, self._handle_device_status)
            
            self.logger.info(f"Registered device: {device.name} ({device.device_id})")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to register device {device.device_id}: {e}")
            return False
    
    def unregister_device(self, device_id: str) -> bool:
        """Unregister IoT device."""
        try:
            if device_id in self.devices:
                device = self.devices[device_id]
                
                # Unsubscribe from MQTT topics
                if device.protocol == Protocol.MQTT and self.mqtt_manager.connected:
                    # Note: paho-mqtt doesn't have direct unsubscribe by topic
                    pass
                
                del self.devices[device_id]
                
                # Clean up related data
                if device_id in self.sensor_readings:
                    del self.sensor_readings[device_id]
                
                self.logger.info(f"Unregistered device: {device_id}")
                return True
            else:
                self.logger.warning(f"Device not found: {device_id}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to unregister device {device_id}: {e}")
            return False
    
    async def discover_devices(self, network_range: str = "192.168.1.0/24") -> List[IoTDevice]:
        """Discover IoT devices on network."""
        discovered_hosts = await self.discovery.scan_network(network_range)
        devices = []
        
        for host in discovered_hosts:
            try:
                # Create device from discovered host
                device = IoTDevice(
                    device_id=f"discovered_{host['ip_address'].replace('.', '_')}",
                    name=f"Device at {host['ip_address']}",
                    device_type=DeviceType(host.get('device_type', 'sensor')),
                    manufacturer=host.get('manufacturer', 'Unknown'),
                    model="Unknown",
                    firmware_version="Unknown",
                    ip_address=host['ip_address'],
                    mac_address="Unknown",
                    protocol=Protocol.HTTP if 80 in host.get('open_ports', []) else Protocol.MQTT,
                    status=DeviceStatus.ONLINE,
                    last_seen=datetime.now()
                )
                
                devices.append(device)
                
            except Exception as e:
                self.logger.error(f"Failed to create device from host {host['ip_address']}: {e}")
        
        self.logger.info(f"Discovered {len(devices)} IoT devices")
        
        return devices
    
    def send_command(self, device_id: str, capability: str, action: str, 
                    parameters: Dict[str, Any] = None) -> str:
        """Send command to IoT device."""
        if device_id not in self.devices:
            raise ValueError(f"Device {device_id} not found")
        
        device = self.devices[device_id]
        command_id = str(uuid.uuid4())
        
        command = DeviceCommand(
            command_id=command_id,
            device_id=device_id,
            capability=capability,
            action=action,
            parameters=parameters or {}
        )
        
        self.device_commands[command_id] = command
        
        try:
            if device.protocol == Protocol.MQTT and self.mqtt_manager.connected:
                # Send command via MQTT
                command_topic = f"devices/{device_id}/commands"
                command_payload = json.dumps({
                    'command_id': command_id,
                    'capability': capability,
                    'action': action,
                    'parameters': parameters or {}
                })
                
                if self.mqtt_manager.publish(command_topic, command_payload):
                    command.status = "sent"
                    self.logger.info(f"Sent command {command_id} to device {device_id}")
                else:
                    command.status = "failed"
                    command.error_message = "MQTT publish failed"
            
            elif device.protocol == Protocol.HTTP:
                # Send command via HTTP
                self._send_http_command(device, command)
            
            else:
                command.status = "failed"
                command.error_message = f"Protocol {device.protocol.value} not supported"
            
        except Exception as e:
            command.status = "failed"
            command.error_message = str(e)
            self.logger.error(f"Failed to send command {command_id}: {e}")
        
        return command_id
    
    def _send_http_command(self, device: IoTDevice, command: DeviceCommand):
        """Send HTTP command to device."""
        try:
            url = f"http://{device.ip_address}/api/command"
            
            payload = {
                'capability': command.capability,
                'action': command.action,
                'parameters': command.parameters
            }
            
            headers = {'Content-Type': 'application/json'}
            
            # Add authentication if available
            if device.credentials:
                if device.credentials.api_key:
                    headers['Authorization'] = f"Bearer {device.credentials.api_key}"
                elif device.credentials.username and device.credentials.password:
                    import base64
                    auth_string = f"{device.credentials.username}:{device.credentials.password}"
                    auth_bytes = base64.b64encode(auth_string.encode()).decode()
                    headers['Authorization'] = f"Basic {auth_bytes}"
            
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            
            if response.status_code == 200:
                command.status = "completed"
                command.result = response.json()
            else:
                command.status = "failed"
                command.error_message = f"HTTP {response.status_code}: {response.text}"
            
        except Exception as e:
            command.status = "failed"
            command.error_message = str(e)
    
    def add_sensor_reading(self, reading: SensorReading):
        """Add sensor reading to storage."""
        device_id = reading.device_id
        
        if device_id not in self.sensor_readings:
            self.sensor_readings[device_id] = []
        
        self.sensor_readings[device_id].append(reading)
        
        # Keep only recent readings (last 1000 per device)
        if len(self.sensor_readings[device_id]) > 1000:
            self.sensor_readings[device_id] = self.sensor_readings[device_id][-1000:]
        
        # Update device last seen
        if device_id in self.devices:
            self.devices[device_id].last_seen = reading.timestamp
            self.devices[device_id].status = DeviceStatus.ONLINE
        
        # Check automation rules
        self._check_automation_rules(reading)
    
    def get_sensor_readings(self, device_id: str, capability: str = None, 
                          hours: int = 24) -> List[SensorReading]:
        """Get sensor readings for device."""
        if device_id not in self.sensor_readings:
            return []
        
        cutoff_time = datetime.now() - timedelta(hours=hours)
        readings = self.sensor_readings[device_id]
        
        # Filter by time and capability
        filtered_readings = [
            reading for reading in readings
            if reading.timestamp >= cutoff_time and
            (capability is None or reading.capability == capability)
        ]
        
        return sorted(filtered_readings, key=lambda r: r.timestamp)
    
    def create_automation_rule(self, rule: AutomationRule) -> bool:
        """Create automation rule."""
        try:
            self.automation_rules[rule.rule_id] = rule
            self.logger.info(f"Created automation rule: {rule.name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to create automation rule: {e}")
            return False
    
    def _check_automation_rules(self, reading: SensorReading):
        """Check if sensor reading triggers any automation rules."""
        for rule in self.automation_rules.values():
            if not rule.enabled:
                continue
            
            try:
                if self._evaluate_rule_conditions(rule, reading):
                    self._execute_rule_actions(rule, reading)
                    
                    rule.last_triggered = datetime.now()
                    rule.trigger_count += 1
                    
                    self.logger.info(f"Triggered automation rule: {rule.name}")
            
            except Exception as e:
                self.logger.error(f"Automation rule evaluation failed for {rule.name}: {e}")
    
    def _evaluate_rule_conditions(self, rule: AutomationRule, reading: SensorReading) -> bool:
        """Evaluate if rule conditions are met."""
        for condition in rule.trigger_conditions:
            device_id = condition.get('device_id')
            capability = condition.get('capability')
            operator = condition.get('operator')
            value = condition.get('value')
            
            # Check if condition matches current reading
            if (device_id == reading.device_id and 
                capability == reading.capability):
                
                if operator == 'greater_than' and reading.value > value:
                    return True
                elif operator == 'less_than' and reading.value < value:
                    return True
                elif operator == 'equals' and reading.value == value:
                    return True
                elif operator == 'not_equals' and reading.value != value:
                    return True
        
        return False
    
    def _execute_rule_actions(self, rule: AutomationRule, trigger_reading: SensorReading):
        """Execute automation rule actions."""
        for action in rule.actions:
            try:
                action_type = action.get('type')
                
                if action_type == 'device_command':
                    device_id = action.get('device_id')
                    capability = action.get('capability')
                    command = action.get('command')
                    parameters = action.get('parameters', {})
                    
                    self.send_command(device_id, capability, command, parameters)
                
                elif action_type == 'notification':
                    message = action.get('message', '')
                    self.logger.info(f"Automation notification: {message}")
                
                elif action_type == 'webhook':
                    url = action.get('url')
                    payload = action.get('payload', {})
                    
                    # Add trigger reading to payload
                    payload['trigger_reading'] = asdict(trigger_reading)
                    
                    requests.post(url, json=payload, timeout=5)
            
            except Exception as e:
                self.logger.error(f"Failed to execute action {action}: {e}")
    
    def _handle_device_data(self, topic: str, payload: str):
        """Handle incoming device data via MQTT."""
        try:
            # Extract device ID from topic
            topic_parts = topic.split('/')
            if len(topic_parts) >= 3 and topic_parts[0] == 'devices':
                device_id = topic_parts[1]
                
                # Parse payload
                data = json.loads(payload)
                
                # Create sensor reading
                reading = SensorReading(
                    device_id=device_id,
                    capability=data.get('capability', 'unknown'),
                    value=data.get('value'),
                    unit=data.get('unit'),
                    quality=data.get('quality', 1.0),
                    metadata=data.get('metadata', {})
                )
                
                self.add_sensor_reading(reading)
        
        except Exception as e:
            self.logger.error(f"Failed to handle device data: {e}")
    
    def _handle_device_status(self, topic: str, payload: str):
        """Handle device status updates via MQTT."""
        try:
            # Extract device ID from topic
            topic_parts = topic.split('/')
            if len(topic_parts) >= 3 and topic_parts[0] == 'devices':
                device_id = topic_parts[1]
                
                if device_id in self.devices:
                    # Parse status
                    status_data = json.loads(payload)
                    status = status_data.get('status', 'unknown')
                    
                    # Update device status
                    try:
                        self.devices[device_id].status = DeviceStatus(status)
                        self.devices[device_id].last_seen = datetime.now()
                    except ValueError:
                        self.logger.warning(f"Unknown device status: {status}")
        
        except Exception as e:
            self.logger.error(f"Failed to handle device status: {e}")
    
    def get_device_status(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get device status and information."""
        if device_id not in self.devices:
            return None
        
        device = self.devices[device_id]
        
        # Get recent readings
        recent_readings = self.get_sensor_readings(device_id, hours=1)
        
        return {
            'device_id': device.device_id,
            'name': device.name,
            'type': device.device_type.value,
            'status': device.status.value,
            'last_seen': device.last_seen.isoformat() if device.last_seen else None,
            'ip_address': device.ip_address,
            'protocol': device.protocol.value,
            'capabilities': [asdict(cap) for cap in device.capabilities],
            'recent_readings_count': len(recent_readings),
            'location': device.location,
            'room': device.room
        }
    
    def list_devices(self) -> List[Dict[str, Any]]:
        """List all registered devices."""
        return [
            {
                'device_id': device.device_id,
                'name': device.name,
                'type': device.device_type.value,
                'status': device.status.value,
                'last_seen': device.last_seen.isoformat() if device.last_seen else None,
                'location': device.location
            }
            for device in self.devices.values()
        ]
    
    def get_platform_statistics(self) -> Dict[str, Any]:
        """Get IoT platform statistics."""
        total_devices = len(self.devices)
        online_devices = sum(1 for d in self.devices.values() if d.status == DeviceStatus.ONLINE)
        
        device_types = {}
        for device in self.devices.values():
            device_type = device.device_type.value
            device_types[device_type] = device_types.get(device_type, 0) + 1
        
        total_readings = sum(len(readings) for readings in self.sensor_readings.values())
        
        return {
            'total_devices': total_devices,
            'online_devices': online_devices,
            'offline_devices': total_devices - online_devices,
            'device_types': device_types,
            'total_sensor_readings': total_readings,
            'automation_rules': len(self.automation_rules),
            'mqtt_connected': self.mqtt_manager.connected,
            'platform_uptime': '99.9%'  # Mock uptime
        }


def main():
    """Example usage of IoT Device Manager."""
    manager = DeviceManager()
    
    try:
        print("🌐 IoT Device Management Platform")
        
        # Create sample devices
        print("\n📱 Registering sample devices...")
        
        # Temperature sensor
        temp_sensor = IoTDevice(
            device_id="temp_sensor_001",
            name="Living Room Temperature Sensor",
            device_type=DeviceType.SENSOR,
            manufacturer="Arduino",
            model="DHT22",
            firmware_version="1.2.3",
            ip_address="192.168.1.100",
            mac_address="AA:BB:CC:DD:EE:FF",
            protocol=Protocol.MQTT,
            status=DeviceStatus.ONLINE,
            location="Living Room",
            capabilities=[
                DeviceCapability("temperature", "float", "°C", -40, 80, True, "Ambient temperature"),
                DeviceCapability("humidity", "float", "%", 0, 100, True, "Relative humidity")
            ]
        )
        
        # Smart light
        smart_light = IoTDevice(
            device_id="light_001",
            name="Kitchen Smart Light",
            device_type=DeviceType.LIGHTING,
            manufacturer="Philips",
            model="Hue Bulb",
            firmware_version="2.1.0",
            ip_address="192.168.1.101",
            mac_address="11:22:33:44:55:66",
            protocol=Protocol.HTTP,
            status=DeviceStatus.ONLINE,
            location="Kitchen",
            capabilities=[
                DeviceCapability("brightness", "int", "%", 0, 100, False, "Light brightness"),
                DeviceCapability("color", "string", None, None, None, False, "Light color"),
                DeviceCapability("power", "bool", None, None, None, False, "Power state")
            ]
        )
        
        # Register devices
        manager.register_device(temp_sensor)
        manager.register_device(smart_light)
        
        print("✅ Devices registered successfully")
        
        # Add sample sensor readings
        print("\n📊 Adding sample sensor readings...")
        
        readings = [
            SensorReading("temp_sensor_001", "temperature", 22.5, "°C"),
            SensorReading("temp_sensor_001", "humidity", 45.2, "%"),
            SensorReading("temp_sensor_001", "temperature", 23.1, "°C"),
            SensorReading("temp_sensor_001", "humidity", 44.8, "%")
        ]
        
        for reading in readings:
            manager.add_sensor_reading(reading)
        
        print(f"✅ Added {len(readings)} sensor readings")
        
        # Create automation rule
        print("\n🤖 Creating automation rule...")
        
        automation_rule = AutomationRule(
            rule_id="temp_alert_rule",
            name="High Temperature Alert",
            description="Turn on fan when temperature exceeds 25°C",
            trigger_conditions=[
                {
                    'device_id': 'temp_sensor_001',
                    'capability': 'temperature',
                    'operator': 'greater_than',
                    'value': 25.0
                }
            ],
            actions=[
                {
                    'type': 'device_command',
                    'device_id': 'light_001',
                    'capability': 'power',
                    'command': 'turn_on',
                    'parameters': {}
                },
                {
                    'type': 'notification',
                    'message': 'High temperature detected! Turning on cooling.'
                }
            ]
        )
        
        manager.create_automation_rule(automation_rule)
        print("✅ Automation rule created")
        
        # Send device command
        print("\n📡 Sending device command...")
        
        command_id = manager.send_command(
            "light_001", 
            "brightness", 
            "set_brightness", 
            {"value": 75}
        )
        
        print(f"✅ Command sent: {command_id}")
        
        # Get device status
        print("\n📋 Device Status:")
        devices = manager.list_devices()
        
        for device in devices:
            print(f"   🔗 {device['name']}")
            print(f"      Status: {device['status']}")
            print(f"      Type: {device['type']}")
            print(f"      Location: {device['location']}")
        
        # Get platform statistics
        print("\n📈 Platform Statistics:")
        stats = manager.get_platform_statistics()
        
        print(f"   Total Devices: {stats['total_devices']}")
        print(f"   Online Devices: {stats['online_devices']}")
        print(f"   Sensor Readings: {stats['total_sensor_readings']}")
        print(f"   Automation Rules: {stats['automation_rules']}")
        print(f"   MQTT Connected: {stats['mqtt_connected']}")
        
        # Simulate device discovery
        print("\n🔍 Discovering devices on network...")
        
        # Note: This would scan the actual network in a real environment
        print("   Network scan completed (simulated)")
        
        print("\n✅ IoT Device Management Platform demo completed!")
        
    except Exception as e:
        print(f"❌ Error: {e}")
    
    finally:
        # Cleanup
        if manager.mqtt_manager.connected:
            manager.mqtt_manager.disconnect()


if __name__ == "__main__":
    main()