#!/usr/bin/env python3
"""
Digital Twin Platform - Enterprise Digital Twin Management System
Advanced digital twin creation, simulation, and lifecycle management platform.

Use of this code is at your own risk.
Author bears no responsibility for any damages caused by the code.
"""

import os
import sys
import json
import time
import asyncio
import logging
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple, Callable
from dataclasses import dataclass, asdict, field
from enum import Enum
import hashlib
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor
import math
import random

class TwinType(Enum):
    """Digital twin types."""
    ASSET = "asset"
    PROCESS = "process"
    SYSTEM = "system"
    PRODUCT = "product"
    BUILDING = "building"
    VEHICLE = "vehicle"
    MANUFACTURING = "manufacturing"
    INFRASTRUCTURE = "infrastructure"

class SimulationState(Enum):
    """Simulation execution states."""
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"

class DataSource(Enum):
    """Data source types."""
    IOT_SENSOR = "iot_sensor"
    DATABASE = "database"
    API = "api"
    FILE = "file"
    STREAM = "stream"
    MANUAL = "manual"

@dataclass
class TwinProperty:
    """Digital twin property definition."""
    name: str
    data_type: str
    unit: Optional[str] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    description: str = ""
    is_input: bool = False
    is_output: bool = False
    default_value: Any = None

@dataclass
class TwinBehavior:
    """Digital twin behavior model."""
    behavior_id: str
    name: str
    description: str
    input_properties: List[str]
    output_properties: List[str]
    model_type: str  # "physics", "ml", "rule_based", "statistical"
    parameters: Dict[str, Any] = field(default_factory=dict)
    equations: List[str] = field(default_factory=list)
    code: Optional[str] = None

@dataclass
class DigitalTwin:
    """Digital twin definition."""
    twin_id: str
    name: str
    description: str
    twin_type: TwinType
    properties: List[TwinProperty]
    behaviors: List[TwinBehavior]
    data_sources: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    relationships: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)

@dataclass
class TwinInstance:
    """Digital twin runtime instance."""
    instance_id: str
    twin_id: str
    name: str
    current_state: Dict[str, Any]
    last_updated: datetime
    simulation_state: SimulationState = SimulationState.IDLE
    data_connections: Dict[str, Any] = field(default_factory=dict)
    metrics: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SimulationScenario:
    """Simulation scenario definition."""
    scenario_id: str
    name: str
    description: str
    twin_instances: List[str]
    initial_conditions: Dict[str, Any]
    simulation_parameters: Dict[str, Any]
    duration_seconds: float
    time_step: float = 1.0
    output_variables: List[str] = field(default_factory=list)

@dataclass
class SimulationResult:
    """Simulation execution result."""
    result_id: str
    scenario_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    status: SimulationState = SimulationState.IDLE
    time_series_data: Dict[str, List[Tuple[float, Any]]] = field(default_factory=dict)
    summary_statistics: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None

class PhysicsEngine:
    """Physics simulation engine for digital twins."""
    
    def __init__(self):
        self.logger = logging.getLogger('PhysicsEngine')
        
    def simulate_mechanical_system(self, properties: Dict[str, Any], 
                                 time_step: float, duration: float) -> Dict[str, List[Tuple[float, float]]]:
        """Simulate mechanical system dynamics."""
        try:
            # Extract system parameters
            mass = properties.get('mass', 1.0)
            damping = properties.get('damping', 0.1)
            stiffness = properties.get('stiffness', 1.0)
            force = properties.get('external_force', 0.0)
            
            # Initial conditions
            position = properties.get('initial_position', 0.0)
            velocity = properties.get('initial_velocity', 0.0)
            
            # Simulation arrays
            time_points = np.arange(0, duration, time_step)
            positions = []
            velocities = []
            accelerations = []
            
            for t in time_points:
                # Calculate acceleration using F = ma
                # For damped harmonic oscillator: ma = -kx - cv + F_ext
                acceleration = (-stiffness * position - damping * velocity + force) / mass
                
                # Update velocity and position using Euler integration
                velocity += acceleration * time_step
                position += velocity * time_step
                
                # Store results
                positions.append((t, position))
                velocities.append((t, velocity))
                accelerations.append((t, acceleration))
            
            return {
                'position': positions,
                'velocity': velocities,
                'acceleration': accelerations
            }
            
        except Exception as e:
            self.logger.error(f"Mechanical simulation failed: {e}")
            return {}
    
    def simulate_thermal_system(self, properties: Dict[str, Any],
                               time_step: float, duration: float) -> Dict[str, List[Tuple[float, float]]]:
        """Simulate thermal system behavior."""
        try:
            # Thermal parameters
            thermal_mass = properties.get('thermal_mass', 1000.0)  # J/K
            thermal_resistance = properties.get('thermal_resistance', 0.1)  # K/W
            ambient_temperature = properties.get('ambient_temperature', 20.0)  # °C
            heat_input = properties.get('heat_input', 0.0)  # W
            
            # Initial temperature
            temperature = properties.get('initial_temperature', ambient_temperature)
            
            # Simulation
            time_points = np.arange(0, duration, time_step)
            temperatures = []
            heat_flows = []
            
            for t in time_points:
                # Heat flow to ambient
                heat_loss = (temperature - ambient_temperature) / thermal_resistance
                
                # Net heat flow
                net_heat = heat_input - heat_loss
                
                # Temperature change: dT/dt = Q_net / C_thermal
                temp_change = net_heat * time_step / thermal_mass
                temperature += temp_change
                
                temperatures.append((t, temperature))
                heat_flows.append((t, net_heat))
            
            return {
                'temperature': temperatures,
                'heat_flow': heat_flows
            }
            
        except Exception as e:
            self.logger.error(f"Thermal simulation failed: {e}")
            return {}
    
    def simulate_fluid_system(self, properties: Dict[str, Any],
                             time_step: float, duration: float) -> Dict[str, List[Tuple[float, float]]]:
        """Simulate fluid system dynamics."""
        try:
            # Fluid parameters
            density = properties.get('density', 1000.0)  # kg/m³
            viscosity = properties.get('viscosity', 0.001)  # Pa·s
            pipe_diameter = properties.get('pipe_diameter', 0.1)  # m
            pipe_length = properties.get('pipe_length', 10.0)  # m
            pressure_drop = properties.get('pressure_drop', 1000.0)  # Pa
            
            # Calculate flow parameters
            pipe_area = math.pi * (pipe_diameter / 2) ** 2
            
            # Simplified flow calculation (Hagen-Poiseuille for laminar flow)
            flow_rate = (pressure_drop * pipe_area * pipe_diameter ** 2) / (32 * viscosity * pipe_length)
            velocity = flow_rate / pipe_area
            
            # Reynolds number
            reynolds = (density * velocity * pipe_diameter) / viscosity
            
            # Simulation (steady-state for simplicity)
            time_points = np.arange(0, duration, time_step)
            flow_rates = []
            velocities = []
            reynolds_numbers = []
            
            for t in time_points:
                # Add some variation for dynamic behavior
                variation = 1 + 0.1 * math.sin(2 * math.pi * t / 10)
                
                current_flow = flow_rate * variation
                current_velocity = velocity * variation
                current_reynolds = reynolds * variation
                
                flow_rates.append((t, current_flow))
                velocities.append((t, current_velocity))
                reynolds_numbers.append((t, current_reynolds))
            
            return {
                'flow_rate': flow_rates,
                'velocity': velocities,
                'reynolds_number': reynolds_numbers
            }
            
        except Exception as e:
            self.logger.error(f"Fluid simulation failed: {e}")
            return {}

class MLModelEngine:
    """Machine learning model engine for digital twins."""
    
    def __init__(self):
        self.logger = logging.getLogger('MLModelEngine')
        self.models = {}
    
    def create_regression_model(self, model_id: str, input_features: List[str],
                               output_feature: str, training_data: Dict[str, List[float]]) -> bool:
        """Create simple regression model."""
        try:
            # Simplified linear regression implementation
            X = np.array([training_data[feature] for feature in input_features]).T
            y = np.array(training_data[output_feature])
            
            # Add bias term
            X_with_bias = np.column_stack([np.ones(X.shape[0]), X])
            
            # Normal equation: θ = (X^T X)^(-1) X^T y
            theta = np.linalg.pinv(X_with_bias.T @ X_with_bias) @ X_with_bias.T @ y
            
            self.models[model_id] = {
                'type': 'linear_regression',
                'coefficients': theta,
                'input_features': input_features,
                'output_feature': output_feature
            }
            
            self.logger.info(f"Created regression model: {model_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create regression model: {e}")
            return False
    
    def predict(self, model_id: str, input_values: Dict[str, float]) -> Optional[float]:
        """Make prediction using trained model."""
        if model_id not in self.models:
            return None
        
        try:
            model = self.models[model_id]
            
            if model['type'] == 'linear_regression':
                # Prepare input vector
                X = np.array([1.0] + [input_values[feature] for feature in model['input_features']])
                
                # Make prediction
                prediction = np.dot(model['coefficients'], X)
                
                return float(prediction)
            
        except Exception as e:
            self.logger.error(f"Prediction failed for model {model_id}: {e}")
        
        return None
    
    def create_time_series_model(self, model_id: str, time_series_data: List[float],
                                window_size: int = 10) -> bool:
        """Create simple time series prediction model."""
        try:
            if len(time_series_data) < window_size + 1:
                raise ValueError("Insufficient data for time series model")
            
            # Create training data (sliding window)
            X = []
            y = []
            
            for i in range(len(time_series_data) - window_size):
                X.append(time_series_data[i:i + window_size])
                y.append(time_series_data[i + window_size])
            
            X = np.array(X)
            y = np.array(y)
            
            # Simple linear model
            X_with_bias = np.column_stack([np.ones(X.shape[0]), X])
            theta = np.linalg.pinv(X_with_bias.T @ X_with_bias) @ X_with_bias.T @ y
            
            self.models[model_id] = {
                'type': 'time_series',
                'coefficients': theta,
                'window_size': window_size
            }
            
            self.logger.info(f"Created time series model: {model_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create time series model: {e}")
            return False
    
    def predict_next_value(self, model_id: str, recent_values: List[float]) -> Optional[float]:
        """Predict next value in time series."""
        if model_id not in self.models:
            return None
        
        try:
            model = self.models[model_id]
            
            if model['type'] == 'time_series':
                if len(recent_values) != model['window_size']:
                    return None
                
                # Prepare input
                X = np.array([1.0] + recent_values)
                
                # Make prediction
                prediction = np.dot(model['coefficients'], X)
                
                return float(prediction)
            
        except Exception as e:
            self.logger.error(f"Time series prediction failed: {e}")
        
        return None

class DigitalTwinEngine:
    """Core digital twin simulation engine."""
    
    def __init__(self):
        self.twins = {}
        self.instances = {}
        self.physics_engine = PhysicsEngine()
        self.ml_engine = MLModelEngine()
        self.logger = logging.getLogger('DigitalTwinEngine')
        
    def register_twin(self, twin: DigitalTwin) -> bool:
        """Register digital twin definition."""
        try:
            self.twins[twin.twin_id] = twin
            self.logger.info(f"Registered digital twin: {twin.name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to register twin {twin.twin_id}: {e}")
            return False
    
    def create_instance(self, twin_id: str, instance_name: str,
                       initial_state: Dict[str, Any] = None) -> Optional[str]:
        """Create digital twin instance."""
        if twin_id not in self.twins:
            return None
        
        try:
            instance_id = str(uuid.uuid4())
            twin = self.twins[twin_id]
            
            # Initialize state with default values
            current_state = {}
            for prop in twin.properties:
                if prop.name in (initial_state or {}):
                    current_state[prop.name] = initial_state[prop.name]
                elif prop.default_value is not None:
                    current_state[prop.name] = prop.default_value
                else:
                    current_state[prop.name] = 0.0 if prop.data_type in ['float', 'int'] else None
            
            instance = TwinInstance(
                instance_id=instance_id,
                twin_id=twin_id,
                name=instance_name,
                current_state=current_state,
                last_updated=datetime.now()
            )
            
            self.instances[instance_id] = instance
            
            self.logger.info(f"Created twin instance: {instance_name} ({instance_id})")
            return instance_id
            
        except Exception as e:
            self.logger.error(f"Failed to create twin instance: {e}")
            return None
    
    def update_instance_state(self, instance_id: str, property_updates: Dict[str, Any]) -> bool:
        """Update digital twin instance state."""
        if instance_id not in self.instances:
            return False
        
        try:
            instance = self.instances[instance_id]
            
            # Update properties
            for prop_name, value in property_updates.items():
                instance.current_state[prop_name] = value
            
            instance.last_updated = datetime.now()
            
            # Execute behaviors based on updated state
            self._execute_behaviors(instance)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update instance state: {e}")
            return False
    
    def _execute_behaviors(self, instance: TwinInstance):
        """Execute twin behaviors based on current state."""
        twin = self.twins[instance.twin_id]
        
        for behavior in twin.behaviors:
            try:
                # Get input values
                input_values = {}
                for input_prop in behavior.input_properties:
                    if input_prop in instance.current_state:
                        input_values[input_prop] = instance.current_state[input_prop]
                
                # Execute behavior based on type
                if behavior.model_type == "physics":
                    outputs = self._execute_physics_behavior(behavior, input_values)
                elif behavior.model_type == "ml":
                    outputs = self._execute_ml_behavior(behavior, input_values)
                elif behavior.model_type == "rule_based":
                    outputs = self._execute_rule_behavior(behavior, input_values)
                elif behavior.model_type == "statistical":
                    outputs = self._execute_statistical_behavior(behavior, input_values)
                else:
                    continue
                
                # Update output properties
                for output_prop, value in outputs.items():
                    if output_prop in behavior.output_properties:
                        instance.current_state[output_prop] = value
                
            except Exception as e:
                self.logger.error(f"Behavior execution failed for {behavior.name}: {e}")
    
    def _execute_physics_behavior(self, behavior: TwinBehavior, 
                                 input_values: Dict[str, Any]) -> Dict[str, Any]:
        """Execute physics-based behavior."""
        outputs = {}
        
        # Simple physics calculations based on behavior parameters
        if 'force_calculation' in behavior.parameters:
            mass = input_values.get('mass', 1.0)
            acceleration = input_values.get('acceleration', 0.0)
            force = mass * acceleration
            outputs['force'] = force
        
        if 'energy_calculation' in behavior.parameters:
            mass = input_values.get('mass', 1.0)
            velocity = input_values.get('velocity', 0.0)
            kinetic_energy = 0.5 * mass * velocity ** 2
            outputs['kinetic_energy'] = kinetic_energy
        
        if 'temperature_transfer' in behavior.parameters:
            temp_diff = input_values.get('temperature_difference', 0.0)
            thermal_conductivity = behavior.parameters.get('thermal_conductivity', 1.0)
            heat_flow = thermal_conductivity * temp_diff
            outputs['heat_flow'] = heat_flow
        
        return outputs
    
    def _execute_ml_behavior(self, behavior: TwinBehavior, 
                            input_values: Dict[str, Any]) -> Dict[str, Any]:
        """Execute ML-based behavior."""
        outputs = {}
        
        model_id = behavior.parameters.get('model_id')
        if model_id and model_id in self.ml_engine.models:
            prediction = self.ml_engine.predict(model_id, input_values)
            if prediction is not None:
                output_prop = behavior.output_properties[0] if behavior.output_properties else 'prediction'
                outputs[output_prop] = prediction
        
        return outputs
    
    def _execute_rule_behavior(self, behavior: TwinBehavior,
                              input_values: Dict[str, Any]) -> Dict[str, Any]:
        """Execute rule-based behavior."""
        outputs = {}
        
        # Simple rule evaluation
        for equation in behavior.equations:
            try:
                # Very simplified rule evaluation (security risk in real implementation)
                # Would use proper expression parser in production
                if '=' in equation:
                    left, right = equation.split('=', 1)
                    output_var = left.strip()
                    
                    # Replace variables with values
                    expression = right.strip()
                    for var, value in input_values.items():
                        expression = expression.replace(var, str(value))
                    
                    # Evaluate simple mathematical expressions
                    try:
                        result = eval(expression)  # SECURITY WARNING: Don't use in production
                        outputs[output_var] = result
                    except:
                        pass
                        
            except Exception as e:
                self.logger.debug(f"Rule evaluation failed: {e}")
        
        return outputs
    
    def _execute_statistical_behavior(self, behavior: TwinBehavior,
                                     input_values: Dict[str, Any]) -> Dict[str, Any]:
        """Execute statistical behavior."""
        outputs = {}
        
        # Simple statistical operations
        if 'mean' in behavior.parameters:
            values = [input_values.get(prop, 0) for prop in behavior.input_properties]
            if values:
                outputs['mean'] = sum(values) / len(values)
        
        if 'variance' in behavior.parameters:
            values = [input_values.get(prop, 0) for prop in behavior.input_properties]
            if len(values) > 1:
                mean_val = sum(values) / len(values)
                variance = sum((x - mean_val) ** 2 for x in values) / len(values)
                outputs['variance'] = variance
        
        return outputs
    
    def simulate_instance(self, instance_id: str, duration: float, 
                         time_step: float = 1.0) -> Optional[Dict[str, List[Tuple[float, Any]]]]:
        """Simulate digital twin instance over time."""
        if instance_id not in self.instances:
            return None
        
        try:
            instance = self.instances[instance_id]
            twin = self.twins[instance.twin_id]
            
            # Initialize simulation data
            time_series_data = {}
            for prop in twin.properties:
                time_series_data[prop.name] = []
            
            # Run simulation
            current_time = 0.0
            while current_time <= duration:
                # Record current state
                for prop_name, value in instance.current_state.items():
                    time_series_data[prop_name].append((current_time, value))
                
                # Execute behaviors to update state
                self._execute_behaviors(instance)
                
                # Add some noise for realistic behavior
                for prop_name in instance.current_state:
                    if isinstance(instance.current_state[prop_name], (int, float)):
                        noise = random.uniform(-0.01, 0.01) * abs(instance.current_state[prop_name])
                        instance.current_state[prop_name] += noise
                
                current_time += time_step
            
            self.logger.info(f"Simulation completed for instance {instance_id}")
            return time_series_data
            
        except Exception as e:
            self.logger.error(f"Simulation failed for instance {instance_id}: {e}")
            return None
    
    def get_instance_state(self, instance_id: str) -> Optional[Dict[str, Any]]:
        """Get current state of digital twin instance."""
        if instance_id not in self.instances:
            return None
        
        instance = self.instances[instance_id]
        
        return {
            'instance_id': instance.instance_id,
            'twin_id': instance.twin_id,
            'name': instance.name,
            'current_state': instance.current_state,
            'last_updated': instance.last_updated.isoformat(),
            'simulation_state': instance.simulation_state.value
        }

class DigitalTwinPlatform:
    """Enterprise digital twin platform."""
    
    def __init__(self):
        self.engine = DigitalTwinEngine()
        self.scenarios = {}
        self.simulation_results = {}
        self.logger = self._setup_logging()
        self.executor = ThreadPoolExecutor(max_workers=5)
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger('DigitalTwinPlatform')
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def create_twin(self, twin: DigitalTwin) -> bool:
        """Create new digital twin."""
        return self.engine.register_twin(twin)
    
    def create_twin_instance(self, twin_id: str, instance_name: str,
                           initial_state: Dict[str, Any] = None) -> Optional[str]:
        """Create digital twin instance."""
        return self.engine.create_instance(twin_id, instance_name, initial_state)
    
    def update_twin_data(self, instance_id: str, data_updates: Dict[str, Any]) -> bool:
        """Update digital twin with real-world data."""
        return self.engine.update_instance_state(instance_id, data_updates)
    
    def run_simulation(self, scenario: SimulationScenario) -> str:
        """Run simulation scenario."""
        result_id = str(uuid.uuid4())
        
        result = SimulationResult(
            result_id=result_id,
            scenario_id=scenario.scenario_id,
            start_time=datetime.now(),
            status=SimulationState.RUNNING
        )
        
        self.simulation_results[result_id] = result
        
        # Run simulation in background
        future = self.executor.submit(self._execute_simulation, scenario, result)
        
        self.logger.info(f"Started simulation: {scenario.name} ({result_id})")
        
        return result_id
    
    def _execute_simulation(self, scenario: SimulationScenario, result: SimulationResult):
        """Execute simulation scenario."""
        try:
            # Initialize instances with scenario conditions
            for instance_id in scenario.twin_instances:
                if instance_id in self.engine.instances:
                    initial_conditions = scenario.initial_conditions.get(instance_id, {})
                    self.engine.update_instance_state(instance_id, initial_conditions)
            
            # Run simulation for each instance
            all_time_series = {}
            
            for instance_id in scenario.twin_instances:
                time_series = self.engine.simulate_instance(
                    instance_id, 
                    scenario.duration_seconds, 
                    scenario.time_step
                )
                
                if time_series:
                    all_time_series[instance_id] = time_series
            
            # Store results
            result.time_series_data = all_time_series
            result.status = SimulationState.COMPLETED
            result.end_time = datetime.now()
            
            # Calculate summary statistics
            result.summary_statistics = self._calculate_summary_stats(all_time_series)
            
            self.logger.info(f"Simulation completed: {scenario.name}")
            
        except Exception as e:
            result.status = SimulationState.FAILED
            result.error_message = str(e)
            result.end_time = datetime.now()
            
            self.logger.error(f"Simulation failed: {e}")
    
    def _calculate_summary_stats(self, time_series_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate summary statistics from simulation results."""
        stats = {}
        
        for instance_id, instance_data in time_series_data.items():
            instance_stats = {}
            
            for property_name, time_series in instance_data.items():
                if time_series:
                    values = [value for time, value in time_series if isinstance(value, (int, float))]
                    
                    if values:
                        instance_stats[property_name] = {
                            'min': min(values),
                            'max': max(values),
                            'mean': sum(values) / len(values),
                            'final_value': values[-1]
                        }
            
            stats[instance_id] = instance_stats
        
        return stats
    
    def get_simulation_result(self, result_id: str) -> Optional[Dict[str, Any]]:
        """Get simulation result."""
        if result_id not in self.simulation_results:
            return None
        
        result = self.simulation_results[result_id]
        
        return {
            'result_id': result.result_id,
            'scenario_id': result.scenario_id,
            'status': result.status.value,
            'start_time': result.start_time.isoformat(),
            'end_time': result.end_time.isoformat() if result.end_time else None,
            'summary_statistics': result.summary_statistics,
            'error_message': result.error_message
        }
    
    def list_twins(self) -> List[Dict[str, Any]]:
        """List all digital twins."""
        return [
            {
                'twin_id': twin.twin_id,
                'name': twin.name,
                'type': twin.twin_type.value,
                'description': twin.description,
                'properties_count': len(twin.properties),
                'behaviors_count': len(twin.behaviors),
                'created_at': twin.created_at.isoformat()
            }
            for twin in self.engine.twins.values()
        ]
    
    def list_instances(self) -> List[Dict[str, Any]]:
        """List all twin instances."""
        return [
            {
                'instance_id': instance.instance_id,
                'twin_id': instance.twin_id,
                'name': instance.name,
                'simulation_state': instance.simulation_state.value,
                'last_updated': instance.last_updated.isoformat()
            }
            for instance in self.engine.instances.values()
        ]
    
    def get_platform_statistics(self) -> Dict[str, Any]:
        """Get platform statistics."""
        return {
            'total_twins': len(self.engine.twins),
            'total_instances': len(self.engine.instances),
            'total_simulations': len(self.simulation_results),
            'running_simulations': len([r for r in self.simulation_results.values() 
                                      if r.status == SimulationState.RUNNING]),
            'twin_types': {
                twin_type.value: len([t for t in self.engine.twins.values() 
                                    if t.twin_type == twin_type])
                for twin_type in TwinType
            }
        }


def main():
    """Example usage of Digital Twin Platform."""
    platform = DigitalTwinPlatform()
    
    try:
        print("🔬 Digital Twin Platform")
        
        # Create digital twin definition
        print("\n🏗️  Creating digital twin...")
        
        # Define properties
        properties = [
            TwinProperty("temperature", "float", "°C", -50, 150, "Current temperature", True, True, 20.0),
            TwinProperty("pressure", "float", "Pa", 0, 1000000, "Current pressure", True, True, 101325.0),
            TwinProperty("flow_rate", "float", "L/min", 0, 1000, "Fluid flow rate", True, True, 10.0),
            TwinProperty("efficiency", "float", "%", 0, 100, "System efficiency", False, True, 85.0),
            TwinProperty("power_consumption", "float", "W", 0, 10000, "Power consumption", False, True, 1000.0)
        ]
        
        # Define behaviors
        behaviors = [
            TwinBehavior(
                behavior_id="thermal_behavior",
                name="Thermal Dynamics",
                description="Temperature and heat transfer behavior",
                input_properties=["temperature", "pressure"],
                output_properties=["efficiency"],
                model_type="physics",
                parameters={"thermal_conductivity": 0.5}
            ),
            TwinBehavior(
                behavior_id="efficiency_model",
                name="Efficiency Calculation",
                description="Calculate system efficiency based on operating conditions",
                input_properties=["temperature", "pressure", "flow_rate"],
                output_properties=["efficiency", "power_consumption"],
                model_type="rule_based",
                equations=[
                    "efficiency = 100 - (temperature - 20) * 0.5 - (pressure - 101325) / 10000",
                    "power_consumption = 1000 + flow_rate * 10 + (100 - efficiency) * 20"
                ]
            )
        ]
        
        # Create digital twin
        industrial_system = DigitalTwin(
            twin_id="industrial_system_001",
            name="Industrial Processing System",
            description="Digital twin of industrial fluid processing system",
            twin_type=TwinType.MANUFACTURING,
            properties=properties,
            behaviors=behaviors
        )
        
        platform.create_twin(industrial_system)
        print("✅ Digital twin created")
        
        # Create twin instances
        print("\n🎯 Creating twin instances...")
        
        instance1_id = platform.create_twin_instance(
            "industrial_system_001",
            "Production Line A",
            {"temperature": 25.0, "pressure": 105000.0, "flow_rate": 15.0}
        )
        
        instance2_id = platform.create_twin_instance(
            "industrial_system_001", 
            "Production Line B",
            {"temperature": 30.0, "pressure": 98000.0, "flow_rate": 12.0}
        )
        
        print(f"✅ Created instances: {instance1_id}, {instance2_id}")
        
        # Update with real-time data
        print("\n📊 Updating with sensor data...")
        
        platform.update_twin_data(instance1_id, {
            "temperature": 28.5,
            "pressure": 103000.0,
            "flow_rate": 16.2
        })
        
        platform.update_twin_data(instance2_id, {
            "temperature": 32.1,
            "pressure": 96500.0,
            "flow_rate": 11.8
        })
        
        print("✅ Sensor data updated")
        
        # Create simulation scenario
        print("\n⚡ Running simulation scenario...")
        
        scenario = SimulationScenario(
            scenario_id="performance_test_001",
            name="Performance Test Scenario",
            description="Test system performance under varying conditions",
            twin_instances=[instance1_id, instance2_id],
            initial_conditions={
                instance1_id: {"temperature": 20.0, "pressure": 101325.0, "flow_rate": 10.0},
                instance2_id: {"temperature": 22.0, "pressure": 101325.0, "flow_rate": 12.0}
            },
            simulation_parameters={"time_step": 1.0},
            duration_seconds=60.0,
            time_step=1.0
        )
        
        result_id = platform.run_simulation(scenario)
        print(f"✅ Simulation started: {result_id}")
        
        # Wait for simulation to complete
        time.sleep(3)
        
        # Get simulation results
        result = platform.get_simulation_result(result_id)
        if result:
            print(f"\n📈 Simulation Results:")
            print(f"   Status: {result['status']}")
            print(f"   Duration: {result['start_time']} to {result['end_time']}")
            
            if result['summary_statistics']:
                print(f"   Summary Statistics:")
                for instance_id, stats in result['summary_statistics'].items():
                    print(f"     Instance {instance_id[:8]}:")
                    for prop, prop_stats in stats.items():
                        print(f"       {prop}: min={prop_stats['min']:.2f}, max={prop_stats['max']:.2f}, mean={prop_stats['mean']:.2f}")
        
        # Show platform status
        print("\n📋 Platform Status:")
        stats = platform.get_platform_statistics()
        
        print(f"   Total Twins: {stats['total_twins']}")
        print(f"   Total Instances: {stats['total_instances']}")
        print(f"   Total Simulations: {stats['total_simulations']}")
        print(f"   Running Simulations: {stats['running_simulations']}")
        
        # List twins and instances
        print("\n🔗 Digital Twins:")
        twins = platform.list_twins()
        
        for twin in twins:
            print(f"   🏭 {twin['name']}")
            print(f"      Type: {twin['type']}")
            print(f"      Properties: {twin['properties_count']}")
            print(f"      Behaviors: {twin['behaviors_count']}")
        
        print("\n🎯 Twin Instances:")
        instances = platform.list_instances()
        
        for instance in instances:
            print(f"   ⚙️  {instance['name']}")
            print(f"      State: {instance['simulation_state']}")
            print(f"      Last Updated: {instance['last_updated']}")
        
        print("\n✅ Digital Twin Platform demo completed!")
        
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()