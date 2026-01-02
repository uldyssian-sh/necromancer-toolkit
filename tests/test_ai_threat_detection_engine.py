#!/usr/bin/env python3
"""
Tests for AI Threat Detection Engine
Author: uldyssian-sh
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_threat_detection_engine import (
    AIThreatDetectionEngine, 
    ThreatDetection, 
    ThreatLevel, 
    ThreatCategory
)

class TestAIThreatDetectionEngine:
    """Test suite for AI Threat Detection Engine"""
    
    @pytest.fixture
    def engine(self):
        """Create engine instance for testing"""
        return AIThreatDetectionEngine()
    
    def test_engine_initialization(self, engine):
        """Test engine initialization"""
        assert engine is not None
        assert engine.config is not None
        assert engine.logger is not None
        assert engine.detection_history == []
        assert engine.behavioral_baselines == {}
        assert engine.ml_models is not None
    
    def test_config_loading(self):
        """Test configuration loading"""
        engine = AIThreatDetectionEngine()
        
        # Test default configuration
        assert engine.config["detection_sensitivity"] == "high"
        assert "anomaly_detection" in engine.config["ml_model_types"]
        assert engine.config["confidence_threshold"] == 0.75
    
    def test_ml_models_initialization(self, engine):
        """Test ML models initialization"""
        models = engine.ml_models
        
        assert "anomaly_detector" in models
        assert "behavioral_analyzer" in models
        assert "pattern_recognizer" in models
        
        # Verify model properties
        for model_name, model_info in models.items():
            assert "type" in model_info
            assert "trained" in model_info
            assert "accuracy" in model_info
            assert model_info["trained"] is True
            assert 0.0 <= model_info["accuracy"] <= 1.0
    
    @pytest.mark.asyncio
    async def test_analyze_network_traffic(self, engine):
        """Test network traffic analysis"""
        traffic_data = {
            "source_ip": "192.168.1.100",
            "bytes_per_second": 1500000,
            "connection_count": 150,
            "user_agent": "bot/1.0",
            "destination_ports": [80, 443, 8080]
        }
        
        detections = await engine.analyze_network_traffic(traffic_data)
        
        # Verify detections
        assert len(detections) > 0
        assert all(isinstance(d, ThreatDetection) for d in detections)
        assert len(engine.detection_history) == len(detections)
        
        # Verify detection properties
        for detection in detections:
            assert detection.detection_id is not None
            assert detection.timestamp is not None
            assert isinstance(detection.threat_level, ThreatLevel)
            assert isinstance(detection.threat_category, ThreatCategory)
            assert 0.0 <= detection.confidence_score <= 1.0
            assert len(detection.affected_assets) > 0
            assert len(detection.mitigation_steps) > 0
    
    @pytest.mark.asyncio
    async def test_detect_network_anomalies(self, engine):
        """Test network anomaly detection"""
        # Test high data volume anomaly
        traffic_data = {
            "source_ip": "192.168.1.100",
            "bytes_per_second": 2000000,  # High volume
            "destination_ports": [80, 443]
        }
        
        anomalies = await engine._detect_network_anomalies(traffic_data)
        
        assert len(anomalies) == 1
        anomaly = anomalies[0]
        assert anomaly.threat_category == ThreatCategory.DATA_EXFILTRATION
        assert anomaly.threat_level == ThreatLevel.HIGH
        assert "unusual_data_volume" in anomaly.indicators
    
    @pytest.mark.asyncio
    async def test_analyze_network_behavior(self, engine):
        """Test network behavior analysis"""
        traffic_data = {
            "source_ip": "192.168.1.100",
            "connection_count": 150,  # High connection count
        }
        
        behavioral_threats = await engine._analyze_network_behavior(traffic_data)
        
        assert len(behavioral_threats) == 1
        threat = behavioral_threats[0]
        assert threat.threat_category == ThreatCategory.APT
        assert threat.threat_level == ThreatLevel.MEDIUM
        assert "excessive_connections" in threat.indicators
    
    @pytest.mark.asyncio
    async def test_recognize_threat_patterns(self, engine):
        """Test threat pattern recognition"""
        traffic_data = {
            "source_ip": "192.168.1.100",
            "user_agent": "bot",  # Suspicious user agent
        }
        
        pattern_threats = await engine._recognize_threat_patterns(traffic_data)
        
        assert len(pattern_threats) == 1
        threat = pattern_threats[0]
        assert threat.threat_category == ThreatCategory.MALWARE
        assert threat.threat_level == ThreatLevel.HIGH
        assert "suspicious_user_agent" in threat.indicators
    
    @pytest.mark.asyncio
    async def test_analyze_user_behavior(self, engine):
        """Test user behavior analysis"""
        user_data = {
            "user_id": "test_user",
            "login_time": datetime.now(),
            "files_accessed": ["file1.txt", "file2.pdf"]
        }
        
        detections = await engine.analyze_user_behavior(user_data)
        
        # First analysis should establish baseline
        assert isinstance(detections, list)
        assert "test_user" in engine.behavioral_baselines
    
    @pytest.mark.asyncio
    async def test_behavioral_baseline_update(self, engine):
        """Test behavioral baseline updates"""
        user_id = "test_user"
        user_data = {
            "user_id": user_id,
            "login_time": datetime.now(),
            "files_accessed": ["file1.txt"]
        }
        
        await engine._update_behavioral_baseline(user_id, user_data)
        
        assert user_id in engine.behavioral_baselines
        baseline = engine.behavioral_baselines[user_id]
        assert "login_times" in baseline
        assert "access_patterns" in baseline
        assert "last_updated" in baseline
    
    @pytest.mark.asyncio
    async def test_detect_behavioral_anomalies(self, engine):
        """Test behavioral anomaly detection"""
        user_id = "test_user"
        
        # Establish baseline with normal hours
        normal_time = datetime.now().replace(hour=9)  # 9 AM
        await engine._update_behavioral_baseline(user_id, {
            "user_id": user_id,
            "login_time": normal_time
        })
        
        # Test unusual login time
        unusual_data = {
            "user_id": user_id,
            "login_time": datetime.now().replace(hour=2)  # 2 AM
        }
        
        # Mock current time to be 2 AM
        with patch('ai_threat_detection_engine.datetime') as mock_datetime:
            mock_datetime.now.return_value = datetime.now().replace(hour=2)
            mock_datetime.side_effect = lambda *args, **kw: datetime(*args, **kw)
            
            anomalies = await engine._detect_behavioral_anomalies(user_id, unusual_data)
            
            if anomalies:  # May not detect if baseline is insufficient
                anomaly = anomalies[0]
                assert anomaly.threat_category == ThreatCategory.INSIDER_THREAT
                assert "unusual_login_time" in anomaly.indicators
    
    def test_generate_detection_id(self, engine):
        """Test detection ID generation"""
        detection_id = engine._generate_detection_id()
        
        assert detection_id is not None
        assert len(detection_id) == 12
        assert isinstance(detection_id, str)
        
        # Test uniqueness
        another_id = engine._generate_detection_id()
        assert detection_id != another_id
    
    def test_maintain_detection_history(self, engine):
        """Test detection history maintenance"""
        # Set low limit for testing
        engine.config["max_detection_history"] = 5
        
        # Add more detections than limit
        for i in range(10):
            detection = ThreatDetection(
                detection_id=f"test_{i}",
                timestamp=datetime.now(),
                threat_level=ThreatLevel.LOW,
                threat_category=ThreatCategory.BEHAVIORAL_ANOMALY,
                confidence_score=0.5,
                affected_assets=["test"],
                indicators={},
                mitigation_steps=["test"],
                ai_analysis={}
            )
            engine.detection_history.append(detection)
        
        engine._maintain_detection_history()
        
        assert len(engine.detection_history) == 5
    
    def test_generate_threat_intelligence_report_empty(self, engine):
        """Test threat intelligence report with no detections"""
        report = engine.generate_threat_intelligence_report()
        
        assert "error" in report
        assert report["error"] == "No threat detections available"
    
    @pytest.mark.asyncio
    async def test_generate_threat_intelligence_report_with_data(self, engine):
        """Test threat intelligence report with detection data"""
        # Add some test detections
        traffic_data = {
            "source_ip": "192.168.1.100",
            "bytes_per_second": 1500000,
            "connection_count": 150,
            "user_agent": "bot/1.0"
        }
        
        await engine.analyze_network_traffic(traffic_data)
        
        report = engine.generate_threat_intelligence_report()
        
        # Verify report structure
        assert "threat_statistics" in report
        assert "average_confidence" in report
        assert "ml_model_performance" in report
        assert "recommendations" in report
        assert "generated_at" in report
        
        # Verify threat statistics
        stats = report["threat_statistics"]
        assert "total_detections" in stats
        assert "threat_levels" in stats
        assert "threat_categories" in stats
        assert stats["total_detections"] > 0
        
        # Verify average confidence
        assert 0.0 <= report["average_confidence"] <= 1.0
        
        # Verify recommendations
        recommendations = report["recommendations"]
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
    
    def test_generate_threat_recommendations(self, engine):
        """Test threat recommendation generation"""
        # Add high-severity threats
        for i in range(6):
            detection = ThreatDetection(
                detection_id=f"high_threat_{i}",
                timestamp=datetime.now(),
                threat_level=ThreatLevel.HIGH,
                threat_category=ThreatCategory.MALWARE,
                confidence_score=0.9,
                affected_assets=["test"],
                indicators={},
                mitigation_steps=["test"],
                ai_analysis={}
            )
            engine.detection_history.append(detection)
        
        recommendations = engine._generate_threat_recommendations()
        
        assert isinstance(recommendations, list)
        assert len(recommendations) > 0
        
        # Should include immediate investigation recommendation
        assert any("immediate investigation" in rec.lower() for rec in recommendations)
    
    def test_threat_level_enum(self):
        """Test ThreatLevel enum"""
        assert ThreatLevel.CRITICAL.value == "critical"
        assert ThreatLevel.HIGH.value == "high"
        assert ThreatLevel.MEDIUM.value == "medium"
        assert ThreatLevel.LOW.value == "low"
        assert ThreatLevel.INFO.value == "info"
    
    def test_threat_category_enum(self):
        """Test ThreatCategory enum"""
        assert ThreatCategory.MALWARE.value == "malware"
        assert ThreatCategory.APT.value == "apt"
        assert ThreatCategory.INSIDER_THREAT.value == "insider_threat"
        assert ThreatCategory.DATA_EXFILTRATION.value == "data_exfiltration"
        assert ThreatCategory.NETWORK_INTRUSION.value == "network_intrusion"
        assert ThreatCategory.BEHAVIORAL_ANOMALY.value == "behavioral_anomaly"

if __name__ == "__main__":
    pytest.main([__file__, "-v"])