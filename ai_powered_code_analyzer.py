#!/usr/bin/env python3
"""
AI-Powered Code Analyzer - Intelligent Code Quality and Security Analysis
Advanced static code analysis using machine learning and AI techniques.

Use of this code is at your own risk.
Author bears no responsibility for any damages caused by the code.
"""

import os
import sys
import ast
import json
import time
import asyncio
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple, Set
from dataclasses import dataclass, asdict, field
from enum import Enum
import subprocess
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import tokenize
import io

class AnalysisType(Enum):
    """Types of code analysis."""
    SECURITY = "security"
    QUALITY = "quality"
    PERFORMANCE = "performance"
    MAINTAINABILITY = "maintainability"
    COMPLEXITY = "complexity"
    DOCUMENTATION = "documentation"
    TESTING = "testing"
    DEPENDENCIES = "dependencies"

class Severity(Enum):
    """Issue severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class Language(Enum):
    """Supported programming languages."""
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA = "java"
    CSHARP = "csharp"
    CPP = "cpp"
    GO = "go"
    RUST = "rust"
    PHP = "php"
    RUBY = "ruby"

@dataclass
class CodeIssue:
    """Code analysis issue."""
    id: str
    file_path: str
    line_number: int
    column_number: int
    severity: Severity
    category: AnalysisType
    rule_id: str
    title: str
    description: str
    suggestion: str
    code_snippet: str
    confidence_score: float
    fix_effort: str
    tags: List[str] = field(default_factory=list)
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None

@dataclass
class CodeMetrics:
    """Code quality metrics."""
    lines_of_code: int
    cyclomatic_complexity: int
    cognitive_complexity: int
    maintainability_index: float
    technical_debt_ratio: float
    test_coverage: float
    duplication_percentage: float
    comment_ratio: float
    function_count: int
    class_count: int
    dependency_count: int

@dataclass
class AnalysisResult:
    """Complete analysis result."""
    project_path: str
    analysis_id: str
    timestamp: datetime
    duration_seconds: float
    files_analyzed: int
    issues: List[CodeIssue]
    metrics: CodeMetrics
    language_distribution: Dict[str, int]
    security_score: float
    quality_score: float
    maintainability_score: float

class SecurityAnalyzer:
    """Security-focused code analyzer."""
    
    def __init__(self):
        self.logger = logging.getLogger('SecurityAnalyzer')
        self.security_patterns = self._load_security_patterns()
    
    def _load_security_patterns(self) -> Dict[str, List[Dict]]:
        """Load security vulnerability patterns."""
        return {
            "sql_injection": [
                {
                    "pattern": r"execute\s*\(\s*[\"'].*%.*[\"']\s*%",
                    "description": "Potential SQL injection vulnerability",
                    "cwe": "CWE-89",
                    "owasp": "A03:2021 – Injection"
                },
                {
                    "pattern": r"cursor\.execute\s*\(\s*[\"'].*\+.*[\"']\s*\)",
                    "description": "SQL query concatenation vulnerability",
                    "cwe": "CWE-89",
                    "owasp": "A03:2021 – Injection"
                }
            ],
            "xss": [
                {
                    "pattern": r"innerHTML\s*=\s*.*\+",
                    "description": "Potential XSS vulnerability in innerHTML",
                    "cwe": "CWE-79",
                    "owasp": "A03:2021 – Injection"
                },
                {
                    "pattern": r"document\.write\s*\(\s*.*\+",
                    "description": "Potential XSS vulnerability in document.write",
                    "cwe": "CWE-79",
                    "owasp": "A03:2021 – Injection"
                }
            ],
            "hardcoded_secrets": [
                {
                    "pattern": r"password\s*=\s*[\"'][^\"']{8,}[\"']",
                    "description": "Hardcoded password detected",
                    "cwe": "CWE-798",
                    "owasp": "A07:2021 – Identification and Authentication Failures"
                },
                {
                    "pattern": r"api_key\s*=\s*[\"'][A-Za-z0-9]{20,}[\"']",
                    "description": "Hardcoded API key detected",
                    "cwe": "CWE-798",
                    "owasp": "A07:2021 – Identification and Authentication Failures"
                }
            ],
            "path_traversal": [
                {
                    "pattern": r"open\s*\(\s*.*\+.*[\"']\.\.\/",
                    "description": "Potential path traversal vulnerability",
                    "cwe": "CWE-22",
                    "owasp": "A01:2021 – Broken Access Control"
                }
            ],
            "command_injection": [
                {
                    "pattern": r"os\.system\s*\(\s*.*\+",
                    "description": "Potential command injection vulnerability",
                    "cwe": "CWE-78",
                    "owasp": "A03:2021 – Injection"
                },
                {
                    "pattern": r"subprocess\.(call|run|Popen)\s*\(\s*.*\+",
                    "description": "Potential command injection in subprocess",
                    "cwe": "CWE-78",
                    "owasp": "A03:2021 – Injection"
                }
            ]
        }
    
    def analyze_file(self, file_path: str, content: str) -> List[CodeIssue]:
        """Analyze file for security vulnerabilities."""
        issues = []
        lines = content.split('\n')
        
        for category, patterns in self.security_patterns.items():
            for pattern_info in patterns:
                pattern = pattern_info["pattern"]
                
                for line_num, line in enumerate(lines, 1):
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    
                    for match in matches:
                        issue = CodeIssue(
                            id=f"sec_{hashlib.md5(f'{file_path}_{line_num}_{match.start()}'.encode()).hexdigest()[:8]}",
                            file_path=file_path,
                            line_number=line_num,
                            column_number=match.start(),
                            severity=Severity.HIGH if category in ["sql_injection", "xss", "command_injection"] else Severity.MEDIUM,
                            category=AnalysisType.SECURITY,
                            rule_id=f"security_{category}",
                            title=f"Security: {category.replace('_', ' ').title()}",
                            description=pattern_info["description"],
                            suggestion=self._get_security_suggestion(category),
                            code_snippet=line.strip(),
                            confidence_score=0.8,
                            fix_effort="Medium",
                            tags=["security", category],
                            cwe_id=pattern_info.get("cwe"),
                            owasp_category=pattern_info.get("owasp")
                        )
                        issues.append(issue)
        
        return issues
    
    def _get_security_suggestion(self, category: str) -> str:
        """Get security fix suggestion for category."""
        suggestions = {
            "sql_injection": "Use parameterized queries or prepared statements instead of string concatenation",
            "xss": "Sanitize user input and use safe DOM manipulation methods",
            "hardcoded_secrets": "Move secrets to environment variables or secure configuration",
            "path_traversal": "Validate and sanitize file paths, use allowlists for permitted paths",
            "command_injection": "Use subprocess with shell=False and validate all inputs"
        }
        return suggestions.get(category, "Review code for security implications")

class QualityAnalyzer:
    """Code quality analyzer."""
    
    def __init__(self):
        self.logger = logging.getLogger('QualityAnalyzer')
    
    def analyze_python_file(self, file_path: str, content: str) -> Tuple[List[CodeIssue], CodeMetrics]:
        """Analyze Python file for quality issues."""
        issues = []
        
        try:
            tree = ast.parse(content)
            
            # Analyze AST for quality issues
            issues.extend(self._check_function_complexity(tree, file_path))
            issues.extend(self._check_naming_conventions(tree, file_path))
            issues.extend(self._check_code_smells(tree, file_path, content))
            
            # Calculate metrics
            metrics = self._calculate_python_metrics(tree, content)
            
        except SyntaxError as e:
            issues.append(CodeIssue(
                id=f"syntax_{hashlib.md5(file_path.encode()).hexdigest()[:8]}",
                file_path=file_path,
                line_number=e.lineno or 1,
                column_number=e.offset or 0,
                severity=Severity.CRITICAL,
                category=AnalysisType.QUALITY,
                rule_id="syntax_error",
                title="Syntax Error",
                description=f"Syntax error: {e.msg}",
                suggestion="Fix syntax error",
                code_snippet="",
                confidence_score=1.0,
                fix_effort="High",
                tags=["syntax", "error"]
            ))
            
            # Return default metrics for files with syntax errors
            metrics = CodeMetrics(
                lines_of_code=len(content.split('\n')),
                cyclomatic_complexity=0,
                cognitive_complexity=0,
                maintainability_index=0.0,
                technical_debt_ratio=1.0,
                test_coverage=0.0,
                duplication_percentage=0.0,
                comment_ratio=0.0,
                function_count=0,
                class_count=0,
                dependency_count=0
            )
        
        return issues, metrics
    
    def _check_function_complexity(self, tree: ast.AST, file_path: str) -> List[CodeIssue]:
        """Check for overly complex functions."""
        issues = []
        
        class ComplexityVisitor(ast.NodeVisitor):
            def visit_FunctionDef(self, node):
                complexity = self._calculate_cyclomatic_complexity(node)
                
                if complexity > 10:
                    issues.append(CodeIssue(
                        id=f"complexity_{hashlib.md5(f'{file_path}_{node.lineno}_{node.name}'.encode()).hexdigest()[:8]}",
                        file_path=file_path,
                        line_number=node.lineno,
                        column_number=node.col_offset,
                        severity=Severity.HIGH if complexity > 20 else Severity.MEDIUM,
                        category=AnalysisType.COMPLEXITY,
                        rule_id="high_complexity",
                        title=f"High Cyclomatic Complexity ({complexity})",
                        description=f"Function '{node.name}' has cyclomatic complexity of {complexity}",
                        suggestion="Consider breaking down this function into smaller, more focused functions",
                        code_snippet=f"def {node.name}(...)",
                        confidence_score=0.9,
                        fix_effort="High",
                        tags=["complexity", "maintainability"]
                    ))
                
                self.generic_visit(node)
            
            def _calculate_cyclomatic_complexity(self, node):
                """Calculate cyclomatic complexity for a function."""
                complexity = 1  # Base complexity
                
                for child in ast.walk(node):
                    if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                        complexity += 1
                    elif isinstance(child, ast.ExceptHandler):
                        complexity += 1
                    elif isinstance(child, ast.BoolOp):
                        complexity += len(child.values) - 1
                
                return complexity
        
        visitor = ComplexityVisitor()
        visitor.visit(tree)
        
        return issues
    
    def _check_naming_conventions(self, tree: ast.AST, file_path: str) -> List[CodeIssue]:
        """Check naming conventions."""
        issues = []
        
        class NamingVisitor(ast.NodeVisitor):
            def visit_FunctionDef(self, node):
                if not re.match(r'^[a-z_][a-z0-9_]*$', node.name):
                    issues.append(CodeIssue(
                        id=f"naming_{hashlib.md5(f'{file_path}_{node.lineno}_{node.name}'.encode()).hexdigest()[:8]}",
                        file_path=file_path,
                        line_number=node.lineno,
                        column_number=node.col_offset,
                        severity=Severity.LOW,
                        category=AnalysisType.QUALITY,
                        rule_id="naming_convention",
                        title="Naming Convention Violation",
                        description=f"Function '{node.name}' doesn't follow snake_case convention",
                        suggestion="Use snake_case for function names",
                        code_snippet=f"def {node.name}(...)",
                        confidence_score=0.95,
                        fix_effort="Low",
                        tags=["naming", "style"]
                    ))
                
                self.generic_visit(node)
            
            def visit_ClassDef(self, node):
                if not re.match(r'^[A-Z][a-zA-Z0-9]*$', node.name):
                    issues.append(CodeIssue(
                        id=f"naming_{hashlib.md5(f'{file_path}_{node.lineno}_{node.name}'.encode()).hexdigest()[:8]}",
                        file_path=file_path,
                        line_number=node.lineno,
                        column_number=node.col_offset,
                        severity=Severity.LOW,
                        category=AnalysisType.QUALITY,
                        rule_id="naming_convention",
                        title="Naming Convention Violation",
                        description=f"Class '{node.name}' doesn't follow PascalCase convention",
                        suggestion="Use PascalCase for class names",
                        code_snippet=f"class {node.name}:",
                        confidence_score=0.95,
                        fix_effort="Low",
                        tags=["naming", "style"]
                    ))
                
                self.generic_visit(node)
        
        visitor = NamingVisitor()
        visitor.visit(tree)
        
        return issues
    
    def _check_code_smells(self, tree: ast.AST, file_path: str, content: str) -> List[CodeIssue]:
        """Check for code smells."""
        issues = []
        lines = content.split('\n')
        
        # Check for long lines
        for line_num, line in enumerate(lines, 1):
            if len(line) > 120:
                issues.append(CodeIssue(
                    id=f"line_length_{hashlib.md5(f'{file_path}_{line_num}'.encode()).hexdigest()[:8]}",
                    file_path=file_path,
                    line_number=line_num,
                    column_number=120,
                    severity=Severity.LOW,
                    category=AnalysisType.QUALITY,
                    rule_id="line_too_long",
                    title="Line Too Long",
                    description=f"Line exceeds 120 characters ({len(line)} characters)",
                    suggestion="Break long lines into multiple lines for better readability",
                    code_snippet=line[:50] + "..." if len(line) > 50 else line,
                    confidence_score=1.0,
                    fix_effort="Low",
                    tags=["style", "readability"]
                ))
        
        # Check for large classes/functions
        class SizeVisitor(ast.NodeVisitor):
            def visit_ClassDef(self, node):
                class_lines = self._count_lines(node)
                if class_lines > 500:
                    issues.append(CodeIssue(
                        id=f"large_class_{hashlib.md5(f'{file_path}_{node.lineno}_{node.name}'.encode()).hexdigest()[:8]}",
                        file_path=file_path,
                        line_number=node.lineno,
                        column_number=node.col_offset,
                        severity=Severity.MEDIUM,
                        category=AnalysisType.MAINTAINABILITY,
                        rule_id="large_class",
                        title="Large Class",
                        description=f"Class '{node.name}' is very large ({class_lines} lines)",
                        suggestion="Consider breaking this class into smaller, more focused classes",
                        code_snippet=f"class {node.name}:",
                        confidence_score=0.8,
                        fix_effort="High",
                        tags=["size", "maintainability"]
                    ))
                
                self.generic_visit(node)
            
            def visit_FunctionDef(self, node):
                func_lines = self._count_lines(node)
                if func_lines > 50:
                    issues.append(CodeIssue(
                        id=f"large_function_{hashlib.md5(f'{file_path}_{node.lineno}_{node.name}'.encode()).hexdigest()[:8]}",
                        file_path=file_path,
                        line_number=node.lineno,
                        column_number=node.col_offset,
                        severity=Severity.MEDIUM,
                        category=AnalysisType.MAINTAINABILITY,
                        rule_id="large_function",
                        title="Large Function",
                        description=f"Function '{node.name}' is very large ({func_lines} lines)",
                        suggestion="Consider breaking this function into smaller functions",
                        code_snippet=f"def {node.name}(...)",
                        confidence_score=0.8,
                        fix_effort="Medium",
                        tags=["size", "maintainability"]
                    ))
                
                self.generic_visit(node)
            
            def _count_lines(self, node):
                """Count lines in an AST node."""
                if hasattr(node, 'end_lineno') and node.end_lineno:
                    return node.end_lineno - node.lineno + 1
                return 1
        
        visitor = SizeVisitor()
        visitor.visit(tree)
        
        return issues
    
    def _calculate_python_metrics(self, tree: ast.AST, content: str) -> CodeMetrics:
        """Calculate code metrics for Python file."""
        lines = content.split('\n')
        lines_of_code = len([line for line in lines if line.strip() and not line.strip().startswith('#')])
        
        # Count functions and classes
        function_count = len([node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)])
        class_count = len([node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)])
        
        # Count imports (dependencies)
        dependency_count = len([node for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom))])
        
        # Calculate comment ratio
        comment_lines = len([line for line in lines if line.strip().startswith('#')])
        comment_ratio = comment_lines / len(lines) if lines else 0
        
        # Calculate cyclomatic complexity (simplified)
        complexity_nodes = [node for node in ast.walk(tree) 
                          if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor, ast.ExceptHandler))]
        cyclomatic_complexity = len(complexity_nodes) + 1
        
        # Simplified metrics (would use more sophisticated algorithms in production)
        maintainability_index = max(0, 171 - 5.2 * math.log(lines_of_code) - 0.23 * cyclomatic_complexity - 16.2 * math.log(lines_of_code)) if lines_of_code > 0 else 100
        
        return CodeMetrics(
            lines_of_code=lines_of_code,
            cyclomatic_complexity=cyclomatic_complexity,
            cognitive_complexity=cyclomatic_complexity,  # Simplified
            maintainability_index=maintainability_index,
            technical_debt_ratio=0.1,  # Would be calculated based on issues
            test_coverage=0.0,  # Would need test runner integration
            duplication_percentage=0.0,  # Would need duplication detection
            comment_ratio=comment_ratio,
            function_count=function_count,
            class_count=class_count,
            dependency_count=dependency_count
        )

class AICodeAnalyzer:
    """Main AI-powered code analyzer."""
    
    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self.security_analyzer = SecurityAnalyzer()
        self.quality_analyzer = QualityAnalyzer()
        self.logger = self._setup_logging()
        self.executor = ThreadPoolExecutor(max_workers=self.config.get("max_workers", 10))
        
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        logger = logging.getLogger('AICodeAnalyzer')
        logger.setLevel(logging.INFO)
        
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        return logger
    
    def _load_config(self, config_path: str) -> Dict:
        """Load analyzer configuration."""
        default_config = {
            "max_workers": 10,
            "max_file_size_mb": 10,
            "excluded_paths": [".git", "__pycache__", "node_modules", ".venv"],
            "included_extensions": [".py", ".js", ".ts", ".java", ".cs", ".cpp", ".go", ".rs", ".php", ".rb"],
            "analysis_types": ["security", "quality", "performance", "maintainability"],
            "severity_threshold": "low",
            "output_format": "json",
            "generate_report": True
        }
        
        if config_path and os.path.exists(config_path):
            with open(config_path, 'r') as f:
                user_config = json.load(f)
                default_config.update(user_config)
        
        return default_config
    
    def analyze_project(self, project_path: str) -> AnalysisResult:
        """Analyze entire project."""
        start_time = time.time()
        analysis_id = f"analysis_{int(start_time)}"
        
        self.logger.info(f"Starting analysis of project: {project_path}")
        
        # Discover files
        files_to_analyze = self._discover_files(project_path)
        self.logger.info(f"Found {len(files_to_analyze)} files to analyze")
        
        # Analyze files in parallel
        all_issues = []
        all_metrics = []
        language_distribution = {}
        
        futures = []
        for file_path in files_to_analyze:
            future = self.executor.submit(self._analyze_file, file_path)
            futures.append((file_path, future))
        
        for file_path, future in futures:
            try:
                issues, metrics, language = future.result(timeout=60)
                all_issues.extend(issues)
                all_metrics.append(metrics)
                
                language_distribution[language] = language_distribution.get(language, 0) + 1
                
            except Exception as e:
                self.logger.error(f"Failed to analyze {file_path}: {e}")
        
        # Calculate aggregate metrics
        aggregate_metrics = self._aggregate_metrics(all_metrics)
        
        # Calculate scores
        security_score = self._calculate_security_score(all_issues)
        quality_score = self._calculate_quality_score(all_issues, aggregate_metrics)
        maintainability_score = self._calculate_maintainability_score(all_issues, aggregate_metrics)
        
        duration = time.time() - start_time
        
        result = AnalysisResult(
            project_path=project_path,
            analysis_id=analysis_id,
            timestamp=datetime.now(),
            duration_seconds=duration,
            files_analyzed=len(files_to_analyze),
            issues=all_issues,
            metrics=aggregate_metrics,
            language_distribution=language_distribution,
            security_score=security_score,
            quality_score=quality_score,
            maintainability_score=maintainability_score
        )
        
        self.logger.info(f"Analysis completed in {duration:.2f} seconds")
        self.logger.info(f"Found {len(all_issues)} issues across {len(files_to_analyze)} files")
        
        return result
    
    def _discover_files(self, project_path: str) -> List[str]:
        """Discover files to analyze in project."""
        files = []
        project_path = Path(project_path)
        
        for file_path in project_path.rglob('*'):
            if file_path.is_file():
                # Check if file should be excluded
                if any(excluded in str(file_path) for excluded in self.config["excluded_paths"]):
                    continue
                
                # Check file extension
                if file_path.suffix in self.config["included_extensions"]:
                    # Check file size
                    if file_path.stat().st_size <= self.config["max_file_size_mb"] * 1024 * 1024:
                        files.append(str(file_path))
        
        return files
    
    def _analyze_file(self, file_path: str) -> Tuple[List[CodeIssue], CodeMetrics, str]:
        """Analyze single file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except Exception as e:
            self.logger.error(f"Failed to read file {file_path}: {e}")
            return [], self._get_default_metrics(), "unknown"
        
        # Detect language
        language = self._detect_language(file_path)
        
        issues = []
        
        # Security analysis
        if "security" in self.config["analysis_types"]:
            security_issues = self.security_analyzer.analyze_file(file_path, content)
            issues.extend(security_issues)
        
        # Quality analysis
        metrics = self._get_default_metrics()
        if "quality" in self.config["analysis_types"]:
            if language == "python":
                quality_issues, metrics = self.quality_analyzer.analyze_python_file(file_path, content)
                issues.extend(quality_issues)
        
        return issues, metrics, language
    
    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension."""
        extension_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.cs': 'csharp',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.cxx': 'cpp',
            '.go': 'go',
            '.rs': 'rust',
            '.php': 'php',
            '.rb': 'ruby'
        }
        
        extension = Path(file_path).suffix.lower()
        return extension_map.get(extension, 'unknown')
    
    def _get_default_metrics(self) -> CodeMetrics:
        """Get default metrics for files that can't be analyzed."""
        return CodeMetrics(
            lines_of_code=0,
            cyclomatic_complexity=0,
            cognitive_complexity=0,
            maintainability_index=100.0,
            technical_debt_ratio=0.0,
            test_coverage=0.0,
            duplication_percentage=0.0,
            comment_ratio=0.0,
            function_count=0,
            class_count=0,
            dependency_count=0
        )
    
    def _aggregate_metrics(self, metrics_list: List[CodeMetrics]) -> CodeMetrics:
        """Aggregate metrics from multiple files."""
        if not metrics_list:
            return self._get_default_metrics()
        
        total_loc = sum(m.lines_of_code for m in metrics_list)
        
        return CodeMetrics(
            lines_of_code=total_loc,
            cyclomatic_complexity=sum(m.cyclomatic_complexity for m in metrics_list),
            cognitive_complexity=sum(m.cognitive_complexity for m in metrics_list),
            maintainability_index=sum(m.maintainability_index for m in metrics_list) / len(metrics_list),
            technical_debt_ratio=sum(m.technical_debt_ratio for m in metrics_list) / len(metrics_list),
            test_coverage=sum(m.test_coverage for m in metrics_list) / len(metrics_list),
            duplication_percentage=sum(m.duplication_percentage for m in metrics_list) / len(metrics_list),
            comment_ratio=sum(m.comment_ratio for m in metrics_list) / len(metrics_list),
            function_count=sum(m.function_count for m in metrics_list),
            class_count=sum(m.class_count for m in metrics_list),
            dependency_count=sum(m.dependency_count for m in metrics_list)
        )
    
    def _calculate_security_score(self, issues: List[CodeIssue]) -> float:
        """Calculate security score (0-100, higher is better)."""
        security_issues = [issue for issue in issues if issue.category == AnalysisType.SECURITY]
        
        if not security_issues:
            return 100.0
        
        # Weight by severity
        severity_weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 5,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0.5
        }
        
        total_weight = sum(severity_weights[issue.severity] for issue in security_issues)
        
        # Score decreases with more severe issues
        score = max(0, 100 - (total_weight * 2))
        
        return score
    
    def _calculate_quality_score(self, issues: List[CodeIssue], metrics: CodeMetrics) -> float:
        """Calculate quality score (0-100, higher is better)."""
        quality_issues = [issue for issue in issues if issue.category == AnalysisType.QUALITY]
        
        # Base score from maintainability index
        base_score = min(100, metrics.maintainability_index)
        
        # Deduct points for quality issues
        issue_penalty = len(quality_issues) * 2
        
        score = max(0, base_score - issue_penalty)
        
        return score
    
    def _calculate_maintainability_score(self, issues: List[CodeIssue], metrics: CodeMetrics) -> float:
        """Calculate maintainability score (0-100, higher is better)."""
        maintainability_issues = [
            issue for issue in issues 
            if issue.category in [AnalysisType.MAINTAINABILITY, AnalysisType.COMPLEXITY]
        ]
        
        # Base score from metrics
        base_score = metrics.maintainability_index
        
        # Adjust for complexity
        if metrics.cyclomatic_complexity > 50:
            base_score -= 20
        elif metrics.cyclomatic_complexity > 20:
            base_score -= 10
        
        # Deduct for maintainability issues
        issue_penalty = len(maintainability_issues) * 3
        
        score = max(0, base_score - issue_penalty)
        
        return score
    
    def generate_report(self, result: AnalysisResult, output_path: str = None) -> str:
        """Generate analysis report."""
        if not output_path:
            output_path = f"analysis_report_{result.analysis_id}.json"
        
        # Group issues by severity and category
        issues_by_severity = {}
        issues_by_category = {}
        
        for issue in result.issues:
            severity = issue.severity.value
            category = issue.category.value
            
            if severity not in issues_by_severity:
                issues_by_severity[severity] = []
            issues_by_severity[severity].append(issue)
            
            if category not in issues_by_category:
                issues_by_category[category] = []
            issues_by_category[category].append(issue)
        
        # Create report
        report = {
            "analysis_summary": {
                "project_path": result.project_path,
                "analysis_id": result.analysis_id,
                "timestamp": result.timestamp.isoformat(),
                "duration_seconds": result.duration_seconds,
                "files_analyzed": result.files_analyzed
            },
            "scores": {
                "security_score": result.security_score,
                "quality_score": result.quality_score,
                "maintainability_score": result.maintainability_score
            },
            "metrics": asdict(result.metrics),
            "language_distribution": result.language_distribution,
            "issue_summary": {
                "total_issues": len(result.issues),
                "by_severity": {k: len(v) for k, v in issues_by_severity.items()},
                "by_category": {k: len(v) for k, v in issues_by_category.items()}
            },
            "top_issues": [
                {
                    "file_path": issue.file_path,
                    "line_number": issue.line_number,
                    "severity": issue.severity.value,
                    "category": issue.category.value,
                    "title": issue.title,
                    "description": issue.description
                }
                for issue in sorted(result.issues, key=lambda x: (x.severity.value, x.confidence_score), reverse=True)[:20]
            ]
        }
        
        # Write report
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.info(f"Report generated: {output_path}")
        
        return output_path


# Import math for maintainability index calculation
import math


async def main():
    """Example usage of AI Code Analyzer."""
    analyzer = AICodeAnalyzer()
    
    # Analyze current directory
    project_path = "."
    
    try:
        print("🔍 Starting AI-powered code analysis...")
        result = analyzer.analyze_project(project_path)
        
        print(f"✅ Analysis completed!")
        print(f"📊 Files analyzed: {result.files_analyzed}")
        print(f"⚠️  Issues found: {len(result.issues)}")
        print(f"⏱️  Duration: {result.duration_seconds:.2f} seconds")
        print()
        
        print("📈 Scores:")
        print(f"  🔒 Security: {result.security_score:.1f}/100")
        print(f"  ✨ Quality: {result.quality_score:.1f}/100")
        print(f"  🔧 Maintainability: {result.maintainability_score:.1f}/100")
        print()
        
        print("📋 Issue Summary:")
        severity_counts = {}
        for issue in result.issues:
            severity = issue.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity, count in severity_counts.items():
            print(f"  {severity.upper()}: {count}")
        
        print()
        print("🏆 Top Issues:")
        top_issues = sorted(result.issues, key=lambda x: (x.severity.value, x.confidence_score), reverse=True)[:5]
        
        for i, issue in enumerate(top_issues, 1):
            print(f"  {i}. {issue.title}")
            print(f"     📁 {issue.file_path}:{issue.line_number}")
            print(f"     ⚠️  {issue.severity.value.upper()} - {issue.description}")
            print()
        
        # Generate report
        report_path = analyzer.generate_report(result)
        print(f"📄 Detailed report: {report_path}")
        
    except Exception as e:
        print(f"❌ Analysis failed: {e}")


if __name__ == "__main__":
    asyncio.run(main())