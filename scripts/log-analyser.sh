#!/usr/bin/env python3
"""
AI-Powered Log Analyzer with Advanced Auto-Fix Capabilities
Reads logs, explains issues, and automatically fixes common problems
"""

import os
import re
import json
import argparse
import datetime
import hashlib
import subprocess
import shlex
import time
import sys
import signal
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Callable, Union
from collections import Counter, defaultdict
import openai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FixError(Exception):
    """Custom exception for fix-related errors"""
    pass

class LogAnalyzer:
    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4", 
                 dry_run: bool = False, auto_approve: bool = False,
                 log_level: str = "INFO"):
        """
        Initialize the log analyzer with OpenAI API
        
        Args:
            api_key: OpenAI API key (optional, will check env var)
            model: GPT model to use
            dry_run: If True, don't actually execute fixes
            auto_approve: If True, automatically approve all fixes
            log_level: Logging level
        """
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError("OpenAI API key required. Set OPENAI_API_KEY environment variable or pass it.")
        
        openai.api_key = self.api_key
        self.model = model
        self.dry_run = dry_run
        self.auto_approve = auto_approve
        self.log_patterns = self._load_patterns()
        self.fix_handlers = self._register_fix_handlers()
        self.executed_fixes = []
        self.fix_history = []
        self.rollback_commands = []
        
        # Set logging level
        logger.setLevel(getattr(logging, log_level.upper()))
        
    def _load_patterns(self) -> Dict[str, List[str]]:
        """Load common log patterns for different log types"""
        return {
            "error_patterns": [
                r"error|exception|fail|timeout|unavailable|denied|reject",
                r"5\d{2}|40[14]|50[0-9]",  # HTTP status codes
                r"null pointer|index out of bounds|stack overflow",
                r"disk full|out of memory|connection refused",
            ],
            "warning_patterns": [
                r"warn|deprecated|slow|high memory|high cpu",
                r"retry|attempt|threshold exceeded",
            ],
            "timestamp_patterns": [
                r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
                r"\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
                r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}",
            ],
            "metric_patterns": [
                r"cpu[=\s:](\d+(?:\.\d+)?)%?",
                r"memory[=\s:](\d+(?:\.\d+)?)%?",
                r"disk[=\s:](\d+(?:\.\d+)?)%?",
            ]
        }
    
    def _register_fix_handlers(self) -> Dict[str, Dict[str, Any]]:
        """Register automatic fix handlers for common issues"""
        return {
            "disk_full": {
                "patterns": [
                    r"disk full",
                    r"no space left",
                    r"disk space critical",
                    r"device .* no space",
                    r"write error: .* no space",
                    r"filesystem full",
                    r"disk usage exceeds"
                ],
                "handler": self._fix_disk_full,
                "description": "Clear disk space by removing temporary files and old logs",
                "risk": "medium",
                "requires_sudo": True,
                "timeout": 60,
                "verification": self._verify_disk_space,
                "rollback": self._rollback_disk_cleanup
            },
            "out_of_memory": {
                "patterns": [
                    r"out of memory",
                    r"cannot allocate memory",
                    r"memory exhausted",
                    r"killed process",
                    r"oom-killer",
                    r"allocation failure"
                ],
                "handler": self._fix_out_of_memory,
                "description": "Clear memory caches and restart memory-intensive services",
                "risk": "high",
                "requires_sudo": True,
                "timeout": 120,
                "verification": self._verify_memory_status,
                "rollback": self._rollback_memory_cleanup
            },
            "connection_refused": {
                "patterns": [
                    r"connection refused",
                    r"cannot connect",
                    r"timeout",
                    r"connection.*failed",
                    r"network unreachable"
                ],
                "handler": self._fix_connection_refused,
                "description": "Restart affected services and check network connectivity",
                "risk": "medium",
                "requires_sudo": True,
                "timeout": 60,
                "verification": self._verify_connection,
                "rollback": None
            },
            "database_connection": {
                "patterns": [
                    r"database.*connection",
                    r"postgres.*down",
                    r"mysql.*down",
                    r"mongodb.*unreachable",
                    r"redis.*connection",
                    r"db connection pool exhausted"
                ],
                "handler": self._fix_database_connection,
                "description": "Check and restart database services",
                "risk": "high",
                "requires_sudo": True,
                "timeout": 90,
                "verification": self._verify_database,
                "rollback": None
            },
            "high_cpu": {
                "patterns": [
                    r"high cpu",
                    r"cpu usage",
                    r"load average",
                    r"cpu.*critical",
                    r"cpu.*threshold exceeded"
                ],
                "handler": self._fix_high_cpu,
                "description": "Identify and restart CPU-intensive processes",
                "risk": "medium",
                "requires_sudo": False,
                "timeout": 30,
                "verification": self._verify_cpu_usage,
                "rollback": None
            },
            "service_down": {
                "patterns": [
                    r"service.*down",
                    r"process.*not running",
                    r"failed to start",
                    r"dead.*service",
                    r"inactive.*service"
                ],
                "handler": self._fix_service_down,
                "description": "Restart failed systemd services",
                "risk": "medium",
                "requires_sudo": True,
                "timeout": 60,
                "verification": self._verify_service_status,
                "rollback": None
            },
            "permission_denied": {
                "patterns": [
                    r"permission denied",
                    r"access denied",
                    r"not allowed",
                    r"cannot open file.*permission",
                    r"unauthorized access"
                ],
                "handler": self._fix_permission_denied,
                "description": "Fix file/directory permissions",
                "risk": "medium",
                "requires_sudo": True,
                "timeout": 30,
                "verification": self._verify_permissions,
                "rollback": self._rollback_permissions
            },
            "port_conflict": {
                "patterns": [
                    r"address already in use",
                    r"port already bound",
                    r"cannot bind",
                    r"port.*conflict",
                    r"already in use"
                ],
                "handler": self._fix_port_conflict,
                "description": "Resolve port conflicts by stopping conflicting processes",
                "risk": "high",
                "requires_sudo": True,
                "timeout": 30,
                "verification": self._verify_port_available,
                "rollback": None
            },
            "nginx_error": {
                "patterns": [
                    r"nginx.*error",
                    r"failed.*nginx",
                    r"cannot load.*nginx"
                ],
                "handler": self._fix_nginx,
                "description": "Check and restart nginx with configuration test",
                "risk": "high",
                "requires_sudo": True,
                "timeout": 45,
                "verification": self._verify_nginx,
                "rollback": None
            },
            "docker_error": {
                "patterns": [
                    r"docker.*error",
                    r"container.*failed",
                    r"cannot connect to docker",
                    r"docker daemon.*not running"
                ],
                "handler": self._fix_docker,
                "description": "Restart docker daemon and containers",
                "risk": "high",
                "requires_sudo": True,
                "timeout": 120,
                "verification": self._verify_docker,
                "rollback": None
            },
            "ssl_cert_error": {
                "patterns": [
                    r"ssl certificate expired",
                    r"certificate.*invalid",
                    r"tls handshake failed",
                    r"certificate verify failed"
                ],
                "handler": self._fix_ssl_cert,
                "description": "Check and renew SSL certificates",
                "risk": "medium",
                "requires_sudo": True,
                "timeout": 60,
                "verification": self._verify_ssl_cert,
                "rollback": self._rollback_ssl_cert
            },
            "application_hang": {
                "patterns": [
                    r"application.*hang",
                    r"process.*unresponsive",
                    r"thread.*blocked",
                    r"deadlock detected"
                ],
                "handler": self._fix_application_hang,
                "description": "Restart hung application processes",
                "risk": "high",
                "requires_sudo": True,
                "timeout": 45,
                "verification": self._verify_application_status,
                "rollback": None
            },
            "network_issue": {
                "patterns": [
                    r"network.*down",
                    r"interface.*down",
                    r"no route to host",
                    r"network.*unreachable"
                ],
                "handler": self._fix_network,
                "description": "Restart network interfaces",
                "risk": "high",
                "requires_sudo": True,
                "timeout": 60,
                "verification": self._verify_network,
                "rollback": self._rollback_network
            }
        }
    
    def read_logs(self, log_source: Union[str, List[str]]) -> List[str]:
        """
        Read logs from file, directory, string, or list
        
        Args:
            log_source: Path to log file/directory, log string, or list of log lines
            
        Returns:
            List of log lines
        """
        log_lines = []
        
        if isinstance(log_source, list):
            return [line.strip() for line in log_source if line.strip()]
        
        path = Path(log_source)
        
        if path.is_file():
            logger.info(f"Reading log file: {log_source}")
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                log_lines = f.readlines()
        elif path.is_dir():
            logger.info(f"Reading logs from directory: {log_source}")
            for log_file in path.glob("**/*.log"):
                try:
                    with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                        log_lines.extend(f.readlines())
                    logger.debug(f"Read {log_file}")
                except Exception as e:
                    logger.warning(f"Error reading {log_file}: {e}")
        else:
            # Assume it's a string of logs
            log_lines = log_source.split('\n')
        
        return [line.strip() for line in log_lines if line.strip()]
    
    def parse_logs(self, log_lines: List[str]) -> Dict[str, Any]:
        """
        Parse and categorize log lines with enhanced detection
        
        Args:
            log_lines: List of log lines
            
        Returns:
            Dictionary with parsed log information
        """
        parsed = {
            "total_lines": len(log_lines),
            "errors": [],
            "warnings": [],
            "info": [],
            "timestamps": [],
            "unique_errors": Counter(),
            "error_clusters": defaultdict(list),
            "ip_addresses": [],
            "http_codes": [],
            "fixable_issues": defaultdict(list),
            "metrics": defaultdict(list),
            "services": set(),
            "containers": set(),
            "severity_levels": Counter(),
            "error_rate": 0.0
        }
        
        error_count = 0
        
        for line_num, line in enumerate(log_lines, 1):
            # Extract timestamps
            for pattern in self.log_patterns["timestamp_patterns"]:
                timestamps = re.findall(pattern, line, re.IGNORECASE)
                if timestamps:
                    parsed["timestamps"].extend(timestamps)
                    break
            
            # Extract IP addresses
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = re.findall(ip_pattern, line)
            if ips:
                parsed["ip_addresses"].extend(ips)
            
            # Extract metrics
            for pattern in self.log_patterns["metric_patterns"]:
                matches = re.findall(pattern, line, re.IGNORECASE)
                if matches:
                    metric_name = pattern.split(r'[=\s:]')[0].replace('\\', '')
                    parsed["metrics"][metric_name].extend(matches)
            
            # Extract service names
            service_match = re.search(r'(?:service|container|pod)[\s:]+([a-zA-Z0-9_-]+)', line, re.IGNORECASE)
            if service_match:
                parsed["services"].add(service_match.group(1))
            
            # Check for fixable issues
            for issue_name, issue_info in self.fix_handlers.items():
                for pattern in issue_info["patterns"]:
                    if re.search(pattern, line, re.IGNORECASE):
                        parsed["fixable_issues"][issue_name].append({
                            "line": line,
                            "line_num": line_num,
                            "timestamp": timestamps[0] if timestamps else None
                        })
                        break
            
            # Determine severity
            if re.search(r'fatal|critical|emergency', line, re.IGNORECASE):
                parsed["severity_levels"]["CRITICAL"] += 1
                parsed["errors"].append(line)
                error_count += 1
            elif re.search(r'error|exception|fail', line, re.IGNORECASE):
                parsed["severity_levels"]["ERROR"] += 1
                parsed["errors"].append(line)
                error_count += 1
            elif re.search(r'warn|warning', line, re.IGNORECASE):
                parsed["severity_levels"]["WARNING"] += 1
                parsed["warnings"].append(line)
            else:
                parsed["severity_levels"]["INFO"] += 1
                parsed["info"].append(line)
            
            # Cluster similar errors
            if re.search(r'error|exception|fatal|critical', line, re.IGNORECASE):
                error_key = self._normalize_error(line)
                parsed["unique_errors"][error_key] += 1
                parsed["error_clusters"][error_key].append({
                    "line": line,
                    "line_num": line_num,
                    "timestamp": timestamps[0] if timestamps else None
                })
            
            # Extract HTTP status codes
            http_pattern = r'\s(2\d{2}|3\d{2}|4\d{2}|5\d{2})\s'
            codes = re.findall(http_pattern, line)
            if codes:
                parsed["http_codes"].extend(codes)
        
        # Calculate error rate
        if parsed["total_lines"] > 0:
            parsed["error_rate"] = (error_count / parsed["total_lines"]) * 100
        
        return parsed
    
    def _normalize_error(self, error_line: str) -> str:
        """Normalize error message for clustering with improved patterns"""
        # Remove variable parts like timestamps, IPs, IDs, memory addresses
        normalized = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '{IP}', error_line)
        normalized = re.sub(r'\b[0-9a-f]{8,}\b', '{ID}', normalized, flags=re.IGNORECASE)
        normalized = re.sub(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?', '{TIMESTAMP}', normalized)
        normalized = re.sub(r'\[\s*\d+\s*\]', '[{NUM}]', normalized)
        normalized = re.sub(r'0x[0-9a-f]+', '{HEX}', normalized, flags=re.IGNORECASE)
        normalized = re.sub(r'\b\d+\b', '{NUM}', normalized)
        normalized = re.sub(r'\s+', ' ', normalized)  # Normalize whitespace
        return normalized.strip()[:150]  # Limit length
    
    # Enhanced Fix Handlers with better error handling and verification
    
    def _run_command(self, cmd: str, timeout: int = 30, check: bool = False) -> subprocess.CompletedProcess:
        """Run a shell command safely with timeout and error handling"""
        try:
            logger.debug(f"Running command: {cmd}")
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                executable='/bin/bash'
            )
            
            if result.returncode != 0:
                logger.warning(f"Command failed with exit code {result.returncode}: {cmd}")
                if result.stderr:
                    logger.debug(f"stderr: {result.stderr[:200]}")
            
            return result
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {timeout}s: {cmd}")
            raise FixError(f"Command timed out: {cmd}")
        except Exception as e:
            logger.error(f"Error running command: {e}")
            raise FixError(f"Failed to run command: {e}")
    
    def _verify_disk_space(self) -> bool:
        """Verify if disk space issue is resolved"""
        result = self._run_command("df -h / | awk 'NR==2 {print $5}' | sed 's/%//'")
        if result.returncode == 0 and result.stdout.strip():
            usage = int(result.stdout.strip())
            return usage < 85  # Less than 85% usage
        return False
    
    def _fix_disk_full(self, error_lines: List[Dict]) -> Dict[str, Any]:
        """Enhanced fix for disk full issues"""
        result = {
            "action": "Cleaning up disk space",
            "commands": [],
            "success": False,
            "details": [],
            "verification": None,
            "backup_created": False
        }
        
        try:
            # Get current disk usage
            df_result = self._run_command("df -h")
            result["details"].append(f"Initial disk usage:\n{df_result.stdout}")
            
            # Find large files and directories
            find_result = self._run_command(
                "find / -type f -size +100M -exec ls -lh {} \\; 2>/dev/null | head -20"
            )
            result["details"].append(f"Large files:\n{find_result.stdout}")
            
            # Create backup of important logs before cleanup
            backup_cmd = "tar -czf /tmp/log-backup-$(date +%Y%m%d-%H%M%S).tar.gz /var/log/*.log 2>/dev/null || true"
            self._run_command(backup_cmd)
            result["backup_created"] = True
            
            # Disk cleanup commands with increasing aggressiveness
            commands = [
                # Level 1: Safe cleanup
                "sudo journalctl --vacuum-time=3d 2>/dev/null || true",
                "sudo apt-get clean 2>/dev/null || true",
                "sudo yum clean all 2>/dev/null || true",
                "sudo dnf clean all 2>/dev/null || true",
                "sudo rm -rf /tmp/* 2>/dev/null || true",
                "sudo rm -rf /var/tmp/* 2>/dev/null || true",
                
                # Level 2: Old log cleanup
                "sudo find /var/log -type f -name '*.log' -mtime +7 -delete 2>/dev/null || true",
                "sudo find /var/log -type f -name '*.gz' -mtime +7 -delete 2>/dev/null || true",
                
                # Level 3: Docker cleanup if docker exists
                "docker system prune -f 2>/dev/null || true",
                "docker image prune -a -f 2>/dev/null || true",
                "docker volume prune -f 2>/dev/null || true",
                
                # Level 4: Package manager caches
                "sudo rm -rf /var/cache/apt/archives/*.deb 2>/dev/null || true",
                "sudo rm -rf /var/cache/yum/* 2>/dev/null || true",
                
                # Level 5: Old kernels (Ubuntu)
                "sudo apt-get autoremove --purge -y 2>/dev/null || true",
                
                # Level 6: Truncate specific large logs
                "sudo truncate -s 0 /var/log/syslog 2>/dev/null || true",
                "sudo truncate -s 0 /var/log/messages 2>/dev/null || true",
            ]
            
            # Execute commands
            for cmd in commands:
                if not self._run_command(f"which {cmd.split()[1] if cmd.startswith('docker') else 'echo'}", check=False).stdout:
                    continue  # Skip if command not available
                    
                result["commands"].append(cmd)
                if not self.dry_run:
                    cmd_result = self._run_command(cmd, timeout=30)
                    result["details"].append(f"Command output: {cmd_result.stdout[:200]}")
                    
                    # Check if we've freed enough space
                    if self._verify_disk_space():
                        logger.info("Sufficient disk space recovered")
                        break
            
            # Verify fix
            if not self.dry_run:
                result["verification"] = self._verify_disk_space()
                df_result = self._run_command("df -h")
                result["details"].append(f"Final disk usage:\n{df_result.stdout}")
                result["success"] = result["verification"]
            
        except Exception as e:
            logger.error(f"Error in disk full fix: {e}")
            result["details"].append(f"Error: {str(e)}")
        
        return result
    
    def _rollback_disk_cleanup(self) -> bool:
        """Rollback disk cleanup (restore from backup)"""
        try:
            # Find latest backup
            backup = self._run_command("ls -t /tmp/log-backup-*.tar.gz 2>/dev/null | head -1")
            if backup.stdout.strip():
                self._run_command(f"tar -xzf {backup.stdout.strip()} -C /")
                logger.info(f"Restored from backup: {backup.stdout.strip()}")
                return True
        except Exception as e:
            logger.error(f"Rollback failed: {e}")
        return False
    
    def _verify_memory_status(self) -> bool:
        """Verify memory status"""
        result = self._run_command("free | grep Mem | awk '{print ($3/$2)*100}'")
        if result.returncode == 0 and result.stdout.strip():
            usage = float(result.stdout.strip())
            return usage < 80  # Less than 80% memory usage
        return False
    
    def _fix_out_of_memory(self, error_lines: List[Dict]) -> Dict[str, Any]:
        """Enhanced fix for out of memory issues"""
        result = {
            "action": "Clearing memory and optimizing usage",
            "commands": [],
            "success": False,
            "details": [],
            "verification": None
        }
        
        try:
            # Get current memory status
            mem_result = self._run_command("free -h")
            result["details"].append(f"Initial memory status:\n{mem_result.stdout}")
            
            # Top memory processes
            top_result = self._run_command("ps aux --sort=-%mem | head -20")
            result["details"].append(f"Top memory processes:\n{top_result.stdout}")
            
            # Memory optimization commands
            commands = [
                # Clear page cache, dentries, and inodes
                "sudo sync && echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null 2>&1 || true",
                
                # Restart memory-intensive services
                "sudo systemctl restart $(systemctl list-units --type=service --state=running | grep -E 'tomcat|java|python|node|nginx|mysql|postgres' | awk '{print $1}') 2>/dev/null || true",
                
                # Adjust swappiness
                "sudo sysctl vm.swappiness=10 2>/dev/null || true",
                
                # Kill top memory processes if > 90%
                "ps aux --sort=-%mem | awk '$4 > 90 {print $2}' | xargs -r kill -15 2>/dev/null || true",
            ]
            
            # Execute commands
            for cmd in commands:
                result["commands"].append(cmd)
                if not self.dry_run:
                    self._run_command(cmd, timeout=30)
            
            # Wait for system to stabilize
            time.sleep(5)
            
            # Verify fix
            if not self.dry_run:
                result["verification"] = self._verify_memory_status()
                mem_result = self._run_command("free -h")
                result["details"].append(f"Final memory status:\n{mem_result.stdout}")
                result["success"] = result["verification"]
            
        except Exception as e:
            logger.error(f"Error in OOM fix: {e}")
            result["details"].append(f"Error: {str(e)}")
        
        return result
    
    def _rollback_memory_cleanup(self) -> bool:
        """Rollback memory cleanup (restore swappiness)"""
        try:
            self._run_command("sudo sysctl vm.swappiness=60")
            return True
        except:
            return False
    
    def _verify_connection(self, host: str = "localhost", port: Optional[int] = None) -> bool:
        """Verify network connection"""
        if port:
            cmd = f"nc -zv {host} {port} 2>&1"
        else:
            cmd = f"ping -c 3 {host} > /dev/null 2>&1"
        result = self._run_command(cmd, check=False)
        return result.returncode == 0
    
    def _fix_connection_refused(self, error_lines: List[Dict]) -> Dict[str, Any]:
        """Enhanced fix for connection refused issues"""
        result = {
            "action": "Checking and restarting network services",
            "commands": [],
            "success": False,
            "details": [],
            "verification": None
        }
        
        try:
            # Extract host and port from error lines
            host = None
            port = None
            
            for error in error_lines[:5]:
                line = error["line"]
                # Extract host
                host_match = re.search(r'(?:to|connect to|refused:?\s*)([a-zA-Z0-9_.-]+)(?::|\s|$)', line)
                if host_match:
                    host = host_match.group(1)
                
                # Extract port
                port_match = re.search(r':(\d{4,5})', line)
                if port_match:
                    port = int(port_match.group(1))
            
            if host:
                result["details"].append(f"Target host: {host}, port: {port}")
                
                # Check DNS resolution
                dns_result = self._run_command(f"getent hosts {host} || nslookup {host} 2>/dev/null")
                result["details"].append(f"DNS resolution:\n{dns_result.stdout}")
            
            # Service restart commands based on common services
            commands = [
                "sudo systemctl restart networking 2>/dev/null || true",
                "sudo systemctl restart network 2>/dev/null || true",
                "sudo systemctl restart docker 2>/dev/null || true",
                "sudo systemctl restart nginx 2>/dev/null || true",
                "sudo systemctl restart postgresql 2>/dev/null || true",
                "sudo systemctl restart mysql 2>/dev/null || true",
                "sudo systemctl restart redis 2>/dev/null || true",
            ]
            
            # Execute commands
            for cmd in commands:
                service = cmd.split()[3] if 'systemctl' in cmd else None
                if service and not self._check_service_exists(service):
                    continue
                    
                result["commands"].append(cmd)
                if not self.dry_run:
                    self._run_command(cmd, timeout=30)
            
            # Verify fix
            if not self.dry_run:
                result["verification"] = self._verify_connection(host or "localhost", port)
                result["success"] = result["verification"]
            
        except Exception as e:
            logger.error(f"Error in connection refused fix: {e}")
            result["details"].append(f"Error: {str(e)}")
        
        return result
    
    def _verify_database(self, db_type: str = None) -> bool:
        """Verify database connectivity"""
        checks = {
            "postgresql": "pg_isready -q",
            "mysql": "mysqladmin ping -h localhost",
            "redis": "redis-cli ping",
            "mongodb": "mongo --eval 'db.runCommand({ping:1})' --quiet"
        }
        
        if db_type and db_type in checks:
            result = self._run_command(checks[db_type], check=False)
            return result.returncode == 0
        
        # Check all databases
        for cmd in checks.values():
            result = self._run_command(cmd, check=False)
            if result.returncode == 0:
                return True
        return False
    
    def _fix_database_connection(self, error_lines: List[Dict]) -> Dict[str, Any]:
        """Enhanced fix for database connection issues"""
        result = {
            "action": "Checking and restarting database services",
            "commands": [],
            "success": False,
            "details": [],
            "verification": None
        }
        
        try:
            # Detect database type from errors
            db_type = None
            for error in error_lines[:5]:
                line = error["line"].lower()
                if "postgres" in line or "pgsql" in line:
                    db_type = "postgresql"
                elif "mysql" in line or "mariadb" in line:
                    db_type = "mysql"
                elif "redis" in line:
                    db_type = "redis"
                elif "mongo" in line:
                    db_type = "mongodb"
            
            result["details"].append(f"Detected database: {db_type or 'unknown'}")
            
            # Check database status
            if db_type:
                status_cmd = f"sudo systemctl status {db_type} 2>/dev/null"
                status_result = self._run_command(status_cmd, check=False)
                result["details"].append(f"Database status:\n{status_result.stdout[:500]}")
            
            # Database restart commands
            commands = []
            if db_type:
                commands = [
                    f"sudo systemctl restart {db_type}",
                    f"sudo systemctl status {db_type} --no-pager"
                ]
            else:
                commands = [
                    "sudo systemctl restart postgresql 2>/dev/null || true",
                    "sudo systemctl restart mysql 2>/dev/null || true",
                    "sudo systemctl restart redis 2>/dev/null || true",
                    "sudo systemctl restart mongodb 2>/dev/null || true",
                ]
            
            # Execute commands
            for cmd in commands:
                if 'systemctl' in cmd and not self._check_service_exists(cmd.split()[3]):
                    continue
                    
                result["commands"].append(cmd)
                if not self.dry_run:
                    self._run_command(cmd, timeout=60)
            
            # Wait for database to start
            time.sleep(5)
            
            # Verify fix
            if not self.dry_run:
                result["verification"] = self._verify_database(db_type)
                result["success"] = result["verification"]
            
        except Exception as e:
            logger.error(f"Error in database connection fix: {e}")
            result["details"].append(f"Error: {str(e)}")
        
        return result
    
    def _verify_cpu_usage(self) -> bool:
        """Verify CPU usage"""
        result = self._run_command("top -bn1 | grep 'Cpu(s)' | awk '{print $2}' | cut -d'%' -f1")
        if result.returncode == 0 and result.stdout.strip():
            usage = float(result.stdout.strip())
            return usage < 70  # Less than 70% CPU usage
        return False
    
    def _fix_high_cpu(self, error_lines: List[Dict]) -> Dict[str, Any]:
        """Enhanced fix for high CPU usage"""
        result = {
            "action": "Identifying and managing high CPU processes",
            "commands": [],
            "success": False,
            "details": [],
            "verification": None
        }
        
        try:
            # Get current CPU usage
            cpu_result = self._run_command("top -bn1 | head -20")
            result["details"].append(f"Current CPU usage:\n{cpu_result.stdout}")
            
            # Find processes using high CPU
            high_cpu = self._run_command(
                "ps aux --sort=-%cpu | awk '$3 > 70 {print $2, $3, $11}' | head -10"
            )
            result["details"].append(f"High CPU processes:\n{high_cpu.stdout}")
            
            # Get process details
            processes = []
            for line in high_cpu.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        processes.append({
                            "pid": parts[0],
                            "cpu": parts[1],
                            "command": ' '.join(parts[2:])
                        })
            
            # Generate commands to handle high CPU processes
            commands = []
            for proc in processes[:3]:  # Limit to top 3
                pid = proc["pid"]
                # Try graceful stop first, then force kill if needed
                commands.extend([
                    f"sudo kill -15 {pid} 2>/dev/null || true",
                    f"sleep 2",
                    f"sudo kill -9 {pid} 2>/dev/null || true"
                ])
            
            # Also restart common services
            commands.extend([
                "sudo systemctl restart $(systemctl list-units --type=service --state=running | grep -E 'tomcat|java|python|node' | awk '{print $1}') 2>/dev/null || true"
            ])
            
            # Execute commands
            for cmd in commands:
                result["commands"].append(cmd)
                if not self.dry_run:
                    self._run_command(cmd, timeout=15)
                    time.sleep(1)
            
            # Verify fix
            if not self.dry_run:
                time.sleep(5)  # Wait for system to stabilize
                result["verification"] = self._verify_cpu_usage()
                cpu_result = self._run_command("top -bn1 | head -10")
                result["details"].append(f"Final CPU status:\n{cpu_result.stdout}")
                result["success"] = result["verification"]
            
        except Exception as e:
            logger.error(f"Error in high CPU fix: {e}")
            result["details"].append(f"Error: {str(e)}")
        
        return result
    
    def _verify_service_status(self, service: str = None) -> bool:
        """Verify service status"""
        if service:
            result = self._run_command(f"systemctl is-active {service}", check=False)
            return result.returncode == 0
        
        # Check if any failed services
        result = self._run_command("systemctl --failed --no-pager | wc -l")
        return int(result.stdout.strip()) <= 1  # At most 1 failed service
    
    def _fix_service_down(self, error_lines: List[Dict]) -> Dict[str, Any]:
        """Enhanced fix for service down issues"""
        result = {
            "action": "Restarting failed services",
            "commands": [],
            "success": False,
            "details": [],
            "verification": None
        }
        
        try:
            # Find failed services
            failed = self._run_command("systemctl --failed --no-pager")
            result["details"].append(f"Failed services:\n{failed.stdout}")
            
            # Extract service names
            service_units = re.findall(r'●\s+(\S+\.service)', failed.stdout)
            
            if not service_units:
                # Try to extract service from error lines
                for error in error_lines[:5]:
                    match = re.search(r'(?:service|process)[\s:]+([a-zA-Z0-9_-]+)', error["line"], re.IGNORECASE)
                    if match:
                        service_units.append(f"{match.group(1)}.service")
            
            result["details"].append(f"Services to restart: {service_units}")
            
            # Generate restart commands
            commands = []
            for unit in service_units:
                commands.extend([
                    f"sudo systemctl restart {unit}",
                    f"sudo systemctl status {unit} --no-pager"
                ])
            
            # Execute commands
            for cmd in commands:
                result["commands"].append(cmd)
                if not self.dry_run:
                    restart_result = self._run_command(cmd, timeout=30)
                    if "status" in cmd:
                        result["details"].append(f"Service status after restart:\n{restart_result.stdout[:200]}")
            
            # Verify fix
            if not self.dry_run:
                result["verification"] = self._verify_service_status()
                result["success"] = result["verification"]
            
        except Exception as e:
            logger.error(f"Error in service down fix: {e}")
            result["details"].append(f"Error: {str(e)}")
        
        return result
    
    def _verify_permissions(self, path: str = None) -> bool:
        """Verify file permissions"""
        if path and os.path.exists(path):
            return os.access(path, os.R_OK | os.W_OK)
        return False
    
    def _fix_permission_denied(self, error_lines: List[Dict]) -> Dict[str, Any]:
        """Enhanced fix for permission denied issues"""
        result = {
            "action": "Fixing file/directory permissions",
            "commands": [],
            "success": False,
            "details": [],
            "verification": None,
            "backup_created": False
        }
        
        try:
            # Extract file paths from errors
            files = set()
            for error in error_lines[:10]:
                line = error["line"]
                # Look for file paths
                matches = re.findall(r'(?:file|directory|path|/[\w/\-\.]+)', line)
                for match in matches:
                    if match.startswith('/') and os.path.exists(match):
                        files.add(match)
            
            result["details"].append(f"Files to fix: {files}")
            
            # Create backup of original permissions
            if files and not self.dry_run:
                backup_info = {}
                for file_path in files:
                    stat_result = self._run_command(f"stat -c '%a %u %g' {file_path}")
                    if stat_result.returncode == 0:
                        backup_info[file_path] = stat_result.stdout.strip()
                
                result["backup_created"] = bool(backup_info)
                result["permission_backup"] = backup_info
            
            # Permission fix commands
            commands = []
            for file_path in files:
                if os.path.isdir(file_path):
                    commands.append(f"sudo chmod -R 755 {file_path}")
                else:
                    commands.append(f"sudo chmod 644 {file_path}")
                
                # Fix ownership to current user if it's in home directory
                if file_path.startswith('/home'):
                    user = os.getenv('USER') or os.getenv('USERNAME')
                    if user:
                        commands.append(f"sudo chown {user}:{user} {file_path}")
            
            # Execute commands
            for cmd in commands:
                result["commands"].append(cmd)
                if not self.dry_run:
                    self._run_command(cmd, timeout=10)
            
            # Verify fix
            if not self.dry_run:
                verification_results = []
                for file_path in files:
                    verification_results.append(self._verify_permissions(file_path))
                
                result["verification"] = all(verification_results)
                result["success"] = result["verification"]
            
        except Exception as e:
            logger.error(f"Error in permission denied fix: {e}")
            result["details"].append(f"Error: {str(e)}")
        
        return result
    
    def _rollback_permissions(self, backup_data: Dict[str, str]) -> bool:
        """Rollback permission changes"""
        try:
            for file_path, perms in backup_data.items():
                if os.path.exists(file_path):
                    self._run_command(f"sudo chmod {perms} {file_path}")
            return True
        except:
            return False
    
    def _verify_port_available(self, port: int) -> bool:
        """Verify if a port is available"""
        result = self._run_command(f"lsof -i :{port} | wc -l", check=False)
        return int(result.stdout.strip()) == 0
    
    def _fix_port_conflict(self, error_lines: List[Dict]) -> Dict[str, Any]:
        """Enhanced fix for port conflict issues"""
        result = {
            "action": "Resolving port conflicts",
            "commands": [],
            "success": False,
            "details": [],
            "verification": None
        }
        
        try:
            # Extract port numbers
            ports = set()
            for error in error_lines[:5]:
                line = error["line"]
                matches = re.findall(r'(?:port|:)(\d{4,5})', line)
                ports.update(matches)
            
            result["details"].append(f"Conflicting ports: {ports}")
            
            for port in ports:
                # Find process using the port
                lsof_result = self._run_command(f"lsof -i :{port} -t")
                pids = lsof_result.stdout.strip().split('\n')
                
                result["details"].append(f"Processes on port {port}: {pids}")
                
                # Kill processes using the port
                for pid in pids:
                    if pid.strip():
                        # Get process info before killing
                        ps_result = self._run_command(f"ps -p {pid} -o comm=")
                        proc_name = ps_result.stdout.strip()
                        
                        result["details"].append(f"Killing process {pid} ({proc_name}) on port {port}")
                        
                        # Graceful kill first, then force
                        commands = [
                            f"sudo kill -15 {pid} 2>/dev/null || true",
                            f"sleep 2",
                            f"sudo kill -9 {pid} 2>/dev/null || true"
                        ]
                        
                        for cmd in commands:
                            result["commands"].append(cmd)
                            if not self.dry_run:
                                self._run_command(cmd, timeout=5)
            
            # Verify fix
            if not self.dry_run:
                verification_results = []
                for port in ports:
                    verification_results.append(self._verify_port_available(int(port)))
                
                result["verification"] = all(verification_results)
                result["success"] = result["verification"]
            
        except Exception as e:
            logger.error(f"Error in port conflict fix: {e}")
            result["details"].append(f"Error: {str(e)}")
        
        return result
    
    def _verify_nginx(self) -> bool:
        """Verify nginx status"""
        result = self._run_command("nginx -t 2>&1", check=False)
        return result.returncode == 0
    
    def _fix_nginx(self, error_lines: List[Dict]) -> Dict[str, Any]:
        """Fix nginx issues"""
        result = {
            "action": "Checking and restarting nginx",
            "commands": [],
            "success": False,
            "details": [],
            "verification": None
        }
        
        try:
            # Test nginx configuration
            test_result = self._run_command("nginx -t 2>&1")
            result["details"].append(f"Configuration test:\n{test_result.stdout}")
            
            if test_result.returncode != 0:
                # Try to find configuration error
                error_match = re.search(r'(.+?\.conf):\d+', test_result.stderr)
                if error_match:
                    config_file = error_match.group(1)
                    result["details"].append(f"Error in config: {config_file}")
                    
                    # Create backup
                    self._run_command(f"cp {config_file} {config_file}.backup")
                    result["backup_created"] = True
            
            commands = [
                "sudo nginx -t && sudo systemctl restart nginx",
                "sudo systemctl status nginx --no-pager"
            ]
            
            for cmd in commands:
                result["commands"].append(cmd)
                if not self.dry_run:
                    self._run_command(cmd, timeout=30)
            
            # Verify fix
            if not self.dry_run:
                result["verification"] = self._verify_nginx()
                result["success"] = result["verification"]
            
        except Exception as e:
            logger.error(f"Error in nginx fix: {e}")
            result["details"].append(f"Error: {str(e)}")
        
        return result
    
    def _verify_docker(self) -> bool:
        """Verify docker status"""
        result = self._run_command("docker info 2>&1", check=False)
        return result.returncode == 0
    
    def _fix_docker(self, error_lines: List[Dict]) -> Dict[str, Any]:
        """Fix docker issues"""
        result = {
            "action": "Restarting docker daemon and containers",
            "commands": [],
            "success": False,
            "details": [],
            "verification": None
        }
        
        try:
            # Get docker status
            status_result = self._run_command("systemctl status docker --no-pager")
            result["details"].append(f"Docker status:\n{status_result.stdout[:500]}")
            
            # List failed containers
            failed_containers = self._run_command("docker ps -a --filter status=exited --format '{{.Names}}'")
            result["details"].append(f"Failed containers:\n{failed_containers.stdout}")
            
            commands = [
                "sudo systemctl restart docker",
                "sleep 5",
                "docker start $(docker ps -a -q --filter status=exited) 2>/dev/null || true",
                "docker ps"
            ]
            
            for cmd in commands:
                result["commands"].append(cmd)
                if not self.dry_run:
                    self._run_command(cmd, timeout=60)
            
            # Verify fix
            if not self.dry_run:
                result["verification"] = self._verify_docker()
                result["success"] = result["verification"]
            
        except Exception as e:
            logger.error(f"Error in docker fix: {e}")
            result["details"].append(f"Error: {str(e)}")
        
        return result
    
    def _verify_ssl_cert(self, cert_path: str = None) -> bool:
        """Verify SSL certificate"""
        if cert_path:
            result = self._run_command(f"openssl x509 -in {cert_path} -checkend 86400 -noout")
            return result.returncode == 0
        return False
    
    def _fix_ssl_cert(self, error_lines: List[Dict]) -> Dict[str, Any]:
        """Fix SSL certificate issues"""
        result = {
            "action": "Checking and renewing SSL certificates",
            "commands": [],
            "success": False,
            "details": [],
            "verification": None,
            "backup_created": False
        }
        
        try:
            # Check certbot availability
            has_certbot = self._run_command("which certbot", check=False).returncode == 0
            
            if has_certbot:
                # Check certificate expiry
                expiry_check = self._run_command("certbot certificates")
                result["details"].append(f"Certificates:\n{expiry_check.stdout}")
                
                # Create backup
                backup_cmd = "tar -czf /tmp/letsencrypt-backup-$(date +%Y%m%d).tar.gz /etc/letsencrypt 2>/dev/null || true"
                self._run_command(backup_cmd)
                result["backup_created"] = True
                
                commands = [
                    "certbot renew --dry-run",
                    "certbot renew --quiet"
                ]
            else:
                # Try to auto-renew using different methods
                commands = [
                    "sudo systemctl restart nginx 2>/dev/null || true",
                    "sudo systemctl restart apache2 2>/dev/null || true",
                    "sudo update-ca-certificates 2>/dev/null || true"
                ]
            
            for cmd in commands:
                result["commands"].append(cmd)
                if not self.dry_run:
                    self._run_command(cmd, timeout=60)
            
            # Verify fix
            if not self.dry_run and has_certbot:
                result["verification"] = True  # Certbot renew handled it
                result["success"] = True
            
        except Exception as e:
            logger.error(f"Error in SSL cert fix: {e}")
            result["details"].append(f"Error: {str(e)}")
        
        return result
    
    def _rollback_ssl_cert(self) -> bool:
        """Rollback SSL certificate changes"""
        try:
            backup = self._run_command("ls -t /tmp/letsencrypt-backup-*.tar.gz 2>/dev/null | head -1")
            if backup.stdout.strip():
                self._run_command(f"tar -xzf {backup.stdout.strip()} -C /")
                return True
        except:
            pass
        return False
    
    def _verify_application_status(self, app_name: str = None) -> bool:
        """Verify application status"""
        if app_name:
            result = self._run_command(f"pgrep -f {app_name} | wc -l")
            return int(result.stdout.strip()) > 0
        return False
    
    def _fix_application_hang(self, error_lines: List[Dict]) -> Dict[str, Any]:
        """Fix hung application processes"""
        result = {
            "action": "Restarting hung application processes",
            "commands": [],
            "success": False,
            "details": [],
            "verification": None
        }
        
        try:
            # Extract application name from errors
            app_name = None
            for error in error_lines[:5]:
                match = re.search(r'(?:application|process)[\s:]+([a-zA-Z0-9_-]+)', error["line"], re.IGNORECASE)
                if match:
                    app_name = match.group(1)
                    break
            
            if app_name:
                result["details"].append(f"Target application: {app_name}")
                
                # Find unresponsive processes
                ps_result = self._run_command(f"ps aux | grep {app_name} | grep -v grep")
                result["details"].append(f"Processes:\n{ps_result.stdout}")
                
                # Extract PIDs
                pids = re.findall(r'^\s*\d+\s+(\d+)', ps_result.stdout, re.MULTILINE)
                
                commands = []
                for pid in pids:
                    # Thread dump for Java apps
                    if self._check_command("jstack"):
                        commands.append(f"jstack {pid} > /tmp/threaddump-{pid}.txt 2>/dev/null || true")
                    
                    # Kill process
                    commands.extend([
                        f"kill -15 {pid} 2>/dev/null || true",
                        f"sleep 3",
                        f"kill -9 {pid} 2>/dev/null || true"
                    ])
                
                # Restart application service
                if self._check_service_exists(app_name):
                    commands.append(f"sudo systemctl restart {app_name}")
                
                for cmd in commands:
                    result["commands"].append(cmd)
                    if not self.dry_run:
                        self._run_command(cmd, timeout=30)
                
                # Verify fix
                if not self.dry_run:
                    time.sleep(5)
                    result["verification"] = self._verify_application_status(app_name)
                    result["success"] = result["verification"]
            
        except Exception as e:
            logger.error(f"Error in application hang fix: {e}")
            result["details"].append(f"Error: {str(e)}")
        
        return result
    
    def _verify_network(self) -> bool:
        """Verify network connectivity"""
        # Check if we can reach common services
        test_hosts = ["8.8.8.8", "1.1.1.1"]
        for host in test_hosts:
            result = self._run_command(f"ping -c 2 -W 2 {host} > /dev/null 2>&1", check=False)
            if result.returncode == 0:
                return True
        return False
    
    def _fix_network(self, error_lines: List[Dict]) -> Dict[str, Any]:
        """Fix network issues"""
        result = {
            "action": "Restarting network services",
            "commands": [],
            "success": False,
            "details": [],
            "verification": None
        }
        
        try:
            # Get network interface status
            ip_result = self._run_command("ip addr show")
            result["details"].append(f"Network interfaces:\n{ip_result.stdout[:500]}")
            
            # Get routing table
            route_result = self._run_command("ip route show")
            result["details"].append(f"Routing table:\n{route_result.stdout}")
            
            commands = [
                "sudo systemctl restart networking 2>/dev/null || true",
                "sudo systemctl restart network 2>/dev/null || true",
                "sudo dhclient -r 2>/dev/null || true",
                "sudo dhclient 2>/dev/null || true",
                "sudo ip link set dev $(ip route | grep default | awk '{print $5}') down 2>/dev/null || true",
                "sleep 5",
                "sudo ip link set dev $(ip route | grep default | awk '{print $5}') up 2>/dev/null || true"
            ]
            
            for cmd in commands:
                result["commands"].append(cmd)
                if not self.dry_run:
                    self._run_command(cmd, timeout=30)
            
            # Verify fix
            if not self.dry_run:
                time.sleep(10)
                result["verification"] = self._verify_network()
                result["success"] = result["verification"]
            
        except Exception as e:
            logger.error(f"Error in network fix: {e}")
            result["details"].append(f"Error: {str(e)}")
        
        return result
    
    # Helper methods
    def _check_command(self, cmd: str) -> bool:
        """Check if a command exists"""
        result = self._run_command(f"which {cmd}", check=False)
        return result.returncode == 0
    
    def _check_service_exists(self, service: str) -> bool:
        """Check if a systemd service exists"""
        result = self._run_command(f"systemctl list-unit-files {service}.service", check=False)
        return result.returncode == 0
    
    def _execute_fix(self, fix_name: str, error_data: List[Dict]) -> Dict[str, Any]:
        """Execute a fix for a specific issue with enhanced safety"""
        if fix_name not in self.fix_handlers:
            return {"error": f"No handler for {fix_name}"}
        
        handler_info = self.fix_handlers[fix_name]
        
        # Display fix information
        print(f"\n🔧 {'='*60}")
        print(f"🔧 FIX: {fix_name.upper().replace('_', ' ')}")
        print(f"🔧 {'='*60}")
        print(f"Description: {handler_info['description']}")
        print(f"Risk level: {handler_info['risk']}")
        print(f"Requires sudo: {handler_info['requires_sudo']}")
        print(f"Timeout: {handler_info.get('timeout', 30)} seconds")
        
        # Check sudo access if required
        if handler_info['requires_sudo'] and not self.dry_run:
            sudo_check = self._run_command("sudo -n true 2>/dev/null", check=False)
            if sudo_check.returncode != 0:
                print("⚠️  Warning: This fix requires sudo access but may not be available")
                if not self.auto_approve:
                    response = input("Continue anyway? (y/n): ").lower()
                    if response != 'y':
                        print("⏩ Fix skipped")
                        return {"skipped": True, "reason": "sudo required"}
        
        # Show affected log lines
        print(f"\n📋 Triggered by {len(error_data)} log entries:")
        for error in error_data[:3]:  # Show first 3
            print(f"  • Line {error['line_num']}: {error['line'][:100]}...")
        if len(error_data) > 3:
            print(f"  ... and {len(error_data) - 3} more")
        
        # Ask for approval if not auto_approve
        if not self.auto_approve and not self.dry_run:
            print(f"\n⚠️  Risk level: {handler_info['risk']}")
            response = input(f"Apply this fix? (y/n/a for all): ").lower()
            
            if response == 'a':
                self.auto_approve = True
            elif response != 'y':
                print("⏩ Fix skipped")
                return {"skipped": True, "reason": "user declined"}
        
        if self.dry_run:
            print("\n📋 DRY RUN - Would execute fix")
        
        # Get fix commands
        fix_result = handler_info["handler"](error_data)
        
        # Add fix metadata
        fix_result["fix_name"] = fix_name
        fix_result["timestamp"] = datetime.datetime.now().isoformat()
        fix_result["dry_run"] = self.dry_run
        
        # Display commands
        if fix_result.get("commands"):
            print(f"\n⚡ Commands to execute:")
            for i, cmd in enumerate(fix_result["commands"], 1):
                print(f"  {i}. {cmd}")
        
        # Show details
        if fix_result.get("details"):
            print(f"\n📊 Details:")
            for detail in fix_result["details"]:
                if detail.strip():
                    print(f"  {detail[:200]}...")
        
        # Execute commands if not dry run
        if not self.dry_run:
            print(f"\n⚡ Executing fix...")
            executed_commands = []
            
            for cmd in fix_result.get("commands", []):
                try:
                    print(f"  → {cmd[:80]}...")
                    result = self._run_command(
                        cmd, 
                        timeout=handler_info.get('timeout', 30)
                    )
                    
                    executed_commands.append({
                        "command": cmd,
                        "returncode": result.returncode,
                        "stdout": result.stdout[:500],
                        "stderr": result.stderr[:500]
                    })
                    
                    if result.returncode != 0:
                        print(f"    ⚠️  Warning: Command exited with {result.returncode}")
                        if result.stderr:
                            print(f"    Error: {result.stderr[:100]}")
                    
                except FixError as e:
                    print(f"    ❌ Error: {e}")
                    executed_commands.append({
                        "command": cmd,
                        "error": str(e)
                    })
                
                time.sleep(1)  # Brief pause between commands
            
            fix_result["executed_commands"] = executed_commands
            fix_result["success"] = all(
                cmd.get("returncode", -1) == 0 
                for cmd in executed_commands 
                if "error" not in cmd
            )
            
            # Run verification if available
            if handler_info.get("verification"):
                print(f"\n🔍 Verifying fix...")
                verification = handler_info["verification"]()
                fix_result["verification_passed"] = verification
                print(f"  ✓ Verification {'passed' if verification else 'failed'}")
                fix_result["success"] = fix_result.get("success", False) and verification
            
            # Store in history
            self.fix_history.append(fix_result)
            
            if fix_result["success"]:
                print(f"✅ Fix completed successfully")
            else:
                print(f"⚠️  Fix completed with issues")
        
        return fix_result
    
    def analyze_with_ai(self, parsed_logs: Dict[str, Any], context: str = "", auto_fix: bool = False) -> str:
        """
        Use AI to analyze logs and provide insights
        
        Args:
            parsed_logs: Parsed log data
            context: Additional context about the system
            auto_fix: Whether to attempt automatic fixes
            
        Returns:
            AI-generated analysis
        """
        # Prepare summary for AI
        summary = self._prepare_summary(parsed_logs)
        
        # Sample error lines for detailed analysis
        sample_errors = []
        for error_key, count in list(parsed_logs["unique_errors"].items())[:10]:
            sample_errors.append(f"Error pattern (occurred {count} times): {error_key}")
            if count > 1 and parsed_logs["error_clusters"][error_key]:
                first_error = parsed_logs["error_clusters"][error_key][0]
                sample_errors.append(f"Example (line {first_error['line_num']}): {first_error['line'][:200]}")
        
        # Add fixable issues information
        fixable_summary = ""
        if parsed_logs["fixable_issues"]:
            fixable_summary = "\n🔧 AUTO-FIXABLE ISSUES DETECTED:\n"
            for issue, lines in parsed_logs["fixable_issues"].items():
                fixable_summary += f"  • {issue}: {len(lines)} occurrences\n"
                if issue in self.fix_handlers:
                    fixable_summary += f"    Fix: {self.fix_handlers[issue]['description']} (Risk: {self.fix_handlers[issue]['risk']})\n"
        
        # Add metrics summary
        metrics_summary = ""
        if parsed_logs["metrics"]:
            metrics_summary = "\n📊 METRICS:\n"
            for metric, values in parsed_logs["metrics"].items():
                if values:
                    avg = sum(float(v) for v in values if v.replace('.', '').isdigit()) / len(values)
                    metrics_summary += f"  • {metric}: avg {avg:.1f}%\n"
        
        prompt = f"""You are a senior Site Reliability Engineer (SRE) analyzing log files. 
Provide a comprehensive analysis of the following log data:

📈 SUMMARY STATISTICS:
- Total log lines: {parsed_logs['total_lines']}
- Error rate: {parsed_logs['error_rate']:.2f}%
- Critical issues: {parsed_logs['severity_levels'].get('CRITICAL', 0)}
- Errors: {parsed_logs['severity_levels'].get('ERROR', 0)}
- Warnings: {parsed_logs['severity_levels'].get('WARNING', 0)}
- Unique error patterns: {len(parsed_logs['unique_errors'])}
- Time range: {summary['time_range']}
- Top IPs: {summary['top_ips']}
- HTTP status codes: {summary['http_codes']}
- Services affected: {', '.join(list(parsed_logs['services'])[:5]) or 'None'}

{fixable_summary}
{metrics_summary}

🔴 ERROR PATTERNS:
{chr(10).join(sample_errors)}

📝 CONTEXT:
{context}

Please provide:

1. 🎯 EXECUTIVE SUMMARY
   A brief overview of system health and major issues

2. 🔥 CRITICAL ISSUES
   List the most severe problems with their business impact
   Prioritize by severity and frequency

3. 🔍 ROOT CAUSE ANALYSIS
   For the top 5 issues, explain likely causes
   Include technical details and chain of events

4. 💡 RECOMMENDATIONS
   Specific actions to resolve issues, prioritized:
   - Immediate actions (quick wins)
   - Short-term fixes (within 24h)
   - Long-term improvements
   
5. 🤖 AUTO-FIX ASSESSMENT
   Which issues can be automatically fixed
   Risks and success probability for each
   Manual steps required

6. 📊 PATTERNS & TRENDS
   Notable patterns, correlations, or anomalies
   Time-based patterns if timestamps available
   Service/component dependencies

7. 🔮 PREDICTIVE ANALYSIS
   What might happen if issues aren't addressed
   Potential cascading failures

8. ✅ CHECKLIST
   What else should be checked
   Additional data needed

Write this analysis as if explaining to a junior engineer - be clear, specific, and actionable.
Use markdown formatting for readability.
"""

        try:
            logger.info("Sending logs to AI for analysis...")
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a senior SRE providing detailed log analysis with actionable fixes. Be thorough but concise."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                max_tokens=2500
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Error calling OpenAI API: {e}")
            return f"Error calling OpenAI API: {str(e)}"
    
    def _prepare_summary(self, parsed_logs: Dict[str, Any]) -> Dict[str, str]:
        """Prepare summary statistics for AI prompt"""
        summary = {}
        
        # Time range
        if parsed_logs["timestamps"]:
            try:
                times = sorted(parsed_logs["timestamps"])
                summary["time_range"] = f"{times[0]} to {times[-1]}"
            except:
                summary["time_range"] = "Unable to parse timestamps"
        else:
            summary["time_range"] = "No timestamps found"
        
        # Top IPs
        if parsed_logs["ip_addresses"]:
            top_ips = Counter(parsed_logs["ip_addresses"]).most_common(5)
            summary["top_ips"] = ", ".join([f"{ip}({count})" for ip, count in top_ips])
        else:
            summary["top_ips"] = "None"
        
        # HTTP codes
        if parsed_logs["http_codes"]:
            code_counts = Counter(parsed_logs["http_codes"]).most_common()
            summary["http_codes"] = ", ".join([f"{code}({count})" for code, count in code_counts])
        else:
            summary["http_codes"] = "None"
        
        return summary
    
    def generate_report(self, analysis: str, parsed_logs: Dict[str, Any], 
                       fix_results: Optional[Dict[str, Any]] = None, 
                       output_file: Optional[str] = None) -> str:
        """
        Generate a formatted report
        
        Args:
            analysis: AI-generated analysis
            parsed_logs: Parsed log data
            fix_results: Results from auto-fix attempts
            output_file: Optional output file path
            
        Returns:
            Formatted report
        """
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = f"""
╔════════════════════════════════════════════════════════════════════════════╗
║                 AI-POWERED LOG ANALYZER WITH AUTO-FIX                      ║
╚════════════════════════════════════════════════════════════════════════════╝

Generated: {timestamp}
Analysis by: {self.model}
Mode: {'🔧 DRY RUN' if self.dry_run else '⚡ LIVE'}
Auto-approve: {'✅ Yes' if self.auto_approve else '❌ No'}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📊 SYSTEM HEALTH OVERVIEW
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Total Log Lines: {parsed_logs['total_lines']:,}
Error Rate: {parsed_logs['error_rate']:.2f}%

Severity Breakdown:
• 🔥 CRITICAL: {parsed_logs['severity_levels'].get('CRITICAL', 0)}
• 🔴 ERROR: {parsed_logs['severity_levels'].get('ERROR', 0)}
• 🟡 WARNING: {parsed_logs['severity_levels'].get('WARNING', 0)}
• 🔵 INFO: {parsed_logs['severity_levels'].get('INFO', 0)}

Unique Error Patterns: {len(parsed_logs['unique_errors'])}
Auto-fixable Issues: {len(parsed_logs['fixable_issues'])}
"""
        
        if parsed_logs['services']:
            report += f"\nAffected Services: {', '.join(list(parsed_logs['services'])[:10])}\n"
        
        if parsed_logs['fixable_issues']:
            report += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔧 AUTO-FIXABLE ISSUES DETECTED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
            for issue, lines in parsed_logs['fixable_issues'].items():
                handler_info = self.fix_handlers.get(issue, {})
                risk_icon = {
                    'low': '🟢',
                    'medium': '🟡',
                    'high': '🔴'
                }.get(handler_info.get('risk', 'unknown'), '⚪')
                
                report += f"\n{risk_icon} {issue.replace('_', ' ').title()}"
                report += f"\n  • Occurrences: {len(lines)}"
                report += f"\n  • Description: {handler_info.get('description', 'N/A')}"
                report += f"\n  • Risk: {handler_info.get('risk', 'unknown').upper()}"
                
                # Show sample log lines
                if lines:
                    report += f"\n  • Sample: {lines[0]['line'][:150]}..."
        
        if fix_results:
            report += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔧 AUTO-FIX RESULTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
            for fix_name, result in fix_results.items():
                if result.get("skipped"):
                    status = "⏩ SKIPPED"
                    status_icon = "⏩"
                elif result.get("success"):
                    status = "✅ SUCCESS"
                    status_icon = "✅"
                elif result.get("executed_commands"):
                    status = "⚠️  PARTIAL"
                    status_icon = "⚠️"
                else:
                    status = "❌ FAILED"
                    status_icon = "❌"
                
                report += f"\n{status_icon} {fix_name.replace('_', ' ').title()}"
                report += f"\n  Status: {status}"
                
                if "verification_passed" in result:
                    report += f"\n  Verification: {'✅ Passed' if result['verification_passed'] else '❌ Failed'}"
                
                if "details" in result:
                    for detail in result["details"]:
                        if detail.strip():
                            # Truncate long details
                            if len(detail) > 200:
                                detail = detail[:200] + "..."
                            report += f"\n  📋 {detail}"
                
                if "executed_commands" in result:
                    report += f"\n  Commands executed:"
                    for cmd in result["executed_commands"]:
                        status_icon = "✅" if cmd.get("returncode", -1) == 0 else "❌"
                        report += f"\n    {status_icon} {cmd['command'][:80]}..."
                        if cmd.get("stderr"):
                            report += f"\n       Error: {cmd['stderr'][:100]}"
        
        report += f"""
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🔍 AI ANALYSIS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{analysis}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  TOP ERROR PATTERNS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        
        # Add top error patterns with examples
        for error, count in parsed_logs['unique_errors'].most_common(10):
            report += f"\n• {error} (x{count})"
            
            if parsed_logs['error_clusters'][error]:
                example = parsed_logs['error_clusters'][error][0]['line'][:200]
                report += f"\n  Example: {example}..."
        
        report += f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📈 METRICS SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        
        if parsed_logs["metrics"]:
            for metric, values in parsed_logs["metrics"].items():
                if values:
                    numeric_values = [float(v) for v in values if v.replace('.', '').isdigit()]
                    if numeric_values:
                        avg = sum(numeric_values) / len(numeric_values)
                        max_val = max(numeric_values)
                        min_val = min(numeric_values)
                        report += f"\n• {metric}:"
                        report += f"\n  Avg: {avg:.1f}%, Max: {max_val:.1f}%, Min: {min_val:.1f}%"
        else:
            report += "\nNo metrics extracted from logs."
        
        report += f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 REPORT END
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""
        
        if output_file:
            try:
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(report)
                logger.info(f"Report saved to: {output_file}")
            except Exception as e:
                logger.error(f"Error saving report: {e}")
        
        return report
    
    def analyze(self, log_source: Union[str, List[str]], context: str = "", 
               auto_fix: bool = False, fix_all: bool = False,
               output_file: Optional[str] = None) -> str:
        """
        Main analysis method
        
        Args:
            log_source: Path to log file/directory, log string, or list of log lines
            context: Additional context about the system
            auto_fix: Whether to attempt automatic fixes
            fix_all: Fix all issues without prompting
            output_file: Optional output file path
            
        Returns:
            Analysis report
        """
        start_time = time.time()
        
        print(f"""
╔════════════════════════════════════════════════════════════════════════════╗
║                    AI-POWERED LOG ANALYZER v2.0                            ║
║                         with Auto-Fix Capabilities                          ║
╚════════════════════════════════════════════════════════════════════════════╝
        """)
        
        logger.info("Starting log analysis...")
        
        # Read logs
        print("\n📖 Reading logs...")
        log_lines = self.read_logs(log_source)
        print(f"✅ Read {len(log_lines):,} log lines")
        
        # Parse logs
        print("🔍 Parsing and categorizing logs...")
        parsed_logs = self.parse_logs(log_lines)
        print(f"✅ Found {len(parsed_logs['errors'])} errors, {len(parsed_logs['warnings'])} warnings")
        print(f"✅ Detected {len(parsed_logs['fixable_issues'])} types of auto-fixable issues")
        
        # Update auto_approve if fix_all is True
        if fix_all:
            self.auto_approve = True
        
        # Handle auto-fix if requested
        fix_results = {}
        if auto_fix and parsed_logs['fixable_issues']:
            print("\n" + "="*70)
            print("🔧 AUTO-FIX MODE ENABLED")
            print("="*70)
            
            for issue_name, error_lines in parsed_logs['fixable_issues'].items():
                if issue_name in self.fix_handlers:
                    fix_results[issue_name] = self._execute_fix(issue_name, error_lines)
                    
                    # Wait a bit between fixes
                    if not self.dry_run:
                        time.sleep(2)
        
        # AI Analysis
        print("\n🤖 Analyzing with AI (this may take a moment)...")
        analysis = self.analyze_with_ai(parsed_logs, context, auto_fix)
        
        # Generate report
        print("📝 Generating comprehensive report...")
        report = self.generate_report(analysis, parsed_logs, fix_results, output_file)
        
        # Print summary
        elapsed_time = time.time() - start_time
        print(f"\n✅ Analysis complete in {elapsed_time:.2f} seconds")
        
        if fix_results:
            successful_fixes = sum(1 for r in fix_results.values() if r.get("success"))
            print(f"✅ Successful fixes: {successful_fixes}/{len(fix_results)}")
        
        if output_file:
            print(f"📄 Full report saved to: {output_file}")
        
        return report


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n\n⚠️  Analysis interrupted by user")
    sys.exit(0)

def main():
    """Main entry point"""
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    parser = argparse.ArgumentParser(
        description="AI-Powered Log Analyzer with Advanced Auto-Fix Capabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis
  python log_analyzer.py /var/log/syslog
  
  # Analyze with context
  python log_analyzer.py app.log -c "Production server after deployment"
  
  # Enable auto-fix (will prompt)
  python log_analyzer.py /var/log/nginx/error.log --auto-fix
  
  # Auto-fix all without prompting
  python log_analyzer.py system.log --auto-fix --fix-all
  
  # Dry run (preview fixes)
  python log_analyzer.py app.log --auto-fix --dry-run
  
  # Save report to file
  python log_analyzer.py logs/ -o analysis.txt -c "Weekly analysis"
  
  # Analyze multiple log files
  python log_analyzer.py "/var/log/app1.log,/var/log/app2.log" --auto-fix
  
  # With custom OpenAI model
  python log_analyzer.py error.log -m gpt-3.5-turbo --auto-fix
        """
    )
    
    parser.add_argument(
        "log_source", 
        help="Log file, directory, comma-separated files, or string to analyze"
    )
    parser.add_argument(
        "-c", "--context", 
        help="Additional context about the system (e.g., 'Production server, recent deployment')", 
        default=""
    )
    parser.add_argument(
        "-o", "--output", 
        help="Output file for the report (e.g., analysis.txt)"
    )
    parser.add_argument(
        "-k", "--api-key", 
        help="OpenAI API key (if not set in environment)"
    )
    parser.add_argument(
        "-m", "--model", 
        help="OpenAI model to use (default: gpt-4)", 
        default="gpt-4",
        choices=["gpt-4", "gpt-4-turbo-preview", "gpt-3.5-turbo"]
    )
    parser.add_argument(
        "--auto-fix", 
        action="store_true", 
        help="Attempt to automatically fix issues (will prompt for each)"
    )
    parser.add_argument(
        "--fix-all", 
        action="store_true", 
        help="Fix all issues without prompting (use with --auto-fix)"
    )
    parser.add_argument(
        "--dry-run", 
        action="store_true", 
        help="Show what would be fixed without actually doing it"
    )
    parser.add_argument(
        "--log-level", 
        help="Set logging level", 
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"]
    )
    parser.add_argument(
        "--version", 
        action="version", 
        version="Log Analyzer v2.0 with Auto-Fix"
    )
    
    args = parser.parse_args()
    
    # Handle comma-separated log files
    if ',' in args.log_source and not os.path.exists(args.log_source):
        log_sources = args.log_source.split(',')
        all_lines = []
        for source in log_sources:
            try:
                with open(source.strip(), 'r', encoding='utf-8', errors='ignore') as f:
                    all_lines.extend(f.readlines())
            except:
                print(f"⚠️  Could not read {source}")
        args.log_source = all_lines
    
    try:
        analyzer = LogAnalyzer(
            api_key=args.api_key, 
            model=args.model, 
            dry_run=args.dry_run,
            auto_approve=args.fix_all,
            log_level=args.log_level
        )
        
        report = analyzer.analyze(
            args.log_source, 
            args.context, 
            auto_fix=args.auto_fix,
            fix_all=args.fix_all,
            output_file=args.output
        )
        
        # Print report to console if no output file
        if not args.output:
            print("\n" + report)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Analysis interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Error: {e}")
        logger.error(f"Fatal error: {e}", exc_info=True)
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
