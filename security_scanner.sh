#!/bin/bash

# Security Scanner Module for Necromancer Toolkit
# Advanced security assessment and vulnerability detection

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Security scanner functions
check_open_ports() {
    echo -e "${YELLOW}Scanning for open ports...${NC}"
    netstat -tuln | grep LISTEN | while read line; do
        port=$(echo $line | awk '{print $4}' | cut -d: -f2)
        echo -e "${BLUE}Open port detected: ${port}${NC}"
    done
}

check_file_permissions() {
    echo -e "${YELLOW}Checking critical file permissions...${NC}"
    
    critical_files=(
        "/etc/passwd"
        "/etc/shadow"
        "/etc/sudoers"
        "~/.ssh/authorized_keys"
    )
    
    for file in "${critical_files[@]}"; do
        if [ -f "$file" ]; then
            perms=$(ls -l "$file" | awk '{print $1}')
            echo -e "${BLUE}$file: $perms${NC}"
        fi
    done
}

check_running_processes() {
    echo -e "${YELLOW}Analyzing running processes...${NC}"
    ps aux | grep -E "(ssh|http|ftp|telnet)" | grep -v grep | while read line; do
        process=$(echo $line | awk '{print $11}')
        echo -e "${BLUE}Network service running: $process${NC}"
    done
}

check_system_updates() {
    echo -e "${YELLOW}Checking for system updates...${NC}"
    if command -v brew &> /dev/null; then
        outdated=$(brew outdated | wc -l)
        echo -e "${BLUE}Outdated packages: $outdated${NC}"
    fi
}

vulnerability_scan() {
    echo -e "${GREEN}=== NECROMANCER SECURITY SCAN ===${NC}"
    echo -e "${GREEN}Starting comprehensive security assessment...${NC}"
    echo ""
    
    check_open_ports
    echo ""
    check_file_permissions
    echo ""
    check_running_processes
    echo ""
    check_system_updates
    echo ""
    
    echo -e "${GREEN}Security scan completed!${NC}"
    echo -e "${YELLOW}Review the findings above and take appropriate action.${NC}"
}

# Main execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    vulnerability_scan
fi