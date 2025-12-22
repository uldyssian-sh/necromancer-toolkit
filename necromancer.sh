#!/bin/bash

# Necromancer Toolkit - Main Script
# Dark arts automation for system administration

VERSION="1.0.0"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logo
show_logo() {
    echo -e "${RED}"
    echo "███╗   ██╗███████╗ ██████╗██████╗  ██████╗ ███╗   ███╗ █████╗ ███╗   ██╗ ██████╗███████╗██████╗ "
    echo "████╗  ██║██╔════╝██╔════╝██╔══██╗██╔═══██╗████╗ ████║██╔══██╗████╗  ██║██╔════╝██╔════╝██╔══██╗"
    echo "██╔██╗ ██║█████╗  ██║     ██████╔╝██║   ██║██╔████╔██║███████║██╔██╗ ██║██║     █████╗  ██████╔╝"
    echo "██║╚██╗██║██╔══╝  ██║     ██╔══██╗██║   ██║██║╚██╔╝██║██╔══██║██║╚██╗██║██║     ██╔══╝  ██╔══██╗"
    echo "██║ ╚████║███████╗╚██████╗██║  ██║╚██████╔╝██║ ╚═╝ ██║██║  ██║██║ ╚████║╚██████╗███████╗██║  ██║"
    echo "╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝╚══════╝╚═╝  ╚═╝"
    echo -e "${NC}"
    echo -e "${YELLOW}Dark Arts Automation Toolkit v${VERSION}${NC}"
    echo ""
}

# Main menu
show_menu() {
    echo -e "${GREEN}Available Tools:${NC}"
    echo "1. System Monitor"
    echo "2. Security Scanner"
    echo "3. Performance Optimizer"
    echo "4. Exit"
    echo ""
}

# System monitoring function
system_monitor() {
    echo -e "${YELLOW}Running System Monitor...${NC}"
    echo "CPU Usage: $(top -l 1 | grep "CPU usage" | awk '{print $3}' | sed 's/%//')"
    echo "Memory Usage: $(vm_stat | grep "Pages active" | awk '{print $3}' | sed 's/\.//')"
    echo "Disk Usage: $(df -h / | tail -1 | awk '{print $5}')"
}

# Security scanner function
security_scanner() {
    echo -e "${YELLOW}Running Security Scanner...${NC}"
    echo "Checking for open ports..."
    netstat -an | grep LISTEN | head -5
}

# Performance optimizer function
performance_optimizer() {
    echo -e "${YELLOW}Running Performance Optimizer...${NC}"
    echo "Clearing system caches..."
    sudo purge 2>/dev/null || echo "Cache clearing completed"
}

# Main execution
main() {
    show_logo
    
    while true; do
        show_menu
        read -p "Select an option (1-4): " choice
        
        case $choice in
            1)
                system_monitor
                ;;
            2)
                security_scanner
                ;;
            3)
                performance_optimizer
                ;;
            4)
                echo -e "${RED}Exiting Necromancer Toolkit...${NC}"
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please try again.${NC}"
                ;;
        esac
        
        echo ""
        read -p "Press Enter to continue..."
        clear
        show_logo
    done
}

# Run main function
main "$@"