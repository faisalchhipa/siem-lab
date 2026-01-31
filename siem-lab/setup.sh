#!/bin/bash
# SIEM Lab Setup Script
# Automated deployment of SIEM, Honeypot, and Network Traffic Analyzer

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Functions
print_banner() {
    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    SIEM LAB SETUP                          ║"
    echo "║     Security Information & Event Management Laboratory       ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed. Please install Docker first."
        echo "Installation: https://docs.docker.com/get-docker/"
        exit 1
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose is not installed. Please install Docker Compose first."
        echo "Installation: https://docs.docker.com/compose/install/"
        exit 1
    fi
    
    # Check Docker is running
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running. Please start Docker."
        exit 1
    fi
    
    print_status "All prerequisites met!"
}

detect_network_interface() {
    print_status "Detecting network interface..."
    
    # Try to find the default network interface
    DEFAULT_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    if [ -z "$DEFAULT_IFACE" ]; then
        DEFAULT_IFACE="eth0"
        print_warning "Could not detect default interface, using: $DEFAULT_IFACE"
    else
        print_status "Detected network interface: $DEFAULT_IFACE"
    fi
    
    # Update .env file
    sed -i "s/ZEEK_INTERFACE=.*/ZEEK_INTERFACE=$DEFAULT_IFACE/" .env
    sed -i "s/SURICATA_INTERFACE=.*/SURICATA_INTERFACE=$DEFAULT_IFACE/" .env
}

create_directories() {
    print_status "Creating necessary directories..."
    
    mkdir -p logs/{cowrie,zeek,suricata,elasticsearch}
    mkdir -p data/{cowrie,zeek,suricata}
    mkdir -p config/{suricata/rules}
    
    print_status "Directories created!"
}

pull_images() {
    print_status "Pulling Docker images..."
    docker-compose pull
    print_status "Images pulled successfully!"
}

start_services() {
    print_status "Starting SIEM Lab services..."
    
    # Start core services first
    print_status "Starting Elasticsearch (this may take a few minutes)..."
    docker-compose up -d elasticsearch
    
    # Wait for Elasticsearch to be ready
    print_status "Waiting for Elasticsearch to be ready..."
    until curl -s http://localhost:9200/_cluster/health | grep -q '"status":"green\|yellow"'; do
        sleep 5
        echo -n "."
    done
    echo ""
    print_status "Elasticsearch is ready!"
    
    # Start remaining services
    print_status "Starting Logstash, Kibana, and other services..."
    docker-compose up -d logstash kibana filebeat redis
    
    # Wait for Kibana
    print_status "Waiting for Kibana to be ready..."
    until curl -s http://localhost:5601/api/status | grep -q '"state":"green\|yellow"'; do
        sleep 5
        echo -n "."
    done
    echo ""
    print_status "Kibana is ready!"
    
    # Start security services
    print_status "Starting security services (Cowrie, Zeek, Suricata)..."
    docker-compose up -d cowrie zeek suricata
    
    print_status "All services started!"
}

setup_kibana() {
    print_status "Setting up Kibana dashboards..."
    
    # Create index patterns
    curl -X POST "localhost:5601/api/saved_objects/index-pattern/cowrie-*" \
        -H "Content-Type: application/json" \
        -H "kbn-xsrf: true" \
        -d '{
            "attributes": {
                "title": "cowrie-*",
                "timeFieldName": "@timestamp"
            }
        }' 2>/dev/null || print_warning "Could not create cowrie index pattern"
    
    curl -X POST "localhost:5601/api/saved_objects/index-pattern/zeek-*" \
        -H "Content-Type: application/json" \
        -H "kbn-xsrf: true" \
        -d '{
            "attributes": {
                "title": "zeek-*",
                "timeFieldName": "@timestamp"
            }
        }' 2>/dev/null || print_warning "Could not create zeek index pattern"
    
    curl -X POST "localhost:5601/api/saved_objects/index-pattern/suricata-*" \
        -H "Content-Type: application/json" \
        -H "kbn-xsrf: true" \
        -d '{
            "attributes": {
                "title": "suricata-*",
                "timeFieldName": "@timestamp"
            }
        }' 2>/dev/null || print_warning "Could not create suricata index pattern"
    
    print_status "Kibana setup complete!"
}

show_status() {
    echo ""
    print_status "SIEM Lab Status:"
    echo "═══════════════════════════════════════════════════════════════"
    docker-compose ps
    echo ""
    echo -e "${GREEN}Service URLs:${NC}"
    echo "  • Kibana Dashboard: http://localhost:5601"
    echo "  • Elasticsearch API: http://localhost:9200"
    echo "  • Cowrie SSH Honeypot: localhost:2222"
    echo "  • Cowrie Telnet Honeypot: localhost:2223"
    echo ""
    echo -e "${GREEN}Useful Commands:${NC}"
    echo "  • View logs: docker-compose logs -f [service]"
    echo "  • Stop services: docker-compose down"
    echo "  • Restart services: docker-compose restart"
    echo "  • Scale services: docker-compose up -d --scale [service]=[count]"
    echo ""
    echo -e "${GREEN}Testing:${NC}"
    echo "  • Test honeypot: ssh -p 2222 root@localhost"
    echo "  • Test telnet: telnet localhost 2223"
    echo "═══════════════════════════════════════════════════════════════"
}

main() {
    print_banner
    
    check_prerequisites
    detect_network_interface
    create_directories
    pull_images
    start_services
    setup_kibana
    show_status
    
    print_status "SIEM Lab setup complete!"
}

# Handle command line arguments
case "${1:-}" in
    start)
        print_banner
        start_services
        show_status
        ;;
    stop)
        print_status "Stopping SIEM Lab services..."
        docker-compose down
        print_status "Services stopped!"
        ;;
    restart)
        print_status "Restarting SIEM Lab services..."
        docker-compose restart
        show_status
        ;;
    status)
        show_status
        ;;
    logs)
        service="${2:-}"
        if [ -n "$service" ]; then
            docker-compose logs -f "$service"
        else
            docker-compose logs -f
        fi
        ;;
    update)
        print_status "Updating SIEM Lab..."
        docker-compose pull
        docker-compose up -d
        print_status "Update complete!"
        ;;
    *)
        main
        ;;
esac
