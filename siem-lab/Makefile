# SIEM Lab Makefile
# Simplified commands for managing the SIEM Lab

.PHONY: help install start stop restart status logs clean update test

# Default target
.DEFAULT_GOAL := help

help: ## Show this help message
	@echo "SIEM Lab - Available Commands:"
	@echo "═══════════════════════════════════════════════════════════════"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo "═══════════════════════════════════════════════════════════════"

install: ## Install and setup the SIEM Lab
	@echo "🔧 Installing SIEM Lab..."
	@./setup.sh

start: ## Start all SIEM Lab services
	@echo "🚀 Starting SIEM Lab services..."
	@docker-compose up -d

stop: ## Stop all SIEM Lab services
	@echo "🛑 Stopping SIEM Lab services..."
	@docker-compose down

restart: ## Restart all SIEM Lab services
	@echo "🔄 Restarting SIEM Lab services..."
	@docker-compose restart

status: ## Show status of all services
	@echo "📊 SIEM Lab Status:"
	@docker-compose ps

logs: ## View logs from all services (use 'make logs SERVICE=name' for specific service)
	@if [ -z "$(SERVICE)" ]; then \
		docker-compose logs -f; \
	else \
		docker-compose logs -f $(SERVICE); \
	fi

clean: ## Stop services and remove all data (WARNING: Data will be lost!)
	@echo "⚠️  WARNING: This will remove all data!"
	@read -p "Are you sure? [y/N] " confirm && [ $$confirm = y ] && \
		docker-compose down -v && \
		docker system prune -f && \
		echo "✅ Cleanup complete!" || \
		echo "❌ Cancelled"

update: ## Update all Docker images
	@echo "⬆️  Updating Docker images..."
	@docker-compose pull
	@docker-compose up -d

pull: ## Pull latest Docker images
	@echo "📥 Pulling Docker images..."
	@docker-compose pull

build: ## Build custom images (if any)
	@echo "🔨 Building images..."
	@docker-compose build

test: ## Run basic tests to verify SIEM Lab functionality
	@echo "🧪 Testing SIEM Lab..."
	@echo "Testing Elasticsearch..."
	@curl -s http://localhost:9200/_cluster/health | grep -q '"status":"green\|yellow"' && echo "✅ Elasticsearch is healthy" || echo "❌ Elasticsearch is not ready"
	@echo "Testing Kibana..."
	@curl -s http://localhost:5601/api/status | grep -q '"state":"green\|yellow"' && echo "✅ Kibana is ready" || echo "❌ Kibana is not ready"
	@echo "Testing Cowrie honeypot..."
	@nc -z localhost 2222 && echo "✅ Cowrie SSH is listening" || echo "❌ Cowrie SSH is not listening"
	@echo "Testing Cowrie Telnet..."
	@nc -z localhost 2223 && echo "✅ Cowrie Telnet is listening" || echo "❌ Cowrie Telnet is not listening"

test-honeypot: ## Test honeypot by attempting SSH connection
	@echo "🔑 Testing Cowrie honeypot with SSH connection..."
	@echo "Attempting connection to localhost:2222..."
	@ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p 2222 root@localhost "exit" 2>/dev/null && echo "✅ SSH connection successful" || echo "❌ SSH connection failed"

shell-%: ## Open shell in specific service (e.g., make shell-cowrie)
	@docker-compose exec $* /bin/sh

exec-%: ## Execute command in specific service (e.g., make exec-cowrie CMD="ls -la")
	@docker-compose exec $* $(CMD)

backup: ## Backup Elasticsearch data
	@echo "💾 Backing up Elasticsearch data..."
	@mkdir -p backups
	@docker run --rm --network=host elasticdump \
		--input=http://localhost:9200/cowrie-* \
		--output=backups/cowrie-$$(date +%Y%m%d).json
	@docker run --rm --network=host elasticdump \
		--input=http://localhost:9200/zeek-* \
		--output=backups/zeek-$$(date +%Y%m%d).json
	@docker run --rm --network=host elasticdump \
		--input=http://localhost:9200/suricata-* \
		--output=backups/suricata-$$(date +%Y%m%d).json
	@echo "✅ Backup complete!"

export-dashboards: ## Export Kibana dashboards
	@echo "📤 Exporting Kibana dashboards..."
	@mkdir -p exports
	@curl -X GET "localhost:5601/api/saved_objects/_export" \
		-H "kbn-xsrf: true" \
		-H "Content-Type: application/json" \
		-d '{"type": "dashboard", "includeReferencesDeep": true}' \
		> exports/dashboards-$$(date +%Y%m%d).ndjson
	@echo "✅ Dashboards exported!"

import-dashboards: ## Import Kibana dashboards
	@echo "📥 Importing Kibana dashboards..."
	@curl -X POST "localhost:5601/api/saved_objects/_import?overwrite=true" \
		-H "kbn-xsrf: true" \
		--form file=@kibana/dashboards/siem-dashboards.ndjson
	@echo "✅ Dashboards imported!"

network-info: ## Display network configuration
	@echo "🌐 Network Configuration:"
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "Default interface:"
	@ip route | grep default | awk '{print "  Interface: " $$5}'
	@echo ""
	@echo "IP Addresses:"
	@ip addr show | grep "inet " | awk '{print "  " $$2}'
	@echo ""
	@echo "Listening ports:"
	@netstat -tlnp 2>/dev/null | grep -E ':(5601|9200|2222|2223|5044|6379)' || \
		ss -tlnp | grep -E ':(5601|9200|2222|2223|5044|6379)'
	@echo "═══════════════════════════════════════════════════════════════"

disk-usage: ## Show disk usage of SIEM Lab
	@echo "💾 Disk Usage:"
	@docker system df
	@echo ""
	@echo "Volume sizes:"
	@docker volume ls -q | xargs -I {} sh -c 'echo "  {}: $$(docker volume inspect {} --format "{{.Mountpoint}}" | xargs du -sh 2>/dev/null || echo "N/A")"'

health: ## Check health of all services
	@echo "🏥 Health Check:"
	@echo "═══════════════════════════════════════════════════════════════"
	@echo "Elasticsearch:"
	@curl -s http://localhost:9200/_cluster/health?pretty 2>/dev/null | grep -E '"status"|"active_shards_percent"' || echo "  ❌ Not responding"
	@echo ""
	@echo "Kibana:"
	@curl -s http://localhost:5601/api/status 2>/dev/null | grep -o '"state":"[^"]*"' || echo "  ❌ Not responding"
	@echo ""
	@echo "Docker containers:"
	@docker-compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
	@echo "═══════════════════════════════════════════════════════════════"

# Development commands
dev-build: ## Build development version
	@docker-compose -f docker-compose.yml -f docker-compose.dev.yml build

dev-up: ## Start development environment
	@docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

dev-down: ## Stop development environment
	@docker-compose -f docker-compose.yml -f docker-compose.dev.yml down

# Monitoring commands
monitor: ## Start monitoring stack (if configured)
	@echo "📊 Starting monitoring..."
	@echo "Access Grafana at http://localhost:3000 (if configured)"

top: ## Show resource usage of containers
	@docker stats --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"
