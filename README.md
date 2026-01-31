# SIEM Lab - Security Information & Event Management Laboratory

A comprehensive security lab featuring a SIEM stack (ELK), SSH/Telnet honeypot (Cowrie), and network traffic analyzer (Zeek + Suricata) for security monitoring, threat detection, and analysis.

## Features

- **SIEM Stack (ELK)**
  - **Elasticsearch**: Distributed search and analytics engine for log storage
  - **Logstash**: Data processing pipeline for ingesting and transforming logs
  - **Kibana**: Visualization and exploration tool for log data
  - **Filebeat**: Lightweight log shipper for forwarding log data

- **Honeypot (Cowrie)**
  - Medium-interaction SSH/Telnet honeypot
  - Captures brute force attacks and shell interactions
  - Logs attacker commands and downloaded files
  - Customizable fake filesystem and credentials

- **Network Traffic Analyzer**
  - **Zeek**: Powerful network analysis framework
  - **Suricata**: High-performance IDS/IPS and network security monitoring
  - Real-time threat detection and alerting

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        SIEM LAB ARCHITECTURE                     │
└─────────────────────────────────────────────────────────────────┘

  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
  │   Cowrie    │    │    Zeek     │    │  Suricata   │
  │  Honeypot   │    │   Network   │    │    IDS/     │
  │ SSH/Telnet  │    │   Analyzer  │    │    IPS      │
  └──────┬──────┘    └──────┬──────┘    └──────┬──────┘
         │                  │                  │
         └──────────────────┼──────────────────┘
                            │
                    ┌───────▼───────┐
                    │   Filebeat    │
                    │  Log Shipper  │
                    └───────┬───────┘
                            │
                    ┌───────▼───────┐
                    │   Logstash    │
                    │   Processor   │
                    └───────┬───────┘
                            │
                    ┌───────▼───────┐
                    │ Elasticsearch │
                    │    Storage    │
                    └───────┬───────┘
                            │
                    ┌───────▼───────┐
                    │    Kibana     │
                    │ Visualization │
                    └───────────────┘
```

## Quick Start

### Prerequisites

- Docker Engine 20.10+
- Docker Compose 2.0+
- 4GB+ RAM available
- Linux/macOS environment

### Installation

1. **Clone or download the SIEM Lab:**
   ```bash
   cd siem-lab
   ```

2. **Run the setup script:**
   ```bash
   ./setup.sh
   ```

   This will:
   - Check prerequisites
   - Detect network interface
   - Pull Docker images
   - Start all services
   - Configure Kibana dashboards

3. **Access the services:**
   - **Kibana**: http://localhost:5601
   - **Elasticsearch**: http://localhost:9200
   - **Cowrie SSH Honeypot**: `ssh -p 2222 root@localhost`
   - **Cowrie Telnet Honeypot**: `telnet localhost 2223`

## Service Details

### Elasticsearch
- **Port**: 9200 (API), 9300 (cluster)
- **Data**: Stored in Docker volume `elasticsearch-data`
- **Memory**: 2GB heap size (configurable)

### Logstash
- **Ports**: 5044 (Beats), 5045 (Syslog), 9600 (API)
- **Pipelines**: Configured for Cowrie, Zeek, Suricata, and syslog
- **Memory**: 1GB heap size (configurable)

### Kibana
- **Port**: 5601
- **Features**: Pre-configured dashboards for security monitoring

### Cowrie Honeypot
- **SSH Port**: 2222
- **Telnet Port**: 2223
- **Credentials**: Configured with common weak passwords
- **Logs**: JSON format with attacker session details

### Zeek
- **Mode**: Network host mode for packet capture
- **Interface**: Auto-detected (configurable via `.env`)
- **Logs**: Connection, DNS, HTTP, SSL, and more

### Suricata
- **Mode**: Network host mode for packet capture
- **Rules**: Custom rules + Emerging Threats (download required)
- **Logs**: EVE JSON format

## Usage

### Managing Services

```bash
# Start all services
./setup.sh start

# Stop all services
./setup.sh stop

# Restart services
./setup.sh restart

# Check status
./setup.sh status

# View logs
./setup.sh logs [service_name]

# Update images
./setup.sh update
```

### Testing the Honeypot

```bash
# SSH to honeypot
ssh -p 2222 root@localhost
# Password: root, password, 123456, admin, etc.

# Telnet to honeypot
telnet localhost 2223

# View honeypot logs
docker-compose logs -f cowrie
```

### Analyzing Network Traffic

```bash
# View Zeek logs
docker-compose logs -f zeek

# View Suricata alerts
docker-compose logs -f suricata
docker exec -it siem-suricata tail -f /var/log/suricata/fast.log
```

### Creating Kibana Visualizations

1. Open Kibana: http://localhost:5601
2. Navigate to **Stack Management** → **Index Patterns**
3. Create patterns for:
   - `cowrie-*`
   - `zeek-*`
   - `suricata-*`
4. Go to **Analytics** → **Dashboard** to create visualizations

## Configuration

### Environment Variables

Edit `.env` file to customize:

```bash
# Network Interface
ZEEK_INTERFACE=eth0
SURICATA_INTERFACE=eth0

# Memory Settings
ES_JAVA_OPTS=-Xms2g -Xmx2g
LS_JAVA_OPTS=-Xms1g -Xmx1g

# Ports
COWRIE_SSH_PORT=2222
COWRIE_TELNET_PORT=2223
```

### Cowrie Configuration

Edit `cowrie/etc/cowrie.cfg` to customize:
- Hostname displayed to attackers
- SSH/Telnet ports
- Fake filesystem
- User credentials (`cowrie/etc/userdb.txt`)

### Suricata Rules

Add custom rules to `suricata/rules/local.rules`:

```suricata
alert tcp any any -> any 22 (msg:"SSH Brute Force"; flow:to_server; detection_filter:track by_src, count 5, seconds 60; sid:1000001; rev:1;)
```

Download additional rules:
```bash
# Using suricata-update
docker exec -it siem-suricata suricata-update
```

## Security Considerations

⚠️ **WARNING**: This lab is for educational and testing purposes only.

- **Do not expose honeypot ports to the internet** without proper isolation
- Use firewall rules to restrict access to management interfaces
- Change default passwords in production environments
- Monitor resource usage as logs can grow quickly
- Regularly update Docker images and detection rules

## Troubleshooting

### Elasticsearch fails to start
```bash
# Check logs
docker-compose logs elasticsearch

# Increase memory limits in docker-compose.yml
# Or increase Docker Desktop memory allocation
```

### Zeek/Suricata not capturing traffic
```bash
# Verify network interface
ip link show

# Update interface in .env file
# Requires restart: docker-compose restart zeek suricata
```

### Kibana connection refused
```bash
# Wait for Elasticsearch to be ready
curl http://localhost:9200/_cluster/health

# Restart Kibana
docker-compose restart kibana
```

## Log Locations

| Service | Log Location |
|---------|-------------|
| Elasticsearch | Docker logs + volume |
| Logstash | Docker logs |
| Kibana | Docker logs |
| Cowrie | `/var/lib/docker/volumes/siem-lab_cowrie-data/_data/log/cowrie/` |
| Zeek | `/var/lib/docker/volumes/siem-lab_zeek-logs/_data/current/` |
| Suricata | `/var/lib/docker/volumes/siem-lab_suricata-logs/_data/` |

## API Examples

### Query Elasticsearch
```bash
# Check cluster health
curl http://localhost:9200/_cluster/health?pretty

# List indices
curl http://localhost:9200/_cat/indices?v

# Search cowrie logs
curl -X GET "localhost:9200/cowrie-*/_search?pretty" -H 'Content-Type: application/json' -d'
{
  "query": {
    "match": {
      "event_type": "cowrie.login.success"
    }
  }
}'
```

### Export Data
```bash
# Export cowrie logs
docker run --rm --network=host elasticdump \
  --input=http://localhost:9200/cowrie-* \
  --output=cowrie-logs.json
```

## Performance Tuning

### For High Traffic Environments

1. **Increase Elasticsearch resources:**
   ```yaml
   environment:
     - "ES_JAVA_OPTS=-Xms4g -Xmx4g"
   ```

2. **Scale Logstash workers:**
   ```yaml
   environment:
     - PIPELINE_WORKERS=4
   ```

3. **Enable Logstash persistent queues:**
   ```yaml
   path.queue: /usr/share/logstash/data/queue
   queue.type: persisted
   ```

## Contributing

Feel free to submit issues and enhancement requests!

## License

This project is for educational purposes. Component licenses:
- ELK Stack: Elastic License
- Cowrie: BSD-3-Clause
- Zeek: BSD
- Suricata: GPL-2.0

## Resources

- [Elastic Documentation](https://www.elastic.co/guide/index.html)
- [Cowrie Documentation](https://docs.cowrie.org/)
- [Zeek Documentation](https://docs.zeek.org/)
- [Suricata Documentation](https://suricata.readthedocs.io/)
