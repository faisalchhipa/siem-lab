# Zeek Local Configuration
# SIEM Lab Network Traffic Analysis

# Load common Zeek scripts
@load protocols/ssh/detect-bruteforcing
@load protocols/http/detect-sqli
@load protocols/ftp/detect-bruteforcing
@load protocols/smtp/detect-suspicious-orig
@load protocols/conn/known-hosts
@load protocols/conn/known-services
@load protocols/ssl/known-certs
@load protocols/ssl/validate-sct
@load protocols/ssl/extract-certs-pem
@load tuning/json-logs
@load misc/scan
@load misc/detect-traceroute
@load frameworks/software/vulnerable
@load frameworks/software/version-changes
@load frameworks/communication/listen-clear
@load frameworks/communication/listen-ssl

# Enable JSON logging
redef LogAscii::use_json = T;

# Configure log rotation
redef Log::default_rotation_interval = 1hr;
redef Log::default_rotation_postprocessor_cmd = "";

# SSH brute force detection
redef SSH::password_guesses_limit = 5;
redef SSH::guessing_timeout = 5 min;

# Scan detection
redef Scan::scan_threshold = 15;
redef Scan::scan_interval = 5 min;

# Notice suppression
redef Notice::suppression_interval = 1 min;

# Custom SIEM detection rules
event connection_state_remove(c: connection)
    {
    # Log suspicious connection patterns
    if ( c$orig$size > 1000000 || c$resp$size > 1000000 )
        {
        NOTICE([$note=LargeTransfer,
                $msg=fmt("Large data transfer detected: %s -> %s (%d bytes)", 
                        c$id$orig_h, c$id$resp_h, c$orig$size + c$resp$size),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$id$resp_h)]);
        }
    }

# Detect suspicious DNS queries
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
    {
    # Flag DNS queries to suspicious domains
    if ( suspicious_domain in query )
        {
        NOTICE([$note=DNS::SuspiciousQuery,
                $msg=fmt("Suspicious DNS query: %s from %s", query, c$id$orig_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, query)]);
        }
    }

# Detect HTTP anomalies
event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    # Detect suspicious user agents
    if ( name == "USER-AGENT" )
        {
        if ( /curl|wget|python|nikto|sqlmap|nmap|masscan/ in value )
            {
            add c$http_tags[Scanner];
            }
        }
    }

# Detect SSL/TLS anomalies
event ssl_established(c: connection)
    {
    # Log weak SSL/TLS versions
    if ( c$ssl$version == /SSLv2|SSLv3/ )
        {
        NOTICE([$note=SSL::WeakCipher,
                $msg=fmt("Weak SSL/TLS version detected: %s from %s", 
                        c$ssl$version, c$id$orig_h),
                $conn=c,
                $identifier=cat(c$id$orig_h, c$ssl$version)]);
        }
    }

# Helper functions
function is_suspicious_domain(domain: string): bool
    {
    local suspicious_patterns = /\.tk$|\.ml$|\.cf$|\.ga$|\.top$|\.xyz$|\.bid$|\.download$|\.work$/;
    return suspicious_patterns in domain;
    }

# Custom notice types
module Notice;

type Notice::Type += {
    LargeTransfer,
    SuspiciousDNSQuery,
    ScannerDetected,
    WeakSSLVersion,
};
