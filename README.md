# AfterDark Threat Intelligence Plugin for Amavisd-new

A comprehensive threat intelligence plugin that integrates **amavisd-new** with AfterDark security services:

- **[dnsscience.io](https://dnsscience.io)** - DNS security, threat intelligence, DNSBL
- **[betterphish.io](https://betterphish.io)** - Phishing data feed aggregator with AI validation

## Features

- **IP Reputation Checks** - Standard DNSBL lookups + API-based threat intelligence
- **URL/Domain Analysis** - Check URLs against phishing databases and reputation services
- **File Hash Lookups** - Check attachment hashes against malware databases
- **AI-Powered Detection** - Machine learning phishing detection via BetterPhish
- **Configurable Actions** - REJECT, QUARANTINE, TAG, or SCORE per threat type
- **Caching** - Built-in caching to minimize API calls and latency
- **Header Injection** - Add X-AfterDark-* headers for downstream processing

## Requirements

- Amavisd-new 2.11.0 or later
- Perl 5.14+
- Perl modules:
  - `Net::DNS` (usually pre-installed with amavisd)
  - `HTTP::Tiny` (core module in Perl 5.14+)
  - `JSON::PP` (core module)
  - `Digest::SHA` (core module)
  - `Storable` (core module)

## Installation

### 1. Install the Plugin Module

```bash
# Create directory structure
sudo mkdir -p /usr/local/lib/amavisd/AfterDark/Amavis

# Copy the plugin module
sudo cp AfterDark/Amavis/ThreatIntel.pm /usr/local/lib/amavisd/AfterDark/Amavis/

# Set permissions
sudo chown root:root /usr/local/lib/amavisd/AfterDark/Amavis/ThreatIntel.pm
sudo chmod 644 /usr/local/lib/amavisd/AfterDark/Amavis/ThreatIntel.pm
```

### 2. Install Configuration

```bash
# Create conf.d directory if it doesn't exist
sudo mkdir -p /etc/amavisd/conf.d

# Copy configuration template
sudo cp conf.d/99-afterdark-threatintel.conf /etc/amavisd/conf.d/

# Edit and add your API keys
sudo nano /etc/amavisd/conf.d/99-afterdark-threatintel.conf
```

### 3. Include Configuration in amavisd.conf

Add this line to your `/etc/amavisd/amavisd.conf` (near the end, after other configurations):

```perl
include('/etc/amavisd/conf.d/99-afterdark-threatintel.conf');
```

### 4. Create Cache Directory

```bash
# Ensure cache directory exists and is writable
sudo mkdir -p /var/lib/amavis
sudo chown amavis:amavis /var/lib/amavis
sudo chmod 750 /var/lib/amavis
```

### 5. Get API Keys

#### DNSScience API Key (Recommended)
1. Go to [https://dnsscience.io](https://dnsscience.io)
2. Create an account or sign in
3. Navigate to Dashboard → API Keys
4. Generate a new API key
5. Add to configuration: `$dnsscience_api_key = 'your-key-here';`

#### BetterPhish API Key (Optional)
1. Go to [https://betterphish.io](https://betterphish.io)
2. See the Pricing page for API access tiers
3. Add to configuration: `$betterphish_api_key = 'your-key-here';`

**Note:** Basic lookups work without API keys, but rate limits apply.

### 6. Restart Amavisd

```bash
sudo systemctl restart amavisd

# Or on older systems:
sudo service amavisd restart
```

### 7. Verify Installation

Check the logs for initialization message:

```bash
grep -i "afterdark" /var/log/maillog
# Should see: "AfterDark::Amavis::ThreatIntel v1.0.0 initializing"
```

## Configuration Options

### Master Controls

| Variable | Default | Description |
|----------|---------|-------------|
| `$afterdark_enabled` | 1 | Master switch for the plugin |
| `$dnsscience_enabled` | 1 | Enable DNSScience integration |
| `$betterphish_enabled` | 1 | Enable BetterPhish integration |

### API Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `$dnsscience_api_key` | '' | Your DNSScience API key |
| `$dnsscience_api_url` | 'https://api.dnsscience.io/v1' | API base URL |
| `$dnsscience_dnsbl_zone` | 'dnsbl.dnsscience.io' | DNSBL zone for IP lookups |
| `$betterphish_api_key` | '' | Your BetterPhish API key |
| `$betterphish_api_url` | 'https://api.betterphish.io/v1' | API base URL |

### Check Types

| Variable | Default | Description |
|----------|---------|-------------|
| `$afterdark_check_ips` | 1 | Check sender IPs |
| `$afterdark_check_urls` | 1 | Check URLs in body |
| `$afterdark_check_hashes` | 1 | Check attachment hashes |

### Actions

Available actions: `REJECT`, `QUARANTINE`, `TAG`, `SCORE`, `PASS`

| Variable | Default | Description |
|----------|---------|-------------|
| `$afterdark_action_on_phishing` | 'REJECT' | Action for phishing |
| `$afterdark_action_on_malware` | 'REJECT' | Action for malware |
| `$afterdark_action_on_spam_source` | 'SCORE' | Action for spam sources |

### Spam Scoring

| Variable | Default | Description |
|----------|---------|-------------|
| `$afterdark_spam_score_phishing` | 10.0 | Score for phishing |
| `$afterdark_spam_score_malware` | 15.0 | Score for malware |
| `$afterdark_spam_score_suspicious` | 3.0 | Score for suspicious |

### Performance

| Variable | Default | Description |
|----------|---------|-------------|
| `$afterdark_cache_enabled` | 1 | Enable caching |
| `$afterdark_cache_ttl` | 3600 | Cache TTL (seconds) |
| `$afterdark_cache_file` | '/var/lib/amavis/afterdark_cache.db' | Cache file path |
| `$afterdark_timeout` | 5 | API timeout (seconds) |

### Headers & Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `$afterdark_add_headers` | 1 | Add X-AfterDark-* headers |
| `$afterdark_log_level` | 2 | 0=none, 1=errors, 2=info, 3=debug |

## Headers Added

When threats are detected, the following headers are added:

```
X-AfterDark-ThreatIntel: version=1.0.0; score=10.0; action=REJECT; threats=1
X-AfterDark-Threat-1: type=url; value=http://phish.example.com; threat=phishing; score=10.0; sources=betterphish
X-AfterDark-DNSScience: enabled
X-AfterDark-BetterPhish: enabled
```

## DNSBL Return Codes

When querying `dnsbl.dnsscience.io`, the following return codes indicate threat types:

| Return Code | Threat Type |
|-------------|-------------|
| 127.0.0.1 | Spam source |
| 127.0.0.2 | Malware |
| 127.0.0.3 | Phishing |
| 127.0.0.4 | Botnet |
| 127.0.0.5 | Exploit |
| 127.0.0.6 | Proxy |
| 127.0.0.7 | Suspicious |

## Testing

### Test DNSBL Lookup

```bash
# Test with a known bad IP (use test IP from dnsscience docs)
dig +short 1.0.0.127.dnsbl.dnsscience.io A
dig +short 1.0.0.127.dnsbl.dnsscience.io TXT
```

### Test API Connectivity

```bash
# Test DNSScience API
curl -H "Authorization: Bearer YOUR_API_KEY" \
  "https://api.dnsscience.io/v1/threat-intel/reputation?domain=example.com"

# Test BetterPhish API
curl "https://api.betterphish.io/v1/lookup?url=https://example.com"
```

### Send Test Email

```bash
# Send a test email with a known phishing URL
echo "Test message with URL: http://test.phish.example.com" | \
  mail -s "AfterDark Test" user@yourdomain.com
```

## Troubleshooting

### Plugin Not Loading

Check amavisd can find the module:

```bash
perl -I/usr/local/lib/amavisd -e 'use AfterDark::Amavis::ThreatIntel; print "OK\n"'
```

### API Timeouts

Increase timeout if you have slow connectivity:

```perl
$afterdark_timeout = 10;  # 10 seconds
```

### Cache Issues

Clear the cache if you see stale results:

```bash
sudo rm /var/lib/amavis/afterdark_cache.db
sudo systemctl restart amavisd
```

### High Memory Usage

Reduce cache TTL or disable caching:

```perl
$afterdark_cache_ttl = 1800;  # 30 minutes
# or
$afterdark_cache_enabled = 0;
```

### Debug Mode

Enable debug logging to see detailed operation:

```perl
$afterdark_log_level = 3;
```

Then check logs:

```bash
tail -f /var/log/maillog | grep -i afterdark
```

## Integration with SpamAssassin

The plugin adds spam scores that SpamAssassin will include in its final score calculation. You can create custom SpamAssassin rules that trigger on the headers:

```perl
# /etc/spamassassin/local.cf

# Match AfterDark threat headers
header   AFTERDARK_PHISHING X-AfterDark-ThreatIntel =~ /threat=phishing/i
score    AFTERDARK_PHISHING 5.0
describe AFTERDARK_PHISHING AfterDark detected phishing

header   AFTERDARK_MALWARE X-AfterDark-ThreatIntel =~ /threat=malware/i
score    AFTERDARK_MALWARE 8.0
describe AFTERDARK_MALWARE AfterDark detected malware
```

## Support

- **Documentation:** https://docs.dnsscience.io
- **BetterPhish Docs:** https://betterphish.io/docs
- **GitHub Issues:** https://github.com/afterdarksys/amavisd-threatintel
- **Email:** support@afterdarksys.com

## License

MIT License - Copyright (c) 2025 After Dark Systems

## Changelog

### v1.0.0 (2025-01-18)
- Initial release
- DNSScience DNSBL and API integration
- BetterPhish URL/hash lookup and AI validation
- Configurable actions per threat type
- Built-in caching
- Header injection for downstream processing
