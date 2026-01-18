package AfterDark::Amavis::ThreatIntel;

#------------------------------------------------------------------------------
# AfterDark Threat Intelligence Plugin for Amavisd-new
#
# Integrates with:
#   - dnsscience.io (DNS security, threat intel, DNSBL)
#   - betterphish.io (Phishing data feed aggregator)
#
# Features:
#   - Standard DNSBL lookups for IP addresses
#   - REST API lookups for URLs, domains, file hashes
#   - Configurable actions per service and threat level
#   - Caching to reduce API calls
#   - Async HTTP requests for performance
#
# Copyright (c) 2025 After Dark Systems
# License: MIT
#------------------------------------------------------------------------------

use strict;
use warnings;
use Amavis::Util qw(do_log ll);
use Amavis::Conf qw(:sa);
use Net::DNS::Resolver;
use HTTP::Tiny;
use JSON::PP qw(encode_json decode_json);
use Digest::SHA qw(sha256_hex sha1_hex);
use Digest::MD5 qw(md5_hex);
use MIME::Base64 qw(encode_base64);
use File::Basename;
use Time::HiRes qw(time);
use Storable qw(store retrieve);

our $VERSION = '1.0.0';

# Export configuration variables for amavisd.conf
use Exporter 'import';
our @EXPORT_OK = qw(
    $afterdark_enabled
    $dnsscience_enabled
    $dnsscience_api_key
    $dnsscience_api_url
    $dnsscience_dnsbl_zone
    $betterphish_enabled
    $betterphish_api_key
    $betterphish_api_url
    $afterdark_check_ips
    $afterdark_check_urls
    $afterdark_check_hashes
    $afterdark_cache_enabled
    $afterdark_cache_ttl
    $afterdark_cache_file
    $afterdark_timeout
    $afterdark_action_on_phishing
    $afterdark_action_on_malware
    $afterdark_action_on_spam_source
    $afterdark_spam_score_phishing
    $afterdark_spam_score_malware
    $afterdark_spam_score_suspicious
    $afterdark_add_headers
    $afterdark_log_level
);

# Configuration defaults (override in amavisd.conf)
our $afterdark_enabled            = 1;
our $dnsscience_enabled           = 1;
our $dnsscience_api_key           = '';
our $dnsscience_api_url           = 'https://api.dnsscience.io/v1';
our $dnsscience_dnsbl_zone        = 'dnsbl.dnsscience.io';
our $betterphish_enabled          = 1;
our $betterphish_api_key          = '';
our $betterphish_api_url          = 'https://api.betterphish.io/v1';
our $afterdark_check_ips          = 1;
our $afterdark_check_urls         = 1;
our $afterdark_check_hashes       = 1;
our $afterdark_cache_enabled      = 1;
our $afterdark_cache_ttl          = 3600;  # 1 hour
our $afterdark_cache_file         = '/var/lib/amavis/afterdark_cache.db';
our $afterdark_timeout            = 5;     # seconds
our $afterdark_action_on_phishing = 'REJECT';  # REJECT, QUARANTINE, TAG, SCORE
our $afterdark_action_on_malware  = 'REJECT';
our $afterdark_action_on_spam_source = 'SCORE';
our $afterdark_spam_score_phishing = 10.0;
our $afterdark_spam_score_malware  = 15.0;
our $afterdark_spam_score_suspicious = 3.0;
our $afterdark_add_headers        = 1;
our $afterdark_log_level          = 2;     # 0=none, 1=errors, 2=info, 3=debug

# Internal state
my %cache;
my $cache_loaded = 0;
my $dns_resolver;
my $http_client;

#------------------------------------------------------------------------------
# Initialization
#------------------------------------------------------------------------------

sub init {
    return unless $afterdark_enabled;

    _log(2, "AfterDark::Amavis::ThreatIntel v$VERSION initializing");

    # Initialize DNS resolver
    $dns_resolver = Net::DNS::Resolver->new(
        tcp_timeout => $afterdark_timeout,
        udp_timeout => $afterdark_timeout,
        retry       => 2,
        retrans     => 1,
    );

    # Initialize HTTP client
    $http_client = HTTP::Tiny->new(
        timeout         => $afterdark_timeout,
        verify_SSL      => 1,
        default_headers => {
            'Content-Type' => 'application/json',
            'User-Agent'   => "AfterDark-Amavis-ThreatIntel/$VERSION",
        },
    );

    # Load cache from disk if enabled
    _load_cache() if $afterdark_cache_enabled;

    _log(2, "AfterDark plugin initialized - DNSScience: " .
        ($dnsscience_enabled ? 'ON' : 'OFF') .
        ", BetterPhish: " . ($betterphish_enabled ? 'ON' : 'OFF'));
}

#------------------------------------------------------------------------------
# Main entry point - called by amavisd for each message
#------------------------------------------------------------------------------

sub check_message {
    my ($msginfo) = @_;

    return unless $afterdark_enabled;

    my $start_time = time();
    my @results;
    my $total_score = 0;

    _log(3, "Processing message: " . ($msginfo->{mail_id} // 'unknown'));

    # Extract data from message
    my $sender_ip = $msginfo->{client_addr};
    my @urls = _extract_urls($msginfo);
    my @attachments = _extract_attachments($msginfo);
    my $raw_email = $msginfo->{mail_text_str} // '';

    # 1. Check sender IP
    if ($afterdark_check_ips && $sender_ip) {
        my $ip_result = check_ip($sender_ip);
        if ($ip_result->{threat_detected}) {
            push @results, $ip_result;
            $total_score += $ip_result->{score};
        }
    }

    # 2. Check URLs in message body
    if ($afterdark_check_urls && @urls) {
        for my $url (@urls) {
            my $url_result = check_url($url);
            if ($url_result->{threat_detected}) {
                push @results, $url_result;
                $total_score += $url_result->{score};
            }
        }
    }

    # 3. Check attachment hashes
    if ($afterdark_check_hashes && @attachments) {
        for my $att (@attachments) {
            my $hash_result = check_hash($att->{sha256}, $att->{filename});
            if ($hash_result->{threat_detected}) {
                push @results, $hash_result;
                $total_score += $hash_result->{score};
            }
        }
    }

    # 4. Submit email to betterphish for analysis (async, don't wait)
    if ($betterphish_enabled && $raw_email) {
        _submit_email_async($raw_email, $msginfo);
    }

    # Determine final action
    my $action = 'PASS';
    my $worst_threat = '';

    for my $r (@results) {
        if ($r->{threat_type} eq 'phishing') {
            $worst_threat = 'phishing';
            $action = $afterdark_action_on_phishing;
        } elsif ($r->{threat_type} eq 'malware' && $worst_threat ne 'phishing') {
            $worst_threat = 'malware';
            $action = $afterdark_action_on_malware;
        } elsif ($r->{threat_type} eq 'spam_source' && !$worst_threat) {
            $worst_threat = 'spam_source';
            $action = $afterdark_action_on_spam_source;
        }
    }

    # Add headers if enabled
    if ($afterdark_add_headers && @results) {
        _add_headers($msginfo, \@results, $total_score, $action);
    }

    my $elapsed = sprintf("%.3f", time() - $start_time);
    _log(2, "Message check complete in ${elapsed}s - " .
        "Action: $action, Score: $total_score, Threats: " . scalar(@results));

    return {
        action       => $action,
        score        => $total_score,
        threats      => \@results,
        elapsed_time => $elapsed,
    };
}

#------------------------------------------------------------------------------
# IP Address Checks (DNSBL + API)
#------------------------------------------------------------------------------

sub check_ip {
    my ($ip) = @_;

    my $result = {
        type           => 'ip',
        value          => $ip,
        threat_detected => 0,
        threat_type    => '',
        score          => 0,
        sources        => [],
    };

    # Check cache first
    my $cache_key = "ip:$ip";
    if (my $cached = _get_cache($cache_key)) {
        _log(3, "IP cache hit: $ip");
        return $cached;
    }

    # 1. DNSBL lookup (fast)
    if ($dnsscience_enabled && $dnsscience_dnsbl_zone) {
        my $dnsbl_result = _dnsbl_lookup($ip, $dnsscience_dnsbl_zone);
        if ($dnsbl_result->{listed}) {
            $result->{threat_detected} = 1;
            $result->{threat_type} = $dnsbl_result->{threat_type} // 'spam_source';
            $result->{score} = $afterdark_spam_score_suspicious;
            push @{$result->{sources}}, {
                service => 'dnsscience-dnsbl',
                result  => $dnsbl_result,
            };
        }
    }

    # 2. API lookup for more details
    if ($dnsscience_enabled && $dnsscience_api_key) {
        my $api_result = _dnsscience_ip_lookup($ip);
        if ($api_result && $api_result->{threat_detected}) {
            $result->{threat_detected} = 1;
            $result->{threat_type} = $api_result->{threat_type};
            $result->{score} = _threat_to_score($api_result->{threat_type});
            push @{$result->{sources}}, {
                service => 'dnsscience-api',
                result  => $api_result,
            };
        }
    }

    # Cache the result
    _set_cache($cache_key, $result);

    return $result;
}

sub _dnsbl_lookup {
    my ($ip, $zone) = @_;

    my $result = {
        listed      => 0,
        threat_type => undef,
        txt_record  => undef,
    };

    # Reverse the IP for DNSBL query
    my $reversed_ip;
    if ($ip =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
        $reversed_ip = "$4.$3.$2.$1";
    } else {
        # IPv6 handling
        $reversed_ip = _reverse_ipv6($ip);
        return $result unless $reversed_ip;
    }

    my $query_name = "$reversed_ip.$zone";
    _log(3, "DNSBL query: $query_name");

    # A record lookup
    my $query = $dns_resolver->search($query_name, 'A');
    if ($query) {
        for my $rr ($query->answer) {
            next unless $rr->type eq 'A';
            $result->{listed} = 1;
            $result->{a_record} = $rr->address;

            # Parse return code to determine threat type
            # Common convention: 127.0.0.x where x indicates threat type
            if ($rr->address =~ /^127\.0\.0\.(\d+)$/) {
                my $code = $1;
                $result->{threat_type} = _decode_dnsbl_code($code);
            }
        }
    }

    # TXT record for description
    if ($result->{listed}) {
        my $txt_query = $dns_resolver->search($query_name, 'TXT');
        if ($txt_query) {
            for my $rr ($txt_query->answer) {
                next unless $rr->type eq 'TXT';
                $result->{txt_record} = join(' ', $rr->txtdata);
            }
        }
    }

    return $result;
}

sub _decode_dnsbl_code {
    my ($code) = @_;

    # DNSScience DNSBL return codes
    my %codes = (
        1  => 'spam_source',
        2  => 'malware',
        3  => 'phishing',
        4  => 'botnet',
        5  => 'exploit',
        6  => 'proxy',
        7  => 'suspicious',
    );

    return $codes{$code} // 'unknown';
}

sub _dnsscience_ip_lookup {
    my ($ip) = @_;

    my $url = "$dnsscience_api_url/threat-intel/ip?ip=$ip";
    my $response = _api_request('GET', $url, undef, {
        'Authorization' => "Bearer $dnsscience_api_key",
    });

    return unless $response && $response->{success};

    my $data = $response->{data};
    return {
        threat_detected => ($data->{risk_level} // 'low') ne 'low',
        threat_type     => $data->{primary_threat} // 'unknown',
        reputation      => $data->{reputation_score},
        blacklists      => $data->{blacklists},
        details         => $data,
    };
}

#------------------------------------------------------------------------------
# URL Checks
#------------------------------------------------------------------------------

sub check_url {
    my ($url) = @_;

    my $result = {
        type            => 'url',
        value           => $url,
        threat_detected => 0,
        threat_type     => '',
        score           => 0,
        sources         => [],
    };

    # Extract domain from URL
    my $domain;
    if ($url =~ m{^https?://([^/:]+)}i) {
        $domain = lc($1);
    }

    # Check cache
    my $cache_key = "url:" . sha256_hex($url);
    if (my $cached = _get_cache($cache_key)) {
        _log(3, "URL cache hit");
        return $cached;
    }

    # 1. BetterPhish URL lookup
    if ($betterphish_enabled) {
        my $phish_result = _betterphish_url_lookup($url);
        if ($phish_result && $phish_result->{is_phishing}) {
            $result->{threat_detected} = 1;
            $result->{threat_type} = 'phishing';
            $result->{score} = $afterdark_spam_score_phishing;
            push @{$result->{sources}}, {
                service => 'betterphish',
                result  => $phish_result,
            };
        }
    }

    # 2. DNSScience domain reputation
    if ($dnsscience_enabled && $dnsscience_api_key && $domain) {
        my $rep_result = _dnsscience_domain_lookup($domain);
        if ($rep_result && $rep_result->{threat_detected}) {
            $result->{threat_detected} = 1;
            $result->{threat_type} ||= $rep_result->{threat_type};
            $result->{score} = _threat_to_score($rep_result->{threat_type});
            push @{$result->{sources}}, {
                service => 'dnsscience',
                result  => $rep_result,
            };
        }
    }

    # 3. BetterPhish AI validation (if not already confirmed phishing)
    if ($betterphish_enabled && $betterphish_api_key && !$result->{threat_detected}) {
        my $ai_result = _betterphish_ai_validate($url);
        if ($ai_result && $ai_result->{is_phishing} && $ai_result->{confidence} > 0.7) {
            $result->{threat_detected} = 1;
            $result->{threat_type} = 'phishing';
            $result->{score} = $afterdark_spam_score_phishing * $ai_result->{confidence};
            push @{$result->{sources}}, {
                service => 'betterphish-ai',
                result  => $ai_result,
            };
        }
    }

    _set_cache($cache_key, $result);
    return $result;
}

sub _betterphish_url_lookup {
    my ($url) = @_;

    my $api_url = "$betterphish_api_url/lookup?url=" . _uri_encode($url);
    my $headers = {};
    $headers->{'X-API-Key'} = $betterphish_api_key if $betterphish_api_key;

    my $response = _api_request('GET', $api_url, undef, $headers);
    return unless $response && $response->{success};

    return $response->{data};
}

sub _betterphish_ai_validate {
    my ($url) = @_;

    my $api_url = "$betterphish_api_url/validate";
    my $headers = {};
    $headers->{'X-API-Key'} = $betterphish_api_key if $betterphish_api_key;

    my $response = _api_request('POST', $api_url, { url => $url }, $headers);
    return unless $response && $response->{success};

    return $response->{data};
}

sub _dnsscience_domain_lookup {
    my ($domain) = @_;

    my $url = "$dnsscience_api_url/threat-intel/reputation?domain=$domain";
    my $response = _api_request('GET', $url, undef, {
        'Authorization' => "Bearer $dnsscience_api_key",
    });

    return unless $response && $response->{success};

    my $data = $response->{data};
    return {
        threat_detected => ($data->{risk_level} // 'low') ne 'low',
        threat_type     => $data->{threat_categories}[0] // 'unknown',
        reputation      => $data->{reputation_score},
        details         => $data,
    };
}

#------------------------------------------------------------------------------
# Hash Checks (File attachments)
#------------------------------------------------------------------------------

sub check_hash {
    my ($hash, $filename) = @_;

    my $result = {
        type            => 'hash',
        value           => $hash,
        filename        => $filename,
        threat_detected => 0,
        threat_type     => '',
        score           => 0,
        sources         => [],
    };

    return $result unless $hash;

    # Check cache
    my $cache_key = "hash:$hash";
    if (my $cached = _get_cache($cache_key)) {
        _log(3, "Hash cache hit");
        return $cached;
    }

    # 1. BetterPhish hash lookup
    if ($betterphish_enabled) {
        my $phish_result = _betterphish_hash_lookup($hash);
        if ($phish_result && $phish_result->{found}) {
            $result->{threat_detected} = 1;
            $result->{threat_type} = 'malware';
            $result->{score} = $afterdark_spam_score_malware;
            push @{$result->{sources}}, {
                service => 'betterphish',
                result  => $phish_result,
            };
        }
    }

    # 2. DNSScience threat intel (malware hash database)
    if ($dnsscience_enabled && $dnsscience_api_key) {
        my $ti_result = _dnsscience_hash_lookup($hash);
        if ($ti_result && $ti_result->{threat_detected}) {
            $result->{threat_detected} = 1;
            $result->{threat_type} = $ti_result->{threat_type} // 'malware';
            $result->{score} = $afterdark_spam_score_malware;
            push @{$result->{sources}}, {
                service => 'dnsscience',
                result  => $ti_result,
            };
        }
    }

    _set_cache($cache_key, $result);
    return $result;
}

sub _betterphish_hash_lookup {
    my ($hash) = @_;

    my $api_url = "$betterphish_api_url/lookup/hash/$hash";
    my $headers = {};
    $headers->{'X-API-Key'} = $betterphish_api_key if $betterphish_api_key;

    my $response = _api_request('GET', $api_url, undef, $headers);
    return unless $response && $response->{success};

    return $response->{data};
}

sub _dnsscience_hash_lookup {
    my ($hash) = @_;

    # DNSScience threat intel API for hash lookup
    my $url = "$dnsscience_api_url/threat-intel/hash?hash=$hash";
    my $response = _api_request('GET', $url, undef, {
        'Authorization' => "Bearer $dnsscience_api_key",
    });

    return unless $response && $response->{success};

    my $data = $response->{data};
    return {
        threat_detected => $data->{found} // 0,
        threat_type     => $data->{threat_type},
        details         => $data,
    };
}

#------------------------------------------------------------------------------
# Email Submission (for community phishing database)
#------------------------------------------------------------------------------

sub _submit_email_async {
    my ($raw_email, $msginfo) = @_;

    return unless $betterphish_enabled;

    # Fork to submit in background (don't delay message processing)
    my $pid = fork();
    return if $pid;  # Parent returns immediately

    if (defined $pid) {
        # Child process
        eval {
            my $api_url = "$betterphish_api_url/submit/email";
            my $headers = {};
            $headers->{'X-API-Key'} = $betterphish_api_key if $betterphish_api_key;

            my $body = {
                email_base64 => encode_base64($raw_email, ''),
                source       => 'amavisd-afterdark',
                recipient    => $msginfo->{recips}[0] // 'unknown',
            };

            _api_request('POST', $api_url, $body, $headers);
        };
        exit(0);
    }
}

#------------------------------------------------------------------------------
# Message Parsing Helpers
#------------------------------------------------------------------------------

sub _extract_urls {
    my ($msginfo) = @_;

    my @urls;
    my $body = $msginfo->{mail_text_str} // '';

    # Extract URLs from message body
    # Supports http, https, and common URL patterns
    while ($body =~ m{(https?://[^\s<>"'\)]+)}gi) {
        my $url = $1;
        # Clean up trailing punctuation
        $url =~ s/[.,;:!?\)]+$//;
        push @urls, $url if length($url) > 10;
    }

    # Remove duplicates
    my %seen;
    @urls = grep { !$seen{$_}++ } @urls;

    _log(3, "Extracted " . scalar(@urls) . " URLs from message");
    return @urls;
}

sub _extract_attachments {
    my ($msginfo) = @_;

    my @attachments;

    # Get attachment info from amavisd
    my $parts = $msginfo->{parts} // [];

    for my $part (@$parts) {
        next unless ref($part) eq 'HASH';
        next unless $part->{name} || $part->{type_short};

        my $content = $part->{body_str} // '';
        next unless $content;

        push @attachments, {
            filename => $part->{name} // 'unnamed',
            type     => $part->{type_short},
            size     => length($content),
            md5      => md5_hex($content),
            sha1     => sha1_hex($content),
            sha256   => sha256_hex($content),
        };
    }

    _log(3, "Extracted " . scalar(@attachments) . " attachments from message");
    return @attachments;
}

#------------------------------------------------------------------------------
# Header Management
#------------------------------------------------------------------------------

sub _add_headers {
    my ($msginfo, $results, $total_score, $action) = @_;

    # Add summary header
    $msginfo->{add_header}{'X-AfterDark-ThreatIntel'} =
        "version=$VERSION; score=$total_score; action=$action; " .
        "threats=" . scalar(@$results);

    # Add individual threat headers
    my $i = 1;
    for my $r (@$results) {
        my $header_val = sprintf(
            "type=%s; value=%s; threat=%s; score=%.1f; sources=%s",
            $r->{type},
            substr($r->{value}, 0, 64),
            $r->{threat_type},
            $r->{score},
            join(',', map { $_->{service} } @{$r->{sources}})
        );
        $msginfo->{add_header}{"X-AfterDark-Threat-$i"} = $header_val;
        $i++;
        last if $i > 10;  # Max 10 threat headers
    }

    # Add service status headers
    $msginfo->{add_header}{'X-AfterDark-DNSScience'} =
        $dnsscience_enabled ? 'enabled' : 'disabled';
    $msginfo->{add_header}{'X-AfterDark-BetterPhish'} =
        $betterphish_enabled ? 'enabled' : 'disabled';
}

#------------------------------------------------------------------------------
# Caching
#------------------------------------------------------------------------------

sub _load_cache {
    return if $cache_loaded;

    if (-f $afterdark_cache_file) {
        eval {
            my $stored = retrieve($afterdark_cache_file);
            %cache = %$stored if $stored;
            _log(3, "Loaded cache with " . scalar(keys %cache) . " entries");
        };
        if ($@) {
            _log(1, "Failed to load cache: $@");
        }
    }

    $cache_loaded = 1;
}

sub _save_cache {
    return unless $afterdark_cache_enabled;

    eval {
        store(\%cache, $afterdark_cache_file);
    };
    if ($@) {
        _log(1, "Failed to save cache: $@");
    }
}

sub _get_cache {
    my ($key) = @_;

    return unless $afterdark_cache_enabled;

    my $entry = $cache{$key};
    return unless $entry;

    # Check TTL
    if (time() - $entry->{timestamp} > $afterdark_cache_ttl) {
        delete $cache{$key};
        return;
    }

    return $entry->{data};
}

sub _set_cache {
    my ($key, $data) = @_;

    return unless $afterdark_cache_enabled;

    $cache{$key} = {
        timestamp => time(),
        data      => $data,
    };

    # Periodic cache save (every 100 entries)
    if (scalar(keys %cache) % 100 == 0) {
        _save_cache();
    }
}

#------------------------------------------------------------------------------
# HTTP/API Helpers
#------------------------------------------------------------------------------

sub _api_request {
    my ($method, $url, $body, $extra_headers) = @_;

    my %options;
    $options{headers} = $extra_headers if $extra_headers;

    if ($body && ref($body)) {
        $options{content} = encode_json($body);
        $options{headers}{'Content-Type'} = 'application/json';
    }

    _log(3, "API $method $url");

    my $response;
    eval {
        if ($method eq 'GET') {
            $response = $http_client->get($url, \%options);
        } elsif ($method eq 'POST') {
            $response = $http_client->post($url, \%options);
        }
    };

    if ($@) {
        _log(1, "API request failed: $@");
        return { success => 0, error => $@ };
    }

    unless ($response->{success}) {
        _log(2, "API request returned " . $response->{status});
        return { success => 0, status => $response->{status} };
    }

    my $data;
    eval {
        $data = decode_json($response->{content});
    };

    if ($@) {
        _log(1, "Failed to parse API response: $@");
        return { success => 0, error => "JSON parse error: $@" };
    }

    return { success => 1, data => $data };
}

sub _uri_encode {
    my ($str) = @_;
    $str =~ s/([^A-Za-z0-9\-_.~])/sprintf("%%%02X", ord($1))/ge;
    return $str;
}

#------------------------------------------------------------------------------
# Utility Functions
#------------------------------------------------------------------------------

sub _threat_to_score {
    my ($threat_type) = @_;

    my %scores = (
        'phishing'    => $afterdark_spam_score_phishing,
        'malware'     => $afterdark_spam_score_malware,
        'spam_source' => $afterdark_spam_score_suspicious,
        'botnet'      => $afterdark_spam_score_malware,
        'exploit'     => $afterdark_spam_score_malware,
        'suspicious'  => $afterdark_spam_score_suspicious,
    );

    return $scores{$threat_type} // $afterdark_spam_score_suspicious;
}

sub _reverse_ipv6 {
    my ($ip) = @_;

    # Expand IPv6 and reverse for DNSBL lookup
    # This is a simplified implementation
    return unless $ip =~ /:/;

    # Expand :: notation
    my @parts = split(/:/, $ip);
    # ... full implementation would expand and reverse

    return;  # For now, skip IPv6 DNSBL
}

sub _log {
    my ($level, $msg) = @_;
    return if $level > $afterdark_log_level;

    my $prefix = ['', 'ERROR', 'INFO', 'DEBUG']->[$level] // '';
    do_log($level, "AfterDark [$prefix]: $msg");
}

#------------------------------------------------------------------------------
# Cleanup on exit
#------------------------------------------------------------------------------

END {
    _save_cache() if $afterdark_cache_enabled && $cache_loaded;
}

1;

__END__

=head1 NAME

AfterDark::Amavis::ThreatIntel - Threat intelligence plugin for amavisd-new

=head1 SYNOPSIS

In amavisd.conf:

    use AfterDark::Amavis::ThreatIntel qw(:DEFAULT);

    $afterdark_enabled = 1;
    $dnsscience_api_key = 'your-api-key';
    $betterphish_api_key = 'your-api-key';

=head1 DESCRIPTION

This plugin integrates amavisd-new with AfterDark threat intelligence services:

=over 4

=item * B<dnsscience.io> - DNS security, threat intel, DNSBL

=item * B<betterphish.io> - Phishing data feed aggregator

=back

=head1 FEATURES

=over 4

=item * Standard DNSBL lookups for sender IPs

=item * REST API lookups for URLs and domains

=item * File hash checking against malware databases

=item * AI-powered phishing detection

=item * Configurable actions per threat type

=item * Caching to reduce API calls

=back

=head1 AUTHOR

After Dark Systems E<lt>support@afterdarksys.comE<gt>

=head1 LICENSE

MIT License

=cut
