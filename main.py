#!/usr/bin/env python3
"""
===============================================================================
L-DNS: Lightweight DNS Tunneling & Anomaly Detection System (Pure Python Edition)
Author      : Cybersecurity Student Project
Version     : 2.0.0
Description : Advanced Command-Line Tool for Detecting DNS Exfiltration & Tunneling
              using Multi-Vector Analysis (Entropy, Encodings, Structural Anomalies).
===============================================================================
"""

import argparse
import datetime
import json
import math
import os
import re
import socket
import struct
import sys
import time

# ==============================================================================
# CONSTANTS & CONFIGURATION DEFAULTS
# ==============================================================================
PROJECT_NAME = "L-DNS Detector"
VERSION = "2.0.0"
DEFAULT_CONFIG_PATH = "config.json"

DEFAULT_CONFIG = {
    "entropy_threshold": 4.15,
    "max_subdomain_length": 35,
    "max_fqdn_length": 70,
    "consonant_ratio_threshold": 0.75,
    "high_risk_record_types": [16, 10, 5, 15, 28],  # TXT, NULL, CNAME, MX, AAAA
    "rate_limit_window_sec": 60,
    "rate_limit_max_queries": 50,
    "whitelist_domains": ["google.com", "microsoft.com", "github.com", "cloudflare.com"]
}

DNS_RECORD_NAMES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    10: "NULL",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY"
}


# Terminal ANSI Color Formatters
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


# ==============================================================================
# 1. LOGGER & ERROR HANDLING SUBSYSTEM
# ==============================================================================
class SafeLogger:
    def __init__(self, log_level="INFO"):
        self.levels = {"DEBUG": 10, "INFO": 20, "WARNING": 30, "ERROR": 40}
        self.current_level = self.levels.get(log_level.upper(), 20)

    def set_level(self, level_str):
        self.current_level = self.levels.get(level_str.upper(), 20)

    def _timestamp(self):
        return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def debug(self, msg):
        if self.current_level <= 10:
            print(f"[{self._timestamp()}] {Colors.OKBLUE}[DEBUG]{Colors.ENDC} {msg}")

    def info(self, msg):
        if self.current_level <= 20:
            print(f"[{self._timestamp()}] {Colors.OKGREEN}[INFO]{Colors.ENDC} {msg}")

    def warning(self, msg):
        if self.current_level <= 30:
            print(f"[{self._timestamp()}] {Colors.WARNING}[WARN]{Colors.ENDC} {msg}")

    def error(self, msg):
        if self.current_level <= 40:
            print(f"[{self._timestamp()}] {Colors.FAIL}[ERROR]{Colors.ENDC} {msg}")


# Global logger instance
logger = SafeLogger()


# ==============================================================================
# 2. PURE PYTHON DNS PACKET PARSER
# ==============================================================================
class PureDNSHeader:
    """Parses 12-byte DNS Header Structure using binary struct unpacking"""

    def __init__(self, data):
        self.transaction_id = 0
        self.flags = 0
        self.qdcount = 0
        self.ancount = 0
        self.nscount = 0
        self.arcount = 0
        self.is_valid = False
        self._parse(data)

    def _parse(self, data):
        if len(data) < 12:
            return
        try:
            fields = struct.unpack("!HHHHHH", data[:12])
            self.transaction_id = fields[0]
            self.flags = fields[1]
            self.qdcount = fields[2]
            self.ancount = fields[3]
            self.nscount = fields[4]
            self.arcount = fields[5]
            self.is_valid = True
        except Exception:
            self.is_valid = False


class PureDNSPacketParser:
    """Extracts Query Names, Subdomains, Record Types, and Payload Metadata"""

    def __init__(self, raw_bytes):
        self.raw_bytes = raw_bytes
        self.header = PureDNSHeader(raw_bytes)
        self.domain_name = ""
        self.subdomain = ""
        self.record_type = 0
        self.record_type_str = "UNKNOWN"
        self.is_parsed = False
        if self.header.is_valid and self.header.qdcount > 0:
            self._parse_question()

    def _parse_question(self):
        try:
            idx = 12  # Skip 12-byte header
            labels = []
            while idx < len(self.raw_bytes):
                length = self.raw_bytes[idx]
                if length == 0:
                    idx += 1
                    break
                if (length & 0xC0) == 0xC0:  # Compression pointer
                    idx += 2
                    break
                idx += 1
                if idx + length > len(self.raw_bytes):
                    return
                label = self.raw_bytes[idx:idx + length].decode('utf-8', errors='ignore')
                labels.append(label)
                idx += length

            if labels:
                self.domain_name = ".".join(labels).lower()
                if len(labels) > 2:
                    self.subdomain = ".".join(labels[:-2]).lower()
                else:
                    self.subdomain = ""

            if idx + 2 <= len(self.raw_bytes):
                self.record_type = struct.unpack("!H", self.raw_bytes[idx:idx + 2])[0]
                self.record_type_str = DNS_RECORD_NAMES.get(self.record_type, f"TYPE_{self.record_type}")

            self.is_parsed = True
        except Exception as e:
            logger.debug(f"Parsing packet failed: {e}")
            self.is_parsed = False


# ==============================================================================
# 3. MATHEMATICAL & HEURISTIC ANALYSIS ENGINE
# ==============================================================================
class FeatureExtractor:
    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Calculates Shannon Entropy (Unpredictability/Randomness score)"""
        if not text:
            return 0.0
        length = len(text)
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def calculate_consonant_ratio(text: str) -> float:
        """Calculates ratio of consonants to total alphabetic characters"""
        letters = [c.lower() for c in text if c.isalpha()]
        if not letters:
            return 0.0
        vowels = set("aeiou")
        consonants = [c for c in letters if c not in vowels]
        return round(len(consonants) / len(letters), 4)

    @staticmethod
    def detect_encoding_patterns(text: str) -> dict:
        """Checks for Base64, Hexadecimal, or Base32 encoding signatures"""
        is_hex = bool(re.match(r'^[0-9a-fA-F]{10,}$', text))
        is_base64 = bool(re.match(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$', text)) and len(
            text) > 16
        return {
            "hex_detected": is_hex,
            "base64_detected": is_base64
        }


class RateTracker:
    """Tracks query frequency from IP addresses to detect volumetric tunneling"""

    def __init__(self, window_sec=60):
        self.window_sec = window_sec
        self.tracker = {}

    def add_query(self, client_ip):
        now = time.time()
        if client_ip not in self.tracker:
            self.tracker[client_ip] = []
        self.tracker[client_ip].append(now)
        # Purge expired timestamps
        self.tracker[client_ip] = [t for t in self.tracker[client_ip] if now - t <= self.window_sec]
        return len(self.tracker[client_ip])


# ==============================================================================
# 4. TUNNELING DETECTION & SCORING ENGINE
# ==============================================================================
class LDNSTunnelDetector:
    def __init__(self, config_path=DEFAULT_CONFIG_PATH):
        self.config = DEFAULT_CONFIG.copy()
        self.rate_tracker = RateTracker(self.config["rate_limit_window_sec"])
        self.load_config(config_path)

    def load_config(self, config_path):
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    user_cfg = json.load(f)
                    self.config.update(user_cfg)
                logger.info(f"Successfully loaded configuration from '{config_path}'")
            except json.JSONDecodeError:
                logger.error(f"Configuration file '{config_path}' is corrupt. Falling back to defaults.")
            except Exception as e:
                logger.error(f"Failed reading config file: {e}. Using default settings.")
        else:
            logger.warning(f"Config file '{config_path}' not found. Using default settings.")

    def save_config(self, config_path):
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=4)
            logger.info(f"Saved default configuration to '{config_path}'")
        except Exception as e:
            logger.error(f"Could not save configuration: {e}")

    def is_whitelisted(self, domain):
        for w_dom in self.config["whitelist_domains"]:
            if domain.endswith(w_dom):
                return True
        return False

    def inspect_query(self, domain_name, record_type=1, client_ip="127.0.0.1"):
        if not domain_name:
            return None

        # Clean domain
        domain_clean = domain_name.strip().rstrip('.')

        # Check Whitelist
        if self.is_whitelisted(domain_clean):
            return {
                "domain": domain_clean,
                "status": "CLEAN",
                "threat_score": 0.0,
                "reasons": ["Whitelisted Domain"]
            }

        labels = domain_clean.split('.')
        subdomain = ".".join(labels[:-2]) if len(labels) > 2 else domain_clean

        # Extract Features
        entropy = FeatureExtractor.calculate_shannon_entropy(subdomain if subdomain else domain_clean)
        consonant_ratio = FeatureExtractor.calculate_consonant_ratio(subdomain)
        encodings = FeatureExtractor.detect_encoding_patterns(labels[0] if labels else "")
        query_rate = self.rate_tracker.add_query(client_ip)

        # Apply Rules & Calculate Risk Score
        threat_score = 0.0
        reasons = []

        if entropy > self.config["entropy_threshold"]:
            threat_score += 35.0
            reasons.append(f"High Entropy ({entropy} > {self.config['entropy_threshold']})")

        if len(subdomain) > self.config["max_subdomain_length"]:
            threat_score += 30.0
            reasons.append(f"Excessive Subdomain Length ({len(subdomain)} chars)")

        if len(domain_clean) > self.config["max_fqdn_length"]:
            threat_score += 20.0
            reasons.append(f"Excessive FQDN Length ({len(domain_clean)} chars)")

        if record_type in self.config["high_risk_record_types"]:
            threat_score += 15.0
            type_name = DNS_RECORD_NAMES.get(record_type, str(record_type))
            reasons.append(f"High Risk Record Type ({type_name})")

        if encodings["hex_detected"] or encodings["base64_detected"]:
            threat_score += 25.0
            enc_str = "Hex" if encodings["hex_detected"] else "Base64"
            reasons.append(f"Encoded Payload Detected ({enc_str})")

        if consonant_ratio > self.config["consonant_ratio_threshold"] and len(subdomain) > 10:
            threat_score += 20.0
            reasons.append(f"Unnatural Consonant Ratio ({consonant_ratio})")

        if query_rate > self.config["rate_limit_max_queries"]:
            threat_score += 25.0
            reasons.append(f"High Query Volume ({query_rate} reqs/min)")

        # Cap score at 100%
        threat_score = min(threat_score, 100.0)
        status = "MALICIOUS (TUNNEL)" if threat_score >= 50.0 else "BENIGN"

        return {
            "timestamp": datetime.datetime.now().isoformat(),
            "client_ip": client_ip,
            "domain": domain_clean,
            "subdomain": subdomain,
            "record_type": DNS_RECORD_NAMES.get(record_type, str(record_type)),
            "entropy": entropy,
            "length": len(domain_clean),
            "threat_score": threat_score,
            "status": status,
            "reasons": reasons
        }


# ==============================================================================
# 5. CLI INTERFACE & ORCHESTRATOR
# ==============================================================================
class LDNSCLI:
    def __init__(self):
        self.detector = None

    def display_banner(self):
        banner = f"""
{Colors.HEADER}========================================================================{Colors.ENDC}
{Colors.BOLD}   L-DNS: Lightweight DNS Tunneling Detection System - Pure Python {Colors.ENDC}
{Colors.HEADER}========================================================================{Colors.ENDC}
 Version     : {VERSION}
 Architecture: Pure Python Engine (Zero External Dependencies)
 Operating OS: Windows & Linux Compliant
"""
        print(banner)

    def print_result_card(self, result):
        if not result:
            return

        is_mal = result["threat_score"] >= 50.0
        status_color = Colors.FAIL if is_mal else Colors.OKGREEN

        print(f"\n{Colors.BOLD}--- [ Query Inspection Report ] ---{Colors.ENDC}")
        print(f" Target Domain  : {result['domain']}")
        print(f" Client IP      : {result.get('client_ip', 'N/A')}")
        print(f" Record Type    : {result.get('record_type', 'A')}")
        print(f" Result Status  : {status_color}{result['status']}{Colors.ENDC}")
        print(f" Threat Score   : {status_color}{result['threat_score']:.2f}%{Colors.ENDC}")
        print(f" Entropy Score  : {result.get('entropy', 0.0)}")
        print(f" Query Length   : {result.get('length', 0)} chars")
        if result.get("reasons"):
            print(" Triggered Rules:")
            for r in result["reasons"]:
                print(f"   {Colors.WARNING}•{Colors.ENDC} {r}")
        print("-" * 42)

    def run(self):
        parser = argparse.ArgumentParser(
            prog="dns_detector.py",
            description="L-DNS Tunneling Detection CLI Tool",
            formatter_class=argparse.RawDescriptionHelpFormatter
        )

        parser.add_argument("-v", "--version", action="version", version=f"{PROJECT_NAME} {VERSION}")
        parser.add_argument("-c", "--config", type=str, default=DEFAULT_CONFIG_PATH,
                            help="Path to config JSON file (default: config.json)")
        parser.add_argument("-l", "--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"], default="INFO",
                            help="Set logging verbosity (default: INFO)")

        subparsers = parser.add_subparsers(dest="command", help="Available sub-commands")

        # Subcommand: analyze
        analyze_p = subparsers.add_parser("analyze", help="Analyze domain names or log files")
        analyze_p.add_argument("-d", "--domain", type=str, help="Single domain name to inspect")
        analyze_p.add_argument("-f", "--file", type=str, help="Path to text/log file containing domain list")
        analyze_p.add_argument("-o", "--output", type=str, help="Save report to JSON file")

        # Subcommand: live
        live_p = subparsers.add_parser("live", help="Listen live on UDP interface for DNS traffic")
        live_p.add_argument("-i", "--ip", type=str, default="0.0.0.0",
                            help="IP address to bind server (default: 0.0.0.0)")
        live_p.add_argument("-p", "--port", type=int, default=53, help="UDP Port to listen on (default: 53)")

        # Subcommand: config
        config_p = subparsers.add_parser("config", help="Manage configuration settings")
        config_p.add_argument("--generate", action="store_true", help="Generate default config.json file")

        args = parser.parse_args()

        logger.set_level(args.log_level)
        self.detector = LDNSTunnelDetector(args.config)

        if args.command == "config":
            if args.generate:
                self.detector.save_config(args.config)
            else:
                print(json.dumps(self.detector.config, indent=4))
            return

        self.display_banner()

        if args.command == "analyze":
            self.handle_analyze(args)
        elif args.command == "live":
            self.handle_live(args)
        else:
            parser.print_help()

    def handle_analyze(self, args):
        results = []
        if args.domain:
            res = self.detector.inspect_query(args.domain)
            self.print_result_card(res)
            results.append(res)
        elif args.file:
            if not os.path.exists(args.file):
                logger.error(f"File not found: '{args.file}'")
                sys.exit(1)

            logger.info(f"Reading targets from file: '{args.file}'...")
            try:
                with open(args.file, "r", encoding="utf-8") as f:
                    lines = [line.strip() for line in f if line.strip() and not line.startswith('#')]

                for line in lines:
                    res = self.detector.inspect_query(line)
                    self.print_result_card(res)
                    results.append(res)
            except Exception as e:
                logger.error(f"Failed reading input file: {e}")

        if args.output and results:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    json.dump(results, f, indent=4)
                logger.info(f"Successfully exported {len(results)} results to '{args.output}'")
            except Exception as e:
                logger.error(f"Failed saving output file: {e}")

    def handle_live(self, args):
        logger.info(f"Starting DNS UDP listener on {args.ip}:{args.port}...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((args.ip, args.port))
        except PermissionError:
            logger.error("Permission Denied: Administrator/Root privileges required to bind to port 53.")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Failed binding socket: {e}")
            sys.exit(1)

        print(f"{Colors.OKGREEN}[+] Listener running. Press Ctrl+C to stop.{Colors.ENDC}\n")
        try:
            while True:
                data, addr = sock.recvfrom(4096)
                parser = PureDNSPacketParser(data)
                if parser.is_parsed and parser.domain_name:
                    res = self.detector.inspect_query(
                        domain_name=parser.domain_name,
                        record_type=parser.record_type,
                        client_ip=addr[0]
                    )
                    self.print_result_card(res)
        except KeyboardInterrupt:
            print(f"\n{Colors.WARNING}[!] Stopping listener.{Colors.ENDC}")
            sock.close()


if __name__ == "__main__":
    cli = LDNSCLI()
    cli.run()