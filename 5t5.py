#!/usr/bin/env python3
"""
HackingProtectGuardDefender
Defensive host/network security monitor.

Supported:
    - Linux
    - Windows
    - TCP monitoring
    - UDP endpoint monitoring
    - Rate-based suspicious activity detection
    - Automatic firewall blocking
    - SHA-256 file scanning
    - Whitelist
    - JSON logging
    - Local HTTP API

IMPORTANT:
    Run as Administrator on Windows or root on Linux for auto-blocking.
    The API binds to 127.0.0.1 only.
"""

import csv
import hashlib
import http.server
import ipaddress
import json
import logging
import os
import platform
import shutil
import socket
import subprocess
import sys
import threading
import time

from collections import defaultdict, deque
from pathlib import Path
from urllib.parse import urlparse


# ============================================================
# CONFIGURATION
# ============================================================

class Config:
    LISTEN_API_HOST = "127.0.0.1"
    LISTEN_API_PORT = 8765

    CHECK_INTERVAL = 5

    MAX_ACTIVITY = 100
    ACTIVITY_WINDOW = 60

    BLOCK_DURATION = 3600

    LOG_FILE = "hackingprotectguarddefender.log"

    # IP yang tidak boleh diblokir.
    WHITELIST = {
        "127.0.0.1",
        "::1",
    }

    # File extension yang tidak perlu dipindai.
    SKIP_EXTENSIONS = {
        ".jpg",
        ".jpeg",
        ".png",
        ".gif",
        ".mp3",
        ".mp4",
        ".avi",
        ".mkv",
        ".zip",
        ".7z",
        ".iso",
    }


# ============================================================
# LOGGER
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    handlers=[
        logging.FileHandler(
            Config.LOG_FILE,
            encoding="utf-8",
        ),
        logging.StreamHandler(sys.stdout),
    ],
)

logger = logging.getLogger(
    "HackingProtectGuardDefender"
)


# ============================================================
# MAIN CLASS
# ============================================================

class HackingProtectGuardDefender:

    def __init__(self):

        self.name = "HackingProtectGuardDefender"
        self.version = "1.0.0"

        self.running = False

        self.lock = threading.RLock()

        self.whitelist = {
            self.normalize_ip(ip)
            for ip in Config.WHITELIST
        }

        self.blocked_ips = {}

        self.activity = defaultdict(deque)

        self.alerts = deque(maxlen=1000)

        self.connection_snapshot = []

        self.scan_results = []

        self.api_server = None

        self.monitor_thread = None

        self.cleanup_thread = None

    # ========================================================
    # IP METHODS
    # ========================================================

    def normalize_ip(self, ip):

        ip = str(ip).strip()

        if ip.lower().startswith("::ffff:"):
            ip = ip[7:]

        try:
            return str(
                ipaddress.ip_address(ip)
            )
        except ValueError:
            return ip

    def is_valid_ip(self, ip):

        try:
            ipaddress.ip_address(
                self.normalize_ip(ip)
            )
            return True
        except ValueError:
            return False

    def is_whitelisted(self, ip):

        return (
            self.normalize_ip(ip)
            in self.whitelist
        )

    def add_whitelist(self, ip):

        ip = self.normalize_ip(ip)

        if not self.is_valid_ip(ip):
            raise ValueError(
                "Invalid IP address"
            )

        with self.lock:
            self.whitelist.add(ip)

        self.log_alert(
            "Whitelist added: " + ip
        )

    def remove_whitelist(self, ip):

        ip = self.normalize_ip(ip)

        if ip in self.whitelist:
            self.whitelist.remove(ip)

            self.log_alert(
                "Whitelist removed: " + ip
            )

    # ========================================================
    # LOGGING
    # ========================================================

    def log_alert(self, message):

        event = {
            "timestamp": time.time(),
            "message": str(message),
        }

        with self.lock:
            self.alerts.append(event)

        logger.warning(message)

    # ========================================================
    # ACTIVITY TRACKING
    # ========================================================

    def register_activity(self, ip):

        ip = self.normalize_ip(ip)

        if self.is_whitelisted(ip):
            return False

        now = time.monotonic()

        with self.lock:

            history = self.activity[ip]

            while (
                history
                and now - history[0]
                > Config.ACTIVITY_WINDOW
            ):
                history.popleft()

            history.append(now)

            return (
                len(history)
                >= Config.MAX_ACTIVITY
            )

    # ========================================================
    # LINUX NETWORK MONITOR
    # ========================================================

    def parse_proc_socket_file(
        self,
        filename,
        protocol,
    ):

        results = []

        try:
            text = Path(
                filename
            ).read_text(
                encoding="utf-8",
                errors="ignore",
            )
        except (
            FileNotFoundError,
            PermissionError,
            OSError,
        ):
            return results

        lines = text.splitlines()

        for line in lines[1:]:

            fields = line.split()

            if len(fields) < 3:
                continue

            remote = fields[2]

            try:
                remote_hex, port_hex = (
                    remote.split(":")
                )

                port = int(
                    port_hex,
                    16,
                )

            except ValueError:
                continue

            if port == 0:
                continue

            try:

                if len(remote_hex) == 8:

                    raw = bytes.fromhex(
                        remote_hex
                    )

                    ip = str(
                        ipaddress.IPv4Address(
                            raw[::-1]
                        )
                    )

                elif len(remote_hex) == 32:

                    raw = bytes.fromhex(
                        remote_hex
                    )

                    ip = str(
                        ipaddress.IPv6Address(
                            raw
                        )
                    )

                else:
                    continue

            except ValueError:
                continue

            results.append(
                {
                    "ip": ip,
                    "port": port,
                    "protocol": protocol,
                }
            )

        return results

    def get_linux_connections(self):

        connections = []

        files = [
            ("/proc/net/tcp", "TCP"),
            ("/proc/net/tcp6", "TCP"),
            ("/proc/net/udp", "UDP"),
            ("/proc/net/udp6", "UDP"),
        ]

        for filename, protocol in files:

            connections.extend(
                self.parse_proc_socket_file(
                    filename,
                    protocol,
                )
            )

        return connections

    # ========================================================
    # WINDOWS NETWORK MONITOR
    # ========================================================

    def powershell(self, command):

        try:

            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    command,
                ],
                capture_output=True,
                text=True,
                timeout=20,
            )

            if result.returncode != 0:
                return ""

            return result.stdout

        except (
            OSError,
            subprocess.SubprocessError,
        ):
            return ""

    def get_windows_connections(self):

        connections = []

        command = (
            "Get-NetTCPConnection "
            "-ErrorAction SilentlyContinue | "
            "Select-Object RemoteAddress,RemotePort,State | "
            "ConvertTo-Csv -NoTypeInformation"
        )

        output = self.powershell(
            command
        )

        for line in output.splitlines()[1:]:

            try:
                row = next(
                    csv.reader([line])
                )
            except (
                StopIteration,
                csv.Error,
            ):
                continue

            if len(row) < 3:
                continue

            ip = self.normalize_ip(
                row[0]
            )

            try:
                port = int(row[1])
            except ValueError:
                continue

            if ip in (
                "",
                "*",
                "0.0.0.0",
                "::",
            ):
                continue

            connections.append(
                {
                    "ip": ip,
                    "port": port,
                    "protocol": "TCP",
                }
            )

        return connections

    # ========================================================
    # CROSS-PLATFORM NETWORK MONITOR
    # ========================================================

    def get_connections(self):

        system = platform.system().lower()

        if system == "linux":
            return self.get_linux_connections()

        if system == "windows":
            return self.get_windows_connections()

        return []

    def monitor_connections(self):

        connections = (
            self.get_connections()
        )

        with self.lock:
            self.connection_snapshot = (
                connections
            )

        # Count each source IP once per cycle.
        seen = set()

        for connection in connections:

            ip = self.normalize_ip(
                connection["ip"]
            )

            if ip in seen:
                continue

            seen.add(ip)

            exceeded = (
                self.register_activity(ip)
            )

            if exceeded:

                self.log_alert(
                    "Suspicious activity: "
                    f"{ip}"
                )

                self.block_ip(ip)

    # ========================================================
    # FIREWALL
    # ========================================================

    def block_ip(self, ip):

        ip = self.normalize_ip(ip)

        if not self.is_valid_ip(ip):
            return False

        if self.is_whitelisted(ip):

            logger.warning(
                "Refusing to block "
                "whitelisted IP: %s",
                ip,
            )

            return False

        with self.lock:

            if ip in self.blocked_ips:

                if (
                    self.blocked_ips[ip]
                    > time.time()
                ):
                    return True

        system = platform.system().lower()

        if system == "windows":
            success = self.block_windows(ip)

        elif system == "linux":
            success = self.block_linux(ip)

        else:
            return False

        if success:

            with self.lock:
                self.blocked_ips[ip] = (
                    time.time()
                    + Config.BLOCK_DURATION
                )

            self.log_alert(
                f"IP blocked: {ip}"
            )

        return success

    def block_windows(self, ip):

        rule_name = (
            "HackingProtectGuardDefender "
            + ip
        )

        command = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
            "protocol=any",
        ]

        try:

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=20,
            )

            return (
                result.returncode == 0
            )

        except (
            OSError,
            subprocess.SubprocessError,
        ):
            return False

    def block_linux(self, ip):

        try:
            address = ipaddress.ip_address(
                ip
            )
        except ValueError:
            return False

        # nftables
        if shutil.which("nft"):

            family = (
                "ip"
                if address.version == 4
                else "ip6"
            )

            subprocess.run(
                [
                    "nft",
                    "add",
                    "table",
                    "inet",
                    "hpgd",
                ],
                capture_output=True,
            )

            subprocess.run(
                [
                    "nft",
                    "add",
                    "chain",
                    "inet",
                    "hpgd",
                    "input",
                    "{",
                    "type",
                    "filter",
                    "hook",
                    "input",
                    "priority",
                    "0",
                    ";",
                    "policy",
                    "accept",
                    ";",
                    "}",
                ],
                capture_output=True,
            )

            result = subprocess.run(
                [
                    "nft",
                    "add",
                    "rule",
                    "inet",
                    "hpgd",
                    "input",
                    family,
                    "saddr",
                    ip,
                    "drop",
                ],
                capture_output=True,
                text=True,
            )

            return (
                result.returncode == 0
                or "File exists"
                in result.stderr
            )

        # iptables fallback
        binary = (
            "iptables"
            if address.version == 4
            else "ip6tables"
        )

        if not shutil.which(binary):
            return False

        check = subprocess.run(
            [
                binary,
                "-C",
                "INPUT",
                "-s",
                ip,
                "-j",
                "DROP",
            ],
            capture_output=True,
        )

        if check.returncode == 0:
            return True

        result = subprocess.run(
            [
                binary,
                "-I",
                "INPUT",
                "-s",
                ip,
                "-j",
                "DROP",
            ],
            capture_output=True,
        )

        return (
            result.returncode == 0
        )

    # ========================================================
    # FILE HASH SCANNER
    # ========================================================

    def sha256_file(self, filename):

        digest = hashlib.sha256()

        try:

            with open(
                filename,
                "rb",
            ) as file:

                while True:

                    chunk = file.read(
                        1024 * 1024
                    )

                    if not chunk:
                        break

                    digest.update(
                        chunk
                    )

            return digest.hexdigest()

        except (
            OSError,
            PermissionError,
        ):

            return None

    def scan_file(self, filename):

        path = Path(filename)

        if not path.is_file():
            return {
                "file": str(path),
                "error": "Not a file",
            }

        file_hash = self.sha256_file(
            path
        )

        result = {
            "file": str(path),
            "sha256": file_hash,
            "suspicious": False,
        }

        with self.lock:
            self.scan_results.append(
                result
            )

            if len(self.scan_results) > 500:
                self.scan_results.pop(0)

        return result

    def scan_directory(self, directory):

        root = Path(directory)

        if not root.exists():

            return {
                "error": "Directory not found"
            }

        results = []

        try:

            files = root.rglob("*")

            for path in files:

                if not path.is_file():
                    continue

                if (
                    path.suffix.lower()
                    in Config.SKIP_EXTENSIONS
                ):
                    continue

                result = (
                    self.scan_file(path)
                )

                results.append(
                    result
                )

                # Safety limit for API-triggered scans.
                if len(results) >= 1000:
                    break

        except (
            OSError,
            PermissionError,
        ) as error:

            return {
                "error": str(error),
                "results": results,
            }

        return {
            "directory": str(root),
            "count": len(results),
            "results": results,
        }

    # ========================================================
    # STATUS
    # ========================================================

    def get_status(self):

        with self.lock:

            return {
                "name": self.name,
                "version": self.version,
                "platform": platform.platform(),
                "running": self.running,
                "whitelist": sorted(
                    self.whitelist
                ),
                "blocked_ips": sorted(
                    self.blocked_ips.keys()
                ),
                "connection_count": len(
                    self.connection_snapshot
                ),
                "alert_count": len(
                    self.alerts
                ),
                "configuration": {
                    "max_activity":
                        Config.MAX_ACTIVITY,
                    "activity_window":
                        Config.ACTIVITY_WINDOW,
                    "block_duration":
                        Config.BLOCK_DURATION,
                    "check_interval":
                        Config.CHECK_INTERVAL,
                },
            }

    def get_alerts(self):

        with self.lock:
            return list(self.alerts)

    def get_connections_snapshot(self):

        with self.lock:
            return list(
                self.connection_snapshot
            )

    # ========================================================
    # CLEANUP
    # ========================================================

    def cleanup(self):

        now = time.time()

        with self.lock:

            expired = [
                ip
                for ip, expiry
                in self.blocked_ips.items()
                if expiry <= now
            ]

            for ip in expired:

                del self.blocked_ips[ip]

                logger.info(
                    "Internal block expired: %s",
                    ip,
                )

    # ========================================================
    # MONITOR LOOP
    # ========================================================

    def monitor_loop(self):

        while self.running:

            try:

                self.monitor_connections()

            except Exception as error:

                logger.exception(
                    "Monitor error: %s",
                    error,
                )

            time.sleep(
                Config.CHECK_INTERVAL
            )

    def cleanup_loop(self):

        while self.running:

            try:
                self.cleanup()

            except Exception as error:

                logger.exception(
                    "Cleanup error: %s",
                    error,
                )

            time.sleep(30)

    # ========================================================
    # API
    # ========================================================

    def start_api(self):

        guard = self

        class APIHandler(
            http.server.BaseHTTPRequestHandler
        ):

            def send_json(
                self,
                data,
                status=200,
            ):

                payload = json.dumps(
                    data,
                    indent=2,
                    ensure_ascii=False,
                ).encode("utf-8")

                self.send_response(status)

                self.send_header(
                    "Content-Type",
                    "application/json",
                )

                self.send_header(
                    "Content-Length",
                    str(len(payload)),
                )

                self.end_headers()

                self.wfile.write(
                    payload
                )

            def do_GET(self):

                parsed = urlparse(
                    self.path
                )

                if parsed.path == "/":
                    self.send_json(
                        {
                            "service":
                                guard.name,
                            "version":
                                guard.version,
                            "endpoints": [
                                "/status",
                                "/alerts",
                                "/connections",
                            ],
                        }
                    )
                    return

                if parsed.path == "/status":

                    self.send_json(
                        guard.get_status()
                    )
                    return

                if parsed.path == "/alerts":

                    self.send_json(
                        guard.get_alerts()
                    )
                    return

                if parsed.path == "/connections":

                    self.send_json(
                        guard.get_connections_snapshot()
                    )
                    return

                self.send_json(
                    {"error": "Not found"},
                    404,
                )

            def do_POST(self):

                parsed = urlparse(
                    self.path
                )

                length = int(
                    self.headers.get(
                        "Content-Length",
                        "0",
                    )
                )

                body = self.rfile.read(
                    length
                )

                try:
                    data = json.loads(
                        body.decode("utf-8")
                    )
                except Exception:
                    data = {}

                # Add whitelist
                if parsed.path == "/whitelist/add":

                    try:
                        guard.add_whitelist(
                            data["ip"]
                        )

                        self.send_json(
                            {"success": True}
                        )

                    except Exception as error:

                        self.send_json(
                            {
                                "success":
                                    False,
                                "error":
                                    str(error),
                            },
                            400,
                        )

                    return

                # Remove whitelist
                if (
                    parsed.path
                    == "/whitelist/remove"
                ):

                    guard.remove_whitelist(
                        data.get("ip", "")
                    )

                    self.send_json(
                        {"success": True}
                    )

                    return

                # Manual defensive block
                if parsed.path == "/block":

                    ip = data.get(
                        "ip",
                        "",
                    )

                    success = (
                        guard.block_ip(ip)
                    )

                    self.send_json(
                        {
                            "success":
                                success,
                            "ip":
                                ip,
                        }
                    )

                    return

                # SHA-256 scan
                if parsed.path == "/scan/file":

                    filename = data.get(
                        "path",
                        "",
                    )

                    if not filename:

                        self.send_json(
                            {
                                "error":
                                    "path required"
                            },
                            400,
                        )

                        return

                    result = (
                        guard.scan_file(
                            filename
                        )
                    )

                    self.send_json(
                        result
                    )

                    return

                if (
                    parsed.path
                    == "/scan/directory"
                ):

                    directory = data.get(
                        "path",
                        "",
                    )

                    if not directory:

                        self.send_json(
                            {
                                "error":
                                    "path required"
                            },
                            400,
                        )

                        return

                    result = (
                        guard.scan_directory(
                            directory
                        )
                    )

                    self.send_json(
                        result
                    )

                    return

                self.send_json(
                    {"error": "Not found"},
                    404,
                )

            def log_message(
                self,
                format_string,
                *args,
            ):

                logger.info(
                    "API %s",
                    format_string % args,
                )

        try:

            self.api_server = (
                http.server.ThreadingHTTPServer(
                    (
                        Config.LISTEN_API_HOST,
                        Config.LISTEN_API_PORT,
                    ),
                    APIHandler,
                )
            )

            logger.info(
                "Local API listening on "
                "http://%s:%s",
                Config.LISTEN_API_HOST,
                Config.LISTEN_API_PORT,
            )

            self.api_server.serve_forever()

        except OSError as error:

            logger.error(
                "API error: %s",
                error,
            )

    # ========================================================
    # START / STOP
    # ========================================================

    def start(self):

        if self.running:
            return

        self.running = True

        logger.info(
            "%s v%s starting",
            self.name,
            self.version,
        )

        self.monitor_thread = (
            threading.Thread(
                target=self.monitor_loop,
                daemon=True,
                name="NetworkMonitor",
            )
        )

        self.cleanup_thread = (
            threading.Thread(
                target=self.cleanup_loop,
                daemon=True,
                name="Cleanup",
            )
        )

        self.monitor_thread.start()

        self.cleanup_thread.start()

        self.start_api()

    def stop(self):

        if not self.running:
            return

        logger.info(
            "Stopping %s",
            self.name,
        )

        self.running = False

        if self.api_server:

            try:
                self.api_server.shutdown()
            except Exception:
                pass

            try:
                self.api_server.server_close()
            except Exception:
                pass

        if self.monitor_thread:

            self.monitor_thread.join(
                timeout=3
            )

        if self.cleanup_thread:

            self.cleanup_thread.join(
                timeout=3
            )

        logger.info(
            "Stopped."
        )

    def run(self):

        try:
            self.start()

        except KeyboardInterrupt:

            self.stop()


# ============================================================
# MAIN
# ============================================================

def main():

    guard = (
        HackingProtectGuardDefender()
    )

    try:

        guard.run()

    except KeyboardInterrupt:

        guard.stop()

    except Exception as error:

        logger.exception(
            "Fatal error: %s",
            error,
        )

        guard.stop()

        return 1

    return 0


if __name__ == "__main__":
    sys.exit(
        main()
    )