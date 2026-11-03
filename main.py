#!/usr/bin/env python3
from __future__ import annotations

import argparse
import collections
import dataclasses
import datetime
import hashlib
import socket
import tempfile
import ipaddress
import json
import math
import os
import re
import shutil
import signal
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Deque, Iterable, Iterator, Optional

APP_NAME = "garden-warden"
APP_VERSION = "1.0.0"
IP = ipaddress.IPv4Address | ipaddress.IPv6Address
NETWORK = ipaddress.IPv4Network | ipaddress.IPv6Network


@dataclasses.dataclass(slots=True)
class Config:
    interval: float = 5.0
    history_size: int = 24
    min_samples: int = 6
    zscore_warn: float = 2.5
    zscore_crit: float = 4.0
    count_warn: int = 50
    count_crit: int = 200
    ratio_warn: float = 3.0
    ratio_crit: float = 6.0
    absolute_delta: int = 10
    expire_seconds: float = 3600.0
    cooldown_seconds: float = 60.0
    top_n: int = 25
    max_sources: int = 100000
    family: str = "any"
    source: str = "auto"
    conntrack_path: Optional[str] = None
    conntrack_command: str = "conntrack"
    max_bytes: int = 256 * 1024 * 1024
    max_lines: int = 2000000
    max_line_size: int = 32768
    include_loopback: bool = False
    include_private: bool = False
    local_networks: tuple[NETWORK, ...] = ()
    trusted_networks: tuple[NETWORK, ...] = ()
    json_output: bool = False
    compact_json: bool = False
    quiet: bool = False
    once: bool = False
    enforce: bool = False
    backend: str = "none"
    ipset_path: str = "ipset"
    ipset_set_v4: str = "garden_warden_v4"
    ipset_set_v6: str = "garden_warden_v6"
    ipset_timeout: int = 3600
    create_sets: bool = False
    max_enforcements: int = 20
    state_path: Optional[str] = None
    save_state: bool = False
    show_all_detections: bool = False
    max_command_seconds: float = 10.0
    theme: str = "cosmos"
    color: str = "auto"
    forensic_output: Optional[str] = None
    compare_snapshot: Optional[str] = None
    profile_limit: int = 100
    scan_port_warn: int = 12
    scan_port_crit: int = 40
    scan_destination_warn: int = 16
    scan_destination_crit: int = 64
    syn_ratio_warn: float = 0.60
    syn_ratio_crit: float = 0.85
    syn_min_connections: int = 20
    entropy_warn: float = 3.5
    analysis_enabled: bool = True
    snapshot_history: int = 64
    max_command_output: int = 128 * 1024 * 1024
    max_snapshot_bytes: int = 32 * 1024 * 1024


@dataclasses.dataclass(slots=True)
class ConntrackEntry:
    family: str
    protocol: str
    state: str
    original_src: IP
    original_dst: IP
    reply_src: Optional[IP]
    reply_dst: Optional[IP]
    original_sport: Optional[int]
    original_dport: Optional[int]
    timeout: Optional[int]
    raw: str
    mark: Optional[int] = None
    zone: Optional[int] = None
    status: tuple[str, ...] = ()


@dataclasses.dataclass(slots=True)
class SourceSnapshot:
    ip: str
    family: str
    connections: int = 0
    protocols: collections.Counter[str] = dataclasses.field(default_factory=collections.Counter)
    states: collections.Counter[str] = dataclasses.field(default_factory=collections.Counter)
    destinations: set[str] = dataclasses.field(default_factory=set)
    ports: set[int] = dataclasses.field(default_factory=set)
    destination_counts: collections.Counter[str] = dataclasses.field(default_factory=collections.Counter)
    port_counts: collections.Counter[int] = dataclasses.field(default_factory=collections.Counter)
    source_ports: set[int] = dataclasses.field(default_factory=set)
    timeouts: list[int] = dataclasses.field(default_factory=list)
    flows: collections.Counter[str] = dataclasses.field(default_factory=collections.Counter)

    def add(self, entry: ConntrackEntry) -> None:
        self.connections += 1
        self.protocols[entry.protocol] += 1
        self.states[entry.state] += 1
        self.destinations.add(str(entry.original_dst))
        self.destination_counts[str(entry.original_dst)] += 1
        if entry.original_sport is not None:
            self.source_ports.add(entry.original_sport)
        if entry.timeout is not None and len(self.timeouts) < 1024:
            self.timeouts.append(entry.timeout)
        self.flows[f"{entry.protocol}:{entry.state}"] += 1
        if entry.original_dport is not None:
            self.ports.add(entry.original_dport)
            self.port_counts[entry.original_dport] += 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "family": self.family,
            "connections": self.connections,
            "protocols": dict(self.protocols),
            "states": dict(self.states),
            "unique_destinations": len(self.destinations),
            "unique_destination_ports": len(self.ports),
            "unique_source_ports": len(self.source_ports),
            "top_destination_ports": ranked_counter(self.port_counts, 10),
            "top_destinations": ranked_counter(self.destination_counts, 10),
            "median_timeout": statistics.median(self.timeouts) if self.timeouts else None,
        }


@dataclasses.dataclass(slots=True)
class Detection:
    ip: str
    family: str
    severity: str
    count: int
    baseline_mean: float
    baseline_stdev: float
    zscore: float
    ratio: float
    delta: float
    samples: int
    reason: str
    first_seen: float
    last_seen: float
    destination_count: int
    destination_port_count: int

    def as_dict(self) -> dict[str, Any]:
        result = dataclasses.asdict(self)
        if not math.isfinite(result["zscore"]):
            result["zscore"] = None
        return result


@dataclasses.dataclass(slots=True)
class Enforcement:
    ip: str
    backend: str
    action: str
    ok: bool
    detail: str
    timestamp: float

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(slots=True)
class SourceState:
    history: Deque[int]
    first_seen: float
    last_seen: float
    last_alert: float = 0.0
    last_enforced: float = 0.0
    detections: int = 0


@dataclasses.dataclass(slots=True)
class ParseStats:
    total_lines: int = 0
    parsed_entries: int = 0
    malformed_lines: int = 0
    excluded_entries: int = 0
    ambiguous_entries: int = 0
    error_samples: list[str] = dataclasses.field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(slots=True)
class Cycle:
    timestamp: float
    source: str
    parse: ParseStats
    sources: dict[str, SourceSnapshot]
    detections: list[Detection]
    enforcements: list[Enforcement]
    duration: float
    monitored_sources: int
    intelligence: Optional[dict[str, Any]] = None

    def as_dict(self, top_n: int) -> dict[str, Any]:
        top = sorted(self.sources.values(), key=lambda s: (-s.connections, s.ip))[:top_n]
        return {
            "app": APP_NAME,
            "version": APP_VERSION,
            "timestamp": self.timestamp,
            "timestamp_iso": iso_time(self.timestamp),
            "source": self.source,
            "duration_seconds": round(self.duration, 6),
            "parse": self.parse.as_dict(),
            "unique_sources": len(self.sources),
            "monitored_sources": self.monitored_sources,
            "total_connections": sum(s.connections for s in self.sources.values()),
            "top_sources": [s.as_dict() for s in top],
            "detections": [d.as_dict() for d in self.detections],
            "enforcements": [e.as_dict() for e in self.enforcements],
            "intelligence": self.intelligence,
        }


def iso_time(value: float) -> str:
    return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat()


def log(level: str, message: str, quiet: bool = False) -> None:
    if quiet and level != "ERROR":
        return
    print(f"[{iso_time(time.time())}] {level}: {message}", file=sys.stderr, flush=True)


def parse_ip(value: str) -> Optional[IP]:
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


def parse_networks(values: Iterable[str]) -> tuple[NETWORK, ...]:
    result: list[NETWORK] = []
    for value in values:
        for item in value.split(","):
            item = item.strip()
            if item:
                result.append(ipaddress.ip_network(item, strict=False))
    return tuple(result)


def belongs(address: IP, networks: tuple[NETWORK, ...]) -> bool:
    return any(address in network for network in networks if address.version == network.version)


class ConntrackParser:
    KV = re.compile(r"([a-zA-Z_][a-zA-Z0-9_]*)=([^\s]+)")
    FAMILY = {"ipv4", "ipv6"}
    STATES = {
        "NONE", "SYN_SENT", "SYN_RECV", "ESTABLISHED", "FIN_WAIT",
        "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE", "LISTEN",
        "UNREPLIED", "ASSURED", "NEW", "RELATED", "INVALID",
    }

    @staticmethod
    def integer(value: Optional[str]) -> Optional[int]:
        if value is None:
            return None
        try:
            result = int(value)
            return result if result >= 0 else None
        except ValueError:
            return None

    def parse(self, line: str) -> Optional[ConntrackEntry]:
        parts = line.split()
        if not parts:
            return None
        family = next((x for x in parts[:3] if x in self.FAMILY), "")
        fields = list(self.KV.findall(line))
        srcs = [v for k, v in fields if k == "src"]
        dsts = [v for k, v in fields if k == "dst"]
        sports = [v for k, v in fields if k == "sport"]
        dports = [v for k, v in fields if k == "dport"]
        if not srcs or not dsts:
            return None
        original_src = parse_ip(srcs[0])
        original_dst = parse_ip(dsts[0])
        if original_src is None or original_dst is None:
            return None
        if original_src.version != original_dst.version:
            return None
        if not family:
            family = f"ipv{original_src.version}"
        if family != f"ipv{original_src.version}":
            return None
        reply_src = parse_ip(srcs[1]) if len(srcs) > 1 else None
        reply_dst = parse_ip(dsts[1]) if len(dsts) > 1 else None
        if parts[0] in self.FAMILY:
            protocol = parts[2] if len(parts) > 2 else "unknown"
        else:
            protocol = parts[0]
        protocol = protocol.lower()
        state = next((x for x in parts if x in self.STATES), "UNKNOWN")
        timeout = None
        protocol_index = 2 if parts[0] in self.FAMILY else 0
        numeric = parts[protocol_index + 1:protocol_index + 4]
        if len(numeric) >= 2 and numeric[0].isdigit() and numeric[1].isdigit():
            timeout = int(numeric[1])
        elif numeric and numeric[0].isdigit():
            timeout = int(numeric[0])
        return ConntrackEntry(
            family=family,
            protocol=protocol,
            state=state,
            original_src=original_src,
            original_dst=original_dst,
            reply_src=reply_src,
            reply_dst=reply_dst,
            original_sport=self.integer(sports[0]) if sports else None,
            original_dport=self.integer(dports[0]) if dports else None,
            timeout=timeout,
            raw=line,
            mark=self.integer(next((v for k, v in fields if k == "mark"), None)),
            zone=self.integer(next((v for k, v in fields if k == "zone"), None)),
            status=tuple(x.strip("[]") for x in parts if x.startswith("[") and x.endswith("]")),
        )


class InputSource:
    PROC_PATHS = ("/proc/net/nf_conntrack", "/proc/net/ip_conntrack")

    def __init__(self, config: Config) -> None:
        self.config = config

    def locate(self) -> tuple[str, str]:
        if self.config.conntrack_path:
            return "file", self.config.conntrack_path
        if self.config.source in {"auto", "proc"}:
            for path in self.PROC_PATHS:
                if Path(path).is_file():
                    return "proc", path
            if self.config.source == "proc":
                raise FileNotFoundError("no readable conntrack proc file found")
        if self.config.source in {"auto", "command"}:
            executable = shutil.which(self.config.conntrack_command)
            if executable:
                return "command", executable
            raise FileNotFoundError(
                "conntrack data unavailable: install conntrack-tools or provide --conntrack-path"
            )
        raise ValueError("unsupported input source")

    def read(self) -> tuple[str, list[str]]:
        kind, value = self.locate()
        if kind == "command":
            result = subprocess.run(
                [value, "-L", "-o", "extended"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self.config.max_command_seconds,
                check=False,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    f"conntrack command failed ({result.returncode}): {result.stderr.strip()[:500]}"
                )
            encoded_size = len(result.stdout.encode("utf-8"))
            if encoded_size > self.config.max_bytes:
                raise ValueError("conntrack command output exceeds maximum size")
            lines = result.stdout.splitlines()
            if len(lines) > self.config.max_lines:
                raise ValueError("conntrack command output exceeds maximum lines")
            if any(len(line) > self.config.max_line_size for line in lines):
                raise ValueError("conntrack command output contains oversized lines")
            return f"command:{value}", lines
        path = Path(value)
        if not path.is_file():
            raise ValueError(f"not a regular input file: {path}")
        if path.stat().st_size > self.config.max_bytes:
            raise ValueError("input file exceeds maximum size")
        lines: list[str] = []
        total = 0
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            for index, line in enumerate(stream, 1):
                if index > self.config.max_lines:
                    raise ValueError("input exceeds maximum lines")
                total += len(line.encode("utf-8"))
                if total > self.config.max_bytes:
                    raise ValueError("input exceeds maximum bytes")
                if len(line) > self.config.max_line_size:
                    raise ValueError(f"oversized input line {index}")
                lines.append(line.rstrip("\n"))
        return f"{kind}:{path}", lines


class Attribution:
    def __init__(self, config: Config) -> None:
        self.config = config

    def eligible(self, entry: ConntrackEntry) -> bool:
        src = entry.original_src
        dst = entry.original_dst
        if self.config.family != "any" and entry.family != self.config.family:
            return False
        if src.is_unspecified or src.is_multicast or src.is_link_local:
            return False
        if src.is_loopback and not self.config.include_loopback:
            return False
        if src.is_private and not self.config.include_private:
            return False
        if belongs(src, self.config.trusted_networks):
            return False
        if self.config.local_networks:
            if belongs(src, self.config.local_networks):
                return False
            if not belongs(dst, self.config.local_networks):
                return False
        return True

    def safe_to_enforce(self, address: IP) -> tuple[bool, str]:
        if not self.config.local_networks:
            return False, "no --local-network configured; direction cannot be verified"
        if belongs(address, self.config.local_networks):
            return False, "source belongs to a local network"
        if belongs(address, self.config.trusted_networks):
            return False, "source belongs to a trusted network"
        if not address.is_global:
            return False, "source is not a global unicast address"
        return True, "eligible"


class SlidingBaseline:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.states: dict[str, SourceState] = {}

    def state(self, ip: str, now: float) -> SourceState:
        existing = self.states.get(ip)
        if existing is not None:
            existing.last_seen = now
            return existing
        if len(self.states) >= self.config.max_sources:
            oldest = min(self.states, key=lambda key: self.states[key].last_seen)
            del self.states[oldest]
        state = SourceState(
            history=collections.deque(maxlen=self.config.history_size),
            first_seen=now,
            last_seen=now,
        )
        self.states[ip] = state
        return state

    def classify(self, snapshot: SourceSnapshot, now: float) -> Optional[Detection]:
        state = self.state(snapshot.ip, now)
        count = snapshot.connections
        history = list(state.history)
        samples = len(history)
        mean = statistics.fmean(history) if history else 0.0
        stdev = statistics.stdev(history) if samples >= 2 else 0.0
        delta = count - mean
        ratio = count / max(mean, 1.0)
        if stdev > 0:
            zscore = delta / stdev
        elif delta > 0:
            zscore = math.inf
        else:
            zscore = 0.0
        severity = ""
        reason = ""
        if samples >= self.config.min_samples:
            critical_count = count >= self.config.count_crit
            warning_count = count >= self.config.count_warn
            critical_spike = (
                delta >= self.config.absolute_delta
                and ratio >= self.config.ratio_crit
                and zscore >= self.config.zscore_crit
            )
            warning_spike = (
                delta >= self.config.absolute_delta
                and ratio >= self.config.ratio_warn
                and zscore >= self.config.zscore_warn
            )
            if critical_count or critical_spike:
                severity = "critical"
                reason = "absolute-threshold" if critical_count else "statistical-spike"
            elif warning_count or warning_spike:
                severity = "warning"
                reason = "absolute-threshold" if warning_count else "statistical-spike"
        if severity != "critical":
            state.history.append(count)
        state.last_seen = now
        if not severity:
            return None
        state.detections += 1
        if now - state.last_alert < self.config.cooldown_seconds:
            return None
        state.last_alert = now
        return Detection(
            ip=snapshot.ip,
            family=snapshot.family,
            severity=severity,
            count=count,
            baseline_mean=mean,
            baseline_stdev=stdev,
            zscore=zscore,
            ratio=ratio,
            delta=delta,
            samples=samples,
            reason=reason,
            first_seen=state.first_seen,
            last_seen=state.last_seen,
            destination_count=len(snapshot.destinations),
            destination_port_count=len(snapshot.ports),
        )

    def update_missing(self, seen: set[str], now: float) -> None:
        for ip, state in self.states.items():
            if ip not in seen:
                state.history.append(0)
        self.prune(now)

    def prune(self, now: float) -> None:
        expired = [
            ip for ip, state in self.states.items()
            if now - state.last_seen > self.config.expire_seconds
        ]
        for ip in expired:
            del self.states[ip]

    def export(self) -> dict[str, Any]:
        return {
            "version": 1,
            "history_size": self.config.history_size,
            "states": {
                ip: {
                    "history": list(state.history),
                    "first_seen": state.first_seen,
                    "last_seen": state.last_seen,
                    "last_alert": state.last_alert,
                    "last_enforced": state.last_enforced,
                    "detections": state.detections,
                }
                for ip, state in self.states.items()
            },
        }

    def restore(self, payload: dict[str, Any]) -> None:
        if payload.get("version") != 1:
            raise ValueError("unsupported state version")
        raw = payload.get("states")
        if not isinstance(raw, dict):
            raise ValueError("invalid state payload")
        if len(raw) > self.config.max_sources:
            raise ValueError("state contains too many sources")
        restored: dict[str, SourceState] = {}
        for key, item in raw.items():
            if not isinstance(key, str) or parse_ip(key) is None:
                continue
            if not isinstance(item, dict):
                continue
            values = item.get("history", [])
            if not isinstance(values, list):
                continue
            if not all(type(v) is int and 0 <= v <= 10**9 for v in values):
                continue
            try:
                times = [float(item.get(name, 0)) for name in ("first_seen", "last_seen", "last_alert", "last_enforced")]
                detections = int(item.get("detections", 0))
            except (TypeError, ValueError, OverflowError):
                continue
            if not all(math.isfinite(v) and v >= 0 for v in times) or detections < 0:
                continue
            restored[key] = SourceState(
                history=collections.deque(values[-self.config.history_size:], maxlen=self.config.history_size),
                first_seen=times[0],
                last_seen=times[1],
                last_alert=times[2],
                last_enforced=times[3],
                detections=detections,
            )
        self.states = restored


class IPSetEnforcer:
    def __init__(self, config: Config, attribution: Attribution) -> None:
        self.config = config
        self.attribution = attribution

    def set_name(self, address: IP) -> str:
        return self.config.ipset_set_v6 if address.version == 6 else self.config.ipset_set_v4

    def execute(self, args: list[str]) -> tuple[bool, str]:
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=self.config.max_command_seconds,
                check=False,
            )
            if result.returncode:
                return False, (result.stderr or result.stdout).strip()[:500]
            return True, result.stdout.strip()[:500] or "ok"
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, str(exc)

    def add(self, ip: str) -> Enforcement:
        now = time.time()
        address = ipaddress.ip_address(ip)
        safe, reason = self.attribution.safe_to_enforce(address)
        if not safe:
            return Enforcement(ip, self.config.backend, "skipped", False, reason, now)
        if not self.config.enforce:
            return Enforcement(ip, self.config.backend, "dry-run", True, "would add to ipset", now)
        if self.config.backend != "ipset":
            return Enforcement(ip, self.config.backend, "skipped", False, "unsupported backend", now)
        executable = shutil.which(self.config.ipset_path)
        if not executable:
            return Enforcement(ip, self.config.backend, "failed", False, "ipset executable missing", now)
        name = self.set_name(address)
        if self.config.create_sets:
            ok, detail = self.execute([
                executable, "create", name, "hash:ip",
                "family", "inet6" if address.version == 6 else "inet",
                "timeout", str(self.config.ipset_timeout), "-exist",
            ])
            if not ok:
                return Enforcement(ip, "ipset", "failed", False, f"set creation: {detail}", now)
        ok, detail = self.execute([
            executable, "add", name, ip,
            "timeout", str(self.config.ipset_timeout), "-exist",
        ])
        return Enforcement(ip, "ipset", "added" if ok else "failed", ok, detail, now)


class StateStore:
    def __init__(self, path: str) -> None:
        self.path = Path(path)

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"version": 1, "states": {}}
        if self.path.stat().st_size > 32 * 1024 * 1024:
            raise ValueError("state file too large")
        with self.path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
        if not isinstance(value, dict):
            raise ValueError("state file must contain a JSON object")
        return value

    def save(self, value: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        try:
            with temp.open("w", encoding="utf-8") as stream:
                json.dump(value, stream, separators=(",", ":"), allow_nan=False)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp, self.path)
        finally:
            if temp.exists():
                temp.unlink()


class Renderer:
    @staticmethod
    def json(cycle: Cycle, config: Config) -> str:
        return json.dumps(
            cycle.as_dict(config.top_n),
            indent=None if config.compact_json else 2,
            ensure_ascii=False,
            allow_nan=False,
        )

    @staticmethod
    def text(cycle: Cycle, config: Config) -> str:
        rows = [
            f"{APP_NAME} {APP_VERSION}  {iso_time(cycle.timestamp)}",
            f"input: {cycle.source}",
            f"entries={cycle.parse.parsed_entries} malformed={cycle.parse.malformed_lines} "
            f"excluded={cycle.parse.excluded_entries} ambiguous={cycle.parse.ambiguous_entries}",
            f"sources={len(cycle.sources)} tracked={cycle.monitored_sources} "
            f"duration={cycle.duration:.3f}s",
            "",
            f"{'SOURCE':<40} {'COUNT':>8} {'DEST':>6} {'PORTS':>6}",
            "-" * 66,
        ]
        top = sorted(cycle.sources.values(), key=lambda s: (-s.connections, s.ip))[:config.top_n]
        for item in top:
            rows.append(
                f"{item.ip:<40} {item.connections:>8} "
                f"{len(item.destinations):>6} {len(item.ports):>6}"
            )
        rows.append("")
        if cycle.detections:
            rows.append("detections:")
            for item in cycle.detections:
                zscore = "inf" if math.isinf(item.zscore) else f"{item.zscore:.2f}"
                rows.append(
                    f"  {item.severity.upper():<8} {item.ip:<39} "
                    f"count={item.count} mean={item.baseline_mean:.2f} "
                    f"z={zscore} ratio={item.ratio:.2f} reason={item.reason}"
                )
        if cycle.enforcements:
            rows.append("enforcement:")
            for item in cycle.enforcements:
                rows.append(
                    f"  {item.action:<9} {item.ip:<39} "
                    f"ok={item.ok} detail={item.detail}"
                )
        if cycle.parse.error_samples:
            rows.append("parse samples:")
            rows.extend(f"  {line}" for line in cycle.parse.error_samples)
        return "\n".join(rows)


class GardenWarden:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.parser = ConntrackParser()
        self.input = InputSource(config)
        self.attribution = Attribution(config)
        self.baseline = SlidingBaseline(config)
        self.enforcer = IPSetEnforcer(config, self.attribution)
        self.shutdown = False
        self.store = StateStore(config.state_path) if config.state_path else None
        self.intelligence = IntelligenceEngine(config)
        self.previous_snapshot: Optional[dict[str, Any]] = None
        self.last_snapshot: Optional[dict[str, Any]] = None
        if self.store:
            self.baseline.restore(self.store.load())

    def install_signals(self) -> None:
        def stop(_signum: int, _frame: Any) -> None:
            self.shutdown = True
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)

    def cycle(self) -> Cycle:
        started = time.monotonic()
        now = time.time()
        source, lines = self.input.read()
        stats = ParseStats()
        snapshots: dict[str, SourceSnapshot] = {}
        for line in lines:
            stats.total_lines += 1
            if not line.strip():
                continue
            entry = self.parser.parse(line)
            if entry is None:
                stats.malformed_lines += 1
                if len(stats.error_samples) < 5:
                    stats.error_samples.append(line[:160])
                continue
            stats.parsed_entries += 1
            if not self.attribution.eligible(entry):
                stats.excluded_entries += 1
                continue
            if not self.config.local_networks:
                stats.ambiguous_entries += 1
            ip = str(entry.original_src)
            snapshot = snapshots.get(ip)
            if snapshot is None:
                snapshot = SourceSnapshot(ip=ip, family=entry.family)
                snapshots[ip] = snapshot
            snapshot.add(entry)
        if len(snapshots) > self.config.max_sources:
            snapshots = dict(sorted(snapshots.items(), key=lambda item: (-item[1].connections, item[0]))[:self.config.max_sources])
        intelligence = self.intelligence.analyze(snapshots, stats, now) if self.config.analysis_enabled else None
        detections: list[Detection] = []
        enforcements: list[Enforcement] = []
        for ip, snapshot in snapshots.items():
            detection = self.baseline.classify(snapshot, now)
            if detection is None:
                continue
            detections.append(detection)
            if detection.severity != "critical":
                continue
            if len(enforcements) >= self.config.max_enforcements:
                continue
            state = self.baseline.states[ip]
            if now - state.last_enforced < self.config.cooldown_seconds:
                continue
            result = self.enforcer.add(ip)
            enforcements.append(result)
            if result.ok and result.action == "added":
                state.last_enforced = now
        self.baseline.update_missing(set(snapshots), now)
        detections.sort(
            key=lambda d: (
                0 if d.severity == "critical" else 1,
                -d.count,
                d.ip,
            )
        )
        return Cycle(
            timestamp=now,
            source=source,
            parse=stats,
            sources=snapshots,
            detections=detections,
            enforcements=enforcements,
            duration=time.monotonic() - started,
            monitored_sources=len(self.baseline.states),
            intelligence=intelligence,
        )

    def emit(self, cycle: Cycle) -> None:
        result = (
            Renderer.json(cycle, self.config)
            if self.config.json_output
            else Renderer.text(cycle, self.config)
        )
        if not self.config.json_output:
            result = CosmosRenderer(self.config).decorate(result, cycle)
        print(result, flush=True)
        if self.config.forensic_output:
            self.write_forensic_snapshot(cycle)

    def write_forensic_snapshot(self, cycle: Cycle) -> None:
        payload = self.intelligence.snapshot(cycle, self.config)
        if self.config.compare_snapshot:
            previous = load_snapshot(self.config.compare_snapshot, self.config.max_snapshot_bytes)
            payload["comparison"] = compare_snapshots(previous, payload)
        atomic_json_write(Path(self.config.forensic_output), payload)

    def save(self) -> None:
        if self.store and self.config.save_state:
            self.store.save(self.baseline.export())

    def run(self) -> int:
        self.install_signals()
        if self.config.enforce:
            log("WARNING", "active ipset changes enabled; firewall rules must separately reference sets", self.config.quiet)
        try:
            while not self.shutdown:
                cycle = self.cycle()
                self.emit(cycle)
                self.save()
                if self.config.once:
                    break
                deadline = time.monotonic() + self.config.interval
                while not self.shutdown and time.monotonic() < deadline:
                    time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
        finally:
            self.save()
        return 0


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description="Connection tracking anomaly detector with cautious optional ipset enforcement",
    )
    parser.add_argument("--interval", type=float, default=5.0)
    parser.add_argument("--history-size", type=int, default=24)
    parser.add_argument("--min-samples", type=int, default=6)
    parser.add_argument("--zscore-warn", type=float, default=2.5)
    parser.add_argument("--zscore-crit", type=float, default=4.0)
    parser.add_argument("--count-warn", type=int, default=50)
    parser.add_argument("--count-crit", type=int, default=200)
    parser.add_argument("--ratio-warn", type=float, default=3.0)
    parser.add_argument("--ratio-crit", type=float, default=6.0)
    parser.add_argument("--absolute-delta", type=int, default=10)
    parser.add_argument("--expire-seconds", type=float, default=3600)
    parser.add_argument("--cooldown-seconds", type=float, default=60)
    parser.add_argument("--top-n", type=int, default=25)
    parser.add_argument("--max-sources", type=int, default=100000)
    parser.add_argument("--family", choices=("any", "ipv4", "ipv6"), default="any")
    parser.add_argument("--source", choices=("auto", "proc", "command"), default="auto")
    parser.add_argument("--conntrack-path")
    parser.add_argument("--conntrack-command", default="conntrack")
    parser.add_argument("--max-bytes", type=int, default=256 * 1024 * 1024)
    parser.add_argument("--max-lines", type=int, default=2000000)
    parser.add_argument("--max-line-size", type=int, default=32768)
    parser.add_argument("--include-loopback", action="store_true")
    parser.add_argument("--include-private", action="store_true")
    parser.add_argument("--local-network", action="append", default=[])
    parser.add_argument("--trusted-network", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--compact-json", action="store_true")
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--enforce", action="store_true")
    parser.add_argument("--backend", choices=("none", "ipset"), default="none")
    parser.add_argument("--ipset-path", default="ipset")
    parser.add_argument("--ipset-set-v4", default="garden_warden_v4")
    parser.add_argument("--ipset-set-v6", default="garden_warden_v6")
    parser.add_argument("--ipset-timeout", type=int, default=3600)
    parser.add_argument("--create-sets", action="store_true")
    parser.add_argument("--max-enforcements", type=int, default=20)
    parser.add_argument("--state-path")
    parser.add_argument("--save-state", action="store_true")
    parser.add_argument("--max-command-seconds", type=float, default=10.0)
    parser.add_argument("--theme", choices=("cosmos", "classic", "mono"), default="cosmos")
    parser.add_argument("--color", choices=("auto", "always", "never"), default="auto")
    parser.add_argument("--forensic-output")
    parser.add_argument("--compare-snapshot")
    parser.add_argument("--profile-limit", type=int, default=100)
    parser.add_argument("--scan-port-warn", type=int, default=12)
    parser.add_argument("--scan-port-crit", type=int, default=40)
    parser.add_argument("--scan-destination-warn", type=int, default=16)
    parser.add_argument("--scan-destination-crit", type=int, default=64)
    parser.add_argument("--syn-ratio-warn", type=float, default=0.60)
    parser.add_argument("--syn-ratio-crit", type=float, default=0.85)
    parser.add_argument("--syn-min-connections", type=int, default=20)
    parser.add_argument("--entropy-warn", type=float, default=3.5)
    parser.add_argument("--no-intelligence", dest="analysis_enabled", action="store_false")
    parser.add_argument("--snapshot-history", type=int, default=64)
    parser.add_argument("--max-command-output", type=int, default=128 * 1024 * 1024)
    parser.add_argument("--max-snapshot-bytes", type=int, default=32 * 1024 * 1024)
    return parser


def validate(config: Config) -> None:
    positive = (
        "interval", "history_size", "min_samples", "zscore_warn", "zscore_crit",
        "count_warn", "count_crit", "ratio_warn", "ratio_crit", "absolute_delta",
        "expire_seconds", "cooldown_seconds", "top_n", "max_sources", "max_bytes",
        "max_lines", "max_line_size", "ipset_timeout", "max_enforcements",
        "max_command_seconds", "profile_limit", "scan_port_warn", "scan_port_crit",
        "scan_destination_warn", "scan_destination_crit", "syn_min_connections",
        "entropy_warn", "snapshot_history", "max_command_output", "max_snapshot_bytes",
    )
    for name in positive:
        value = getattr(config, name)
        if not math.isfinite(value) or value <= 0:
            raise ValueError(f"{name} must be finite and greater than zero")
    if config.min_samples > config.history_size:
        raise ValueError("min_samples cannot exceed history_size")
    if config.zscore_crit < config.zscore_warn:
        raise ValueError("critical zscore must be >= warning zscore")
    if config.count_crit < config.count_warn:
        raise ValueError("critical count must be >= warning count")
    if config.ratio_crit < config.ratio_warn:
        raise ValueError("critical ratio must be >= warning ratio")
    if not (0 <= config.syn_ratio_warn <= config.syn_ratio_crit <= 1):
        raise ValueError("SYN ratios must be ordered and between zero and one")
    if config.scan_port_crit < config.scan_port_warn:
        raise ValueError("critical port threshold must be >= warning threshold")
    if config.scan_destination_crit < config.scan_destination_warn:
        raise ValueError("critical destination threshold must be >= warning threshold")
    if config.compare_snapshot and not config.forensic_output:
        raise ValueError("--compare-snapshot requires --forensic-output")
    if config.enforce and config.backend != "ipset":
        raise ValueError("--enforce requires --backend ipset")
    if config.enforce and not config.local_networks:
        raise ValueError("--enforce requires explicit --local-network for direction validation")
    if config.save_state and not config.state_path:
        raise ValueError("--save-state requires --state-path")
    for name in (config.ipset_set_v4, config.ipset_set_v6):
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,31}", name):
            raise ValueError("invalid ipset set name")


def config_from_args(args: argparse.Namespace) -> Config:
    values = vars(args).copy()
    values["json_output"] = values.pop("json") or values["compact_json"]
    values["local_networks"] = parse_networks(values.pop("local_network"))
    values["trusted_networks"] = parse_networks(values.pop("trusted_network"))
    return Config(**values)


def main(argv: Optional[list[str]] = None) -> int:
    try:
        args = argument_parser().parse_args(argv)
        config = config_from_args(args)
        validate(config)
        return GardenWarden(config).run()
    except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
        log("ERROR", str(exc))
        return 1
    except KeyboardInterrupt:
        return 130


def ranked_counter(counter: collections.Counter[Any], limit: int) -> list[dict[str, Any]]:
    return [
        {"value": str(key), "count": count}
        for key, count in sorted(counter.items(), key=lambda item: (-item[1], str(item[0])))[:limit]
    ]


def shannon_entropy(counter: collections.Counter[Any]) -> float:
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    return -sum((value / total) * math.log2(value / total) for value in counter.values() if value > 0)


def coefficient_of_variation(values: Iterable[float]) -> float:
    numbers = [float(value) for value in values if math.isfinite(float(value))]
    if len(numbers) < 2:
        return 0.0
    mean = statistics.fmean(numbers)
    if mean == 0:
        return 0.0
    return statistics.pstdev(numbers) / abs(mean)


def quantiles(values: Iterable[float]) -> dict[str, float | None]:
    numbers = sorted(float(value) for value in values)
    if not numbers:
        return {"min": None, "p25": None, "p50": None, "p75": None, "p90": None, "p95": None, "p99": None, "max": None}
    def percentile(percent: float) -> float:
        position = (len(numbers) - 1) * percent
        low = math.floor(position)
        high = math.ceil(position)
        return numbers[low] + (numbers[high] - numbers[low]) * (position - low)
    return {
        "min": numbers[0],
        "p25": percentile(0.25),
        "p50": percentile(0.50),
        "p75": percentile(0.75),
        "p90": percentile(0.90),
        "p95": percentile(0.95),
        "p99": percentile(0.99),
        "max": numbers[-1],
    }


def gini_coefficient(values: Iterable[int]) -> float:
    numbers = sorted(max(0, int(value)) for value in values)
    total = sum(numbers)
    if not numbers or total == 0:
        return 0.0
    weighted = sum(index * value for index, value in enumerate(numbers, 1))
    return (2 * weighted) / (len(numbers) * total) - (len(numbers) + 1) / len(numbers)


def safe_fraction(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def normalized_state(state: str) -> str:
    state = state.strip().upper()
    if state in {"SYN_SENT", "SYN_RECV"}:
        return "SYN"
    if state in {"ESTABLISHED", "ASSURED"}:
        return "ESTABLISHED"
    if state in {"FIN_WAIT", "CLOSE_WAIT", "LAST_ACK", "TIME_WAIT", "CLOSE"}:
        return "CLOSING"
    if state in {"UNREPLIED", "NEW"}:
        return "UNREPLIED"
    return "OTHER"


@dataclasses.dataclass(slots=True)
class Finding:
    source: str
    category: str
    severity: str
    title: str
    description: str
    evidence: dict[str, Any]
    confidence: str = "heuristic"

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(slots=True)
class SourceProfile:
    ip: str
    family: str
    connections: int
    protocols: dict[str, int]
    states: dict[str, int]
    normalized_states: dict[str, int]
    destination_count: int
    destination_port_count: int
    source_port_count: int
    port_entropy: float
    destination_entropy: float
    state_entropy: float
    syn_fraction: float
    unreplied_fraction: float
    closing_fraction: float
    tcp_fraction: float
    udp_fraction: float
    port_concentration: float
    destination_concentration: float
    median_timeout: float | None
    timeout_quantiles: dict[str, float | None]
    common_ports: list[dict[str, Any]]
    common_destinations: list[dict[str, Any]]
    common_flows: list[dict[str, Any]]
    risk_score: float = 0.0
    risk_band: str = "informational"
    finding_count: int = 0

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


class ProfileBuilder:
    def __init__(self, config: Config) -> None:
        self.config = config

    def build(self, snapshot: SourceSnapshot) -> SourceProfile:
        total = snapshot.connections
        normalized = collections.Counter()
        for state, count in snapshot.states.items():
            normalized[normalized_state(state)] += count
        top_port = max(snapshot.port_counts.values(), default=0)
        top_destination = max(snapshot.destination_counts.values(), default=0)
        return SourceProfile(
            ip=snapshot.ip,
            family=snapshot.family,
            connections=total,
            protocols=dict(snapshot.protocols),
            states=dict(snapshot.states),
            normalized_states=dict(normalized),
            destination_count=len(snapshot.destinations),
            destination_port_count=len(snapshot.ports),
            source_port_count=len(snapshot.source_ports),
            port_entropy=shannon_entropy(snapshot.port_counts),
            destination_entropy=shannon_entropy(snapshot.destination_counts),
            state_entropy=shannon_entropy(normalized),
            syn_fraction=safe_fraction(normalized["SYN"], total),
            unreplied_fraction=safe_fraction(normalized["UNREPLIED"], total),
            closing_fraction=safe_fraction(normalized["CLOSING"], total),
            tcp_fraction=safe_fraction(snapshot.protocols["tcp"], total),
            udp_fraction=safe_fraction(snapshot.protocols["udp"], total),
            port_concentration=safe_fraction(top_port, total),
            destination_concentration=safe_fraction(top_destination, total),
            median_timeout=statistics.median(snapshot.timeouts) if snapshot.timeouts else None,
            timeout_quantiles=quantiles(snapshot.timeouts),
            common_ports=ranked_counter(snapshot.port_counts, 10),
            common_destinations=ranked_counter(snapshot.destination_counts, 10),
            common_flows=ranked_counter(snapshot.flows, 10),
        )


class FindingRules:
    def __init__(self, config: Config) -> None:
        self.config = config

    def evaluate(self, profile: SourceProfile) -> list[Finding]:
        findings: list[Finding] = []
        rules = (
            self.port_fanout,
            self.destination_fanout,
            self.syn_concentration,
            self.unreplied_concentration,
            self.closing_concentration,
            self.high_volume,
            self.port_entropy,
            self.destination_entropy,
            self.single_port_flood,
            self.single_destination_flood,
            self.source_port_churn,
            self.udp_dominance,
            self.low_timeout,
            self.high_timeout,
            self.mixed_protocols,
            self.sparse_port_distribution,
            self.dense_destination_distribution,
        )
        for rule in rules:
            finding = rule(profile)
            if finding is not None:
                findings.append(finding)
        return findings

    def finding(self, profile: SourceProfile, category: str, severity: str, title: str, description: str, evidence: dict[str, Any]) -> Finding:
        return Finding(profile.ip, category, severity, title, description, evidence)

    def port_fanout(self, p: SourceProfile) -> Finding | None:
        if p.destination_port_count >= self.config.scan_port_crit:
            severity = "critical"
        elif p.destination_port_count >= self.config.scan_port_warn:
            severity = "warning"
        else:
            return None
        return self.finding(p, "port-fanout", severity, "Many destination ports", "A source has connections across numerous destination ports; this may reflect scanning or legitimate discovery.", {"ports": p.destination_port_count, "connections": p.connections})

    def destination_fanout(self, p: SourceProfile) -> Finding | None:
        if p.destination_count >= self.config.scan_destination_crit:
            severity = "critical"
        elif p.destination_count >= self.config.scan_destination_warn:
            severity = "warning"
        else:
            return None
        return self.finding(p, "destination-fanout", severity, "Many destination hosts", "The source is connected to a large number of destinations; attribution requires local-network context.", {"destinations": p.destination_count, "connections": p.connections})

    def syn_concentration(self, p: SourceProfile) -> Finding | None:
        if p.connections < self.config.syn_min_connections or p.tcp_fraction < 0.5:
            return None
        if p.syn_fraction >= self.config.syn_ratio_crit:
            severity = "critical"
        elif p.syn_fraction >= self.config.syn_ratio_warn:
            severity = "warning"
        else:
            return None
        return self.finding(p, "syn-concentration", severity, "SYN-heavy connection population", "A large fraction of tracked connections is in TCP handshake states; a single conntrack snapshot cannot establish a SYN flood.", {"syn_fraction": round(p.syn_fraction, 5), "tcp_fraction": round(p.tcp_fraction, 5), "connections": p.connections})

    def unreplied_concentration(self, p: SourceProfile) -> Finding | None:
        if p.connections < 20 or p.unreplied_fraction < 0.70:
            return None
        return self.finding(p, "unreplied", "warning", "High unreplied fraction", "Many tracked flows lack replies, which may indicate filtering, unreachable services, or transient traffic.", {"fraction": round(p.unreplied_fraction, 5), "connections": p.connections})

    def closing_concentration(self, p: SourceProfile) -> Finding | None:
        if p.connections < 30 or p.closing_fraction < 0.8:
            return None
        return self.finding(p, "closing", "info", "Closing-state concentration", "A majority of flows are in TCP teardown states; review connection churn and application behavior.", {"fraction": round(p.closing_fraction, 5)})

    def high_volume(self, p: SourceProfile) -> Finding | None:
        if p.connections >= self.config.count_crit:
            severity = "critical"
        elif p.connections >= self.config.count_warn:
            severity = "warning"
        else:
            return None
        return self.finding(p, "volume", severity, "Elevated tracked connection count", "An absolute count threshold has been exceeded; this does not imply malicious traffic.", {"connections": p.connections, "threshold": self.config.count_crit if severity == "critical" else self.config.count_warn})

    def port_entropy(self, p: SourceProfile) -> Finding | None:
        if p.destination_port_count < 8 or p.port_entropy < self.config.entropy_warn:
            return None
        return self.finding(p, "port-entropy", "info", "Diverse destination-port distribution", "Connections are distributed across multiple ports with relatively high Shannon entropy.", {"entropy_bits": round(p.port_entropy, 4), "unique_ports": p.destination_port_count})

    def destination_entropy(self, p: SourceProfile) -> Finding | None:
        if p.destination_count < 8 or p.destination_entropy < self.config.entropy_warn:
            return None
        return self.finding(p, "destination-entropy", "info", "Diverse destination distribution", "Destination selection is broad rather than concentrated on a small set of hosts.", {"entropy_bits": round(p.destination_entropy, 4), "unique_destinations": p.destination_count})

    def single_port_flood(self, p: SourceProfile) -> Finding | None:
        if p.connections < 50 or p.port_concentration < 0.9:
            return None
        return self.finding(p, "port-concentration", "warning", "Single-port connection concentration", "Most tracked connections target one destination port; this may be expected for application traffic.", {"fraction": round(p.port_concentration, 5), "top_ports": p.common_ports[:3]})

    def single_destination_flood(self, p: SourceProfile) -> Finding | None:
        if p.connections < 50 or p.destination_concentration < 0.9:
            return None
        return self.finding(p, "destination-concentration", "warning", "Single-destination connection concentration", "Most tracked connections target one destination; investigate workload context before drawing conclusions.", {"fraction": round(p.destination_concentration, 5), "top_destinations": p.common_destinations[:3]})

    def source_port_churn(self, p: SourceProfile) -> Finding | None:
        if p.connections < 30 or p.source_port_count < 25:
            return None
        if safe_fraction(p.source_port_count, p.connections) < 0.8:
            return None
        return self.finding(p, "source-port-churn", "info", "Many distinct source ports", "The source uses many ephemeral ports, which may be ordinary client connection behavior.", {"unique_source_ports": p.source_port_count, "connections": p.connections})

    def udp_dominance(self, p: SourceProfile) -> Finding | None:
        if p.connections < 50 or p.udp_fraction < 0.9:
            return None
        return self.finding(p, "udp-dominance", "info", "UDP-dominated tracked flows", "Most observed flows use UDP; examine DNS, QUIC, media, or other application traffic.", {"udp_fraction": round(p.udp_fraction, 5)})

    def low_timeout(self, p: SourceProfile) -> Finding | None:
        if p.connections < 30 or p.median_timeout is None or p.median_timeout > 15:
            return None
        return self.finding(p, "short-timeout", "info", "Short remaining conntrack timeouts", "A majority of sampled timeout values are short; values are remaining lifetime rather than flow duration.", {"median_timeout": p.median_timeout})

    def high_timeout(self, p: SourceProfile) -> Finding | None:
        if p.connections < 30 or p.median_timeout is None or p.median_timeout < 86400:
            return None
        return self.finding(p, "long-timeout", "info", "Long remaining conntrack timeouts", "Tracked flows have long remaining timeouts; verify whether the configured conntrack policies are appropriate.", {"median_timeout": p.median_timeout})

    def mixed_protocols(self, p: SourceProfile) -> Finding | None:
        if p.connections < 30 or len(p.protocols) < 3:
            return None
        return self.finding(p, "protocol-diversity", "info", "Mixed protocol activity", "The source has flows across several protocols.", {"protocols": p.protocols})

    def sparse_port_distribution(self, p: SourceProfile) -> Finding | None:
        if p.connections < 30 or p.destination_port_count < 20:
            return None
        if p.port_concentration > 0.2:
            return None
        return self.finding(p, "sparse-port-distribution", "warning", "Diffuse port targeting", "No destination port dominates the source's broad port distribution; investigate possible reconnaissance.", {"unique_ports": p.destination_port_count, "top_port_fraction": round(p.port_concentration, 5)})

    def dense_destination_distribution(self, p: SourceProfile) -> Finding | None:
        if p.connections < 40 or p.destination_count < 20:
            return None
        if p.destination_concentration > 0.2:
            return None
        return self.finding(p, "dense-destination-distribution", "warning", "Diffuse destination targeting", "The source has a broad distribution of destination hosts without a dominant target.", {"unique_destinations": p.destination_count, "top_destination_fraction": round(p.destination_concentration, 5)})


class RiskScorer:
    WEIGHTS = {
        "port-fanout": 14,
        "destination-fanout": 14,
        "syn-concentration": 24,
        "unreplied": 10,
        "closing": 2,
        "volume": 10,
        "port-entropy": 3,
        "destination-entropy": 3,
        "port-concentration": 8,
        "destination-concentration": 8,
        "source-port-churn": 2,
        "udp-dominance": 2,
        "short-timeout": 2,
        "long-timeout": 2,
        "protocol-diversity": 2,
        "sparse-port-distribution": 10,
        "dense-destination-distribution": 10,
    }

    def score(self, findings: list[Finding]) -> tuple[float, str]:
        raw = sum(self.WEIGHTS.get(finding.category, 1) * (1.4 if finding.severity == "critical" else 1.0) for finding in findings)
        score = min(100.0, round(raw, 2))
        if score >= 70:
            band = "critical"
        elif score >= 40:
            band = "high"
        elif score >= 15:
            band = "moderate"
        else:
            band = "informational"
        return score, band


class IntelligenceEngine:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.builder = ProfileBuilder(config)
        self.rules = FindingRules(config)
        self.scorer = RiskScorer()
        self.history: collections.deque[dict[str, Any]] = collections.deque(maxlen=config.snapshot_history)
        self.cumulative_findings: collections.Counter[str] = collections.Counter()
        self.cumulative_sources: collections.Counter[str] = collections.Counter()
        self.cycle_number = 0

    def analyze(self, snapshots: dict[str, SourceSnapshot], stats: ParseStats, now: float) -> dict[str, Any]:
        self.cycle_number += 1
        profiles: list[SourceProfile] = []
        findings: list[Finding] = []
        protocol_counts: collections.Counter[str] = collections.Counter()
        state_counts: collections.Counter[str] = collections.Counter()
        total_connections = 0
        for snapshot in snapshots.values():
            profile = self.builder.build(snapshot)
            local_findings = self.rules.evaluate(profile)
            score, band = self.scorer.score(local_findings)
            profile.risk_score = score
            profile.risk_band = band
            profile.finding_count = len(local_findings)
            profiles.append(profile)
            findings.extend(local_findings)
            protocol_counts.update(snapshot.protocols)
            state_counts.update(snapshot.states)
            total_connections += snapshot.connections
            self.cumulative_sources[snapshot.ip] += 1
            for finding in local_findings:
                self.cumulative_findings[finding.category] += 1
        profiles.sort(key=lambda profile: (-profile.risk_score, -profile.connections, profile.ip))
        findings.sort(key=lambda finding: ({"critical": 0, "warning": 1, "info": 2}.get(finding.severity, 3), finding.source, finding.category))
        counts = [snapshot.connections for snapshot in snapshots.values()]
        distribution = quantiles(counts)
        concentration = safe_fraction(max(counts, default=0), total_connections)
        histogram = self.connection_histogram(counts)
        summary = {
            "cycle": self.cycle_number,
            "timestamp": iso_time(now),
            "sources": len(snapshots),
            "connections": total_connections,
            "protocols": dict(protocol_counts),
            "states": dict(state_counts),
            "connection_distribution": distribution,
            "connection_histogram": histogram,
            "connection_gini": round(gini_coefficient(counts), 6),
            "largest_source_fraction": round(concentration, 6),
            "parse_success_fraction": round(safe_fraction(stats.parsed_entries, stats.total_lines), 6),
            "finding_count": len(findings),
            "critical_findings": sum(finding.severity == "critical" for finding in findings),
            "warning_findings": sum(finding.severity == "warning" for finding in findings),
        }
        self.history.append({"timestamp": now, "sources": len(snapshots), "connections": total_connections, "findings": len(findings)})
        trends = self.trends()
        return {
            "summary": summary,
            "trends": trends,
            "profiles": [profile.as_dict() for profile in profiles[:self.config.profile_limit]],
            "findings": [finding.as_dict() for finding in findings[:self.config.profile_limit * 8]],
            "findings_truncated": len(findings) > self.config.profile_limit * 8,
            "cumulative_categories": dict(self.cumulative_findings),
            "observed_cycles": self.cycle_number,
            "limitations": [
                "A conntrack table is a point-in-time population, not a packet or event capture.",
                "Source attribution can be ambiguous behind NAT or without local network boundaries.",
                "Scores are heuristic and are not calibrated probabilities of compromise.",
                "Per-source risk findings are based on one cycle; temporal statistics use recent cycles.",
            ],
        }

    def connection_histogram(self, values: list[int]) -> dict[str, int]:
        ranges = [(0, 0), (1, 1), (2, 4), (5, 9), (10, 24), (25, 49), (50, 99), (100, 249), (250, 999), (1000, None)]
        result = {}
        for low, high in ranges:
            label = f"{low}+" if high is None else f"{low}-{high}"
            result[label] = sum(value >= low and (high is None or value <= high) for value in values)
        return result

    def trends(self) -> dict[str, Any]:
        if not self.history:
            return {}
        connections = [record["connections"] for record in self.history]
        sources = [record["sources"] for record in self.history]
        findings = [record["findings"] for record in self.history]
        current = self.history[-1]
        previous = self.history[-2] if len(self.history) > 1 else None
        return {
            "samples": len(self.history),
            "connection_mean": round(statistics.fmean(connections), 4),
            "connection_stdev": round(statistics.pstdev(connections), 4),
            "connection_cv": round(coefficient_of_variation(connections), 6),
            "connection_quantiles": quantiles(connections),
            "source_mean": round(statistics.fmean(sources), 4),
            "finding_mean": round(statistics.fmean(findings), 4),
            "connection_delta": current["connections"] - previous["connections"] if previous else None,
            "source_delta": current["sources"] - previous["sources"] if previous else None,
            "finding_delta": current["findings"] - previous["findings"] if previous else None,
            "time_since_previous": round(current["timestamp"] - previous["timestamp"], 6) if previous else None,
        }

    def snapshot(self, cycle: Cycle, config: Config) -> dict[str, Any]:
        data = cycle.as_dict(config.top_n)
        profiles = cycle.intelligence.get("profiles", []) if cycle.intelligence else []
        findings = cycle.intelligence.get("findings", []) if cycle.intelligence else []
        fingerprint_source = json.dumps({"profiles": profiles, "findings": findings}, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        return {
            "format": "garden-warden-forensic-snapshot",
            "schema_version": 1,
            "application_version": APP_VERSION,
            "created_utc": iso_time(time.time()),
            "host": socket.gethostname(),
            "fingerprint_sha256": hashlib.sha256(fingerprint_source).hexdigest(),
            "cycle": data,
            "history": list(self.history),
            "configuration": {
                "local_networks": [str(network) for network in config.local_networks],
                "trusted_networks": [str(network) for network in config.trusted_networks],
                "include_private": config.include_private,
                "include_loopback": config.include_loopback,
                "family": config.family,
                "analysis_enabled": config.analysis_enabled,
                "enforce": config.enforce,
            },
        }


def load_snapshot(path: str, max_bytes: int) -> dict[str, Any]:
    target = Path(path)
    if not target.is_file():
        raise ValueError("snapshot must be a regular file")
    if target.stat().st_size > max_bytes:
        raise ValueError("snapshot exceeds maximum size")
    with target.open("r", encoding="utf-8") as stream:
        data = json.load(stream)
    if not isinstance(data, dict) or data.get("format") != "garden-warden-forensic-snapshot":
        raise ValueError("unsupported forensic snapshot")
    if data.get("schema_version") != 1:
        raise ValueError("unsupported snapshot schema")
    return data


def atomic_json_write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, ensure_ascii=False, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def compare_snapshots(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    old_cycle = previous.get("cycle", {})
    new_cycle = current.get("cycle", {})
    old_intelligence = old_cycle.get("intelligence") or {}
    new_intelligence = new_cycle.get("intelligence") or {}
    old_profiles = {item["ip"]: item for item in old_intelligence.get("profiles", []) if isinstance(item, dict) and "ip" in item}
    new_profiles = {item["ip"]: item for item in new_intelligence.get("profiles", []) if isinstance(item, dict) and "ip" in item}
    added = sorted(set(new_profiles) - set(old_profiles))
    removed = sorted(set(old_profiles) - set(new_profiles))
    common = sorted(set(old_profiles) & set(new_profiles))
    changes = []
    for ip in common:
        before = old_profiles[ip]
        after = new_profiles[ip]
        if before.get("connections") != after.get("connections") or before.get("risk_band") != after.get("risk_band"):
            changes.append({
                "ip": ip,
                "connections_before": before.get("connections"),
                "connections_after": after.get("connections"),
                "risk_before": before.get("risk_band"),
                "risk_after": after.get("risk_band"),
            })
    old_count = old_cycle.get("total_connections", 0)
    new_count = new_cycle.get("total_connections", 0)
    return {
        "changed": previous.get("fingerprint_sha256") != current.get("fingerprint_sha256"),
        "previous_fingerprint": previous.get("fingerprint_sha256"),
        "current_fingerprint": current.get("fingerprint_sha256"),
        "connection_delta": new_count - old_count,
        "added_sources": added,
        "removed_sources": removed,
        "changed_sources": changes,
        "comparison_is_profile_limited": len(old_profiles) >= 100 or len(new_profiles) >= 100,
    }


class CosmosRenderer:
    PALETTES = {
        "cosmos": {
            "title": "\033[1;38;5;141m",
            "heading": "\033[1;38;5;45m",
            "normal": "\033[38;5;153m",
            "muted": "\033[38;5;103m",
            "number": "\033[38;5;219m",
            "warning": "\033[1;38;5;214m",
            "critical": "\033[1;38;5;197m",
            "success": "\033[1;38;5;120m",
            "info": "\033[38;5;81m",
            "divider": "\033[38;5;60m",
        },
        "classic": {
            "title": "\033[1;36m",
            "heading": "\033[1;34m",
            "normal": "\033[0m",
            "muted": "\033[2m",
            "number": "\033[1;37m",
            "warning": "\033[1;33m",
            "critical": "\033[1;31m",
            "success": "\033[1;32m",
            "info": "\033[36m",
            "divider": "\033[2m",
        },
        "mono": {},
    }

    def __init__(self, config: Config) -> None:
        self.config = config
        self.palette = self.PALETTES[config.theme]
        self.enabled = config.theme != "mono" and (config.color == "always" or (config.color == "auto" and sys.stdout.isatty() and os.environ.get("NO_COLOR") is None))

    def paint(self, text: str, role: str) -> str:
        if not self.enabled:
            return text
        return f"{self.palette.get(role, '')}{text}\033[0m"

    def decorate(self, original: str, cycle: Cycle) -> str:
        lines = original.splitlines()
        result = []
        for index, line in enumerate(lines):
            if index == 0:
                result.append(self.paint(line, "title"))
            elif line.startswith("input:"):
                result.append(self.paint(line, "muted"))
            elif line.startswith("entries=") or line.startswith("sources="):
                result.append(self.paint(line, "info"))
            elif line.startswith("SOURCE"):
                result.append(self.paint(line, "heading"))
            elif line.startswith("---"):
                result.append(self.paint(line, "divider"))
            elif "CRITICAL" in line:
                result.append(self.paint(line, "critical"))
            elif "WARNING" in line:
                result.append(self.paint(line, "warning"))
            elif line.endswith(":"):
                result.append(self.paint(line, "heading"))
            elif line.strip():
                result.append(self.paint(line, "normal"))
            else:
                result.append(line)
        if cycle.intelligence:
            intelligence = cycle.intelligence
            summary = intelligence["summary"]
            result.append("")
            result.append(self.paint("NETWORK INTELLIGENCE", "title"))
            result.append(self.paint("=" * 72, "divider"))
            result.append(self.paint(f"Findings: {summary['finding_count']}   Critical: {summary['critical_findings']}   Warning: {summary['warning_findings']}", "info"))
            result.append(self.paint(f"Connection Gini: {summary['connection_gini']:.4f}   Largest source share: {summary['largest_source_fraction']:.4f}", "muted"))
            trends = intelligence.get("trends", {})
            if trends.get("connection_delta") is not None:
                result.append(self.paint(f"Connection delta: {trends['connection_delta']:+d}   Source delta: {trends['source_delta']:+d}", "number"))
            for finding in intelligence.get("findings", [])[:min(self.config.top_n, 25)]:
                severity = finding["severity"]
                role = "critical" if severity == "critical" else "warning" if severity == "warning" else "info"
                result.append(self.paint(f"{severity.upper():<8} {finding['source']:<39} {finding['category']}", role))
            result.append(self.paint("Findings are heuristic indicators; review evidence before acting.", "muted"))
        return "\n".join(result)


class HostContext:
    @staticmethod
    def read_integer(path: str) -> int | None:
        try:
            text = Path(path).read_text(encoding="ascii").strip()
            return int(text)
        except (OSError, ValueError):
            return None

    @staticmethod
    def conntrack_limits() -> dict[str, Any]:
        count = HostContext.read_integer("/proc/sys/net/netfilter/nf_conntrack_count")
        maximum = HostContext.read_integer("/proc/sys/net/netfilter/nf_conntrack_max")
        return {
            "current": count,
            "maximum": maximum,
            "utilization": round(safe_fraction(count, maximum), 6) if count is not None and maximum else None,
        }

    @staticmethod
    def kernel() -> dict[str, Any]:
        info = os.uname()
        return {
            "system": info.sysname,
            "release": info.release,
            "machine": info.machine,
            "hostname": info.nodename,
        }

    @staticmethod
    def uptime() -> float | None:
        try:
            text = Path("/proc/uptime").read_text(encoding="ascii").split()[0]
            return float(text)
        except (OSError, ValueError, IndexError):
            return None

    @staticmethod
    def summary() -> dict[str, Any]:
        return {
            "kernel": HostContext.kernel(),
            "uptime_seconds": HostContext.uptime(),
            "conntrack_table": HostContext.conntrack_limits(),
        }


class IntegrityInspector:
    @staticmethod
    def validate_snapshot(snapshot: dict[str, Any]) -> list[str]:
        problems = []
        if snapshot.get("format") != "garden-warden-forensic-snapshot":
            problems.append("unrecognized snapshot format")
        cycle = snapshot.get("cycle")
        if not isinstance(cycle, dict):
            problems.append("missing cycle payload")
            return problems
        if not isinstance(cycle.get("top_sources"), list):
            problems.append("top sources must be an array")
        if not isinstance(cycle.get("detections"), list):
            problems.append("detections must be an array")
        if not isinstance(cycle.get("parse"), dict):
            problems.append("parse statistics must be an object")
        intelligence = cycle.get("intelligence")
        if intelligence is not None and not isinstance(intelligence, dict):
            problems.append("intelligence must be an object or null")
        return problems

    @staticmethod
    def fingerprint_profiles(snapshot: dict[str, Any]) -> str:
        intelligence = snapshot.get("cycle", {}).get("intelligence") or {}
        payload = {
            "profiles": intelligence.get("profiles", []),
            "findings": intelligence.get("findings", []),
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        return hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def verify(snapshot: dict[str, Any]) -> dict[str, Any]:
        problems = IntegrityInspector.validate_snapshot(snapshot)
        expected = snapshot.get("fingerprint_sha256")
        actual = IntegrityInspector.fingerprint_profiles(snapshot)
        if expected != actual:
            problems.append("profile fingerprint mismatch")
        return {"valid": not problems, "problems": problems, "expected": expected, "actual": actual}


class ForensicExporter:
    @staticmethod
    def jsonl_findings(intelligence: dict[str, Any]) -> str:
        return "\n".join(json.dumps(item, ensure_ascii=False, separators=(",", ":")) for item in intelligence.get("findings", []))

    @staticmethod
    def csv_profiles(intelligence: dict[str, Any]) -> str:
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        columns = ("ip", "family", "connections", "destination_count", "destination_port_count", "syn_fraction", "unreplied_fraction", "port_entropy", "risk_score", "risk_band", "finding_count")
        writer.writerow(columns)
        for profile in intelligence.get("profiles", []):
            writer.writerow([profile.get(key, "") for key in columns])
        return output.getvalue()

    @staticmethod
    def text_findings(intelligence: dict[str, Any]) -> str:
        lines = []
        for finding in intelligence.get("findings", []):
            lines.append(f"{finding['severity'].upper():<8} {finding['source']:<39} {finding['title']}")
            lines.append(f"  {finding['description']}")
        return "\n".join(lines)


class SnapshotRepository:
    def __init__(self, directory: Path, max_bytes: int) -> None:
        self.directory = directory
        self.max_bytes = max_bytes

    def paths(self) -> list[Path]:
        if not self.directory.is_dir():
            return []
        return sorted((path for path in self.directory.glob("*.json") if path.is_file()), key=lambda path: path.name)

    def list_snapshots(self) -> list[dict[str, Any]]:
        result = []
        for path in self.paths():
            try:
                snapshot = load_snapshot(str(path), self.max_bytes)
                result.append({"path": str(path), "created_utc": snapshot.get("created_utc"), "fingerprint": snapshot.get("fingerprint_sha256"), "valid": IntegrityInspector.verify(snapshot)["valid"]})
            except (OSError, ValueError, json.JSONDecodeError):
                result.append({"path": str(path), "valid": False})
        return result

    def recent(self, limit: int = 10) -> list[dict[str, Any]]:
        return self.list_snapshots()[-limit:]

    def compare_latest(self) -> dict[str, Any] | None:
        paths = self.paths()
        if len(paths) < 2:
            return None
        old = load_snapshot(str(paths[-2]), self.max_bytes)
        new = load_snapshot(str(paths[-1]), self.max_bytes)
        return compare_snapshots(old, new)


class FlowStatistics:
    @staticmethod
    def summarize(snapshots: dict[str, SourceSnapshot]) -> dict[str, Any]:
        protocol_counts: collections.Counter[str] = collections.Counter()
        state_counts: collections.Counter[str] = collections.Counter()
        port_counts: collections.Counter[int] = collections.Counter()
        destination_counts: collections.Counter[str] = collections.Counter()
        timeout_values = []
        for source in snapshots.values():
            protocol_counts.update(source.protocols)
            state_counts.update(source.states)
            port_counts.update(source.port_counts)
            destination_counts.update(source.destination_counts)
            timeout_values.extend(source.timeouts)
        return {
            "protocols": dict(protocol_counts),
            "states": dict(state_counts),
            "top_ports": ranked_counter(port_counts, 20),
            "top_destinations": ranked_counter(destination_counts, 20),
            "timeout_quantiles": quantiles(timeout_values),
            "port_entropy": round(shannon_entropy(port_counts), 6),
            "destination_entropy": round(shannon_entropy(destination_counts), 6),
            "source_count": len(snapshots),
            "total_connections": sum(source.connections for source in snapshots.values()),
        }


class SamplingInspector:
    @staticmethod
    def analyze(history: Iterable[dict[str, Any]]) -> dict[str, Any]:
        records = list(history)
        intervals = [records[index]["timestamp"] - records[index - 1]["timestamp"] for index in range(1, len(records))]
        if not intervals:
            return {"samples": len(records), "intervals": 0, "irregular": False}
        mean = statistics.fmean(intervals)
        stdev = statistics.pstdev(intervals)
        cv = safe_fraction(stdev, mean)
        return {
            "samples": len(records),
            "intervals": len(intervals),
            "mean_seconds": round(mean, 6),
            "stdev_seconds": round(stdev, 6),
            "min_seconds": min(intervals),
            "max_seconds": max(intervals),
            "cv": round(cv, 6),
            "irregular": cv > 0.25,
            "interval_quantiles": quantiles(intervals),
        }


class AddressInspector:
    @staticmethod
    def classify(ip: str) -> dict[str, Any]:
        address = ipaddress.ip_address(ip)
        return {
            "address": str(address),
            "version": address.version,
            "global": address.is_global,
            "private": address.is_private,
            "loopback": address.is_loopback,
            "link_local": address.is_link_local,
            "multicast": address.is_multicast,
            "reserved": address.is_reserved,
            "unspecified": address.is_unspecified,
        }

    @staticmethod
    def summarize(ips: Iterable[str]) -> dict[str, Any]:
        counts: collections.Counter[str] = collections.Counter()
        for ip in ips:
            try:
                address = AddressInspector.classify(ip)
            except ValueError:
                counts["invalid"] += 1
                continue
            counts["ipv4" if address["version"] == 4 else "ipv6"] += 1
            for name in ("global", "private", "loopback", "link_local", "multicast", "reserved"):
                if address[name]:
                    counts[name] += 1
        return dict(counts)


class PortInspector:
    WELL_KNOWN = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 25: "smtp", 53: "dns",
        67: "dhcp-server", 68: "dhcp-client", 80: "http", 110: "pop3",
        123: "ntp", 143: "imap", 161: "snmp", 389: "ldap", 443: "https",
        445: "smb", 465: "smtps", 514: "syslog", 587: "submission",
        636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
        1521: "oracle-db", 2049: "nfs", 2375: "docker-api", 2376: "docker-tls",
        3306: "mysql", 3389: "rdp", 5432: "postgresql", 5672: "amqp",
        5900: "vnc", 6379: "redis", 6443: "kubernetes-api", 8080: "http-alt",
        8443: "https-alt", 9090: "prometheus", 9200: "elasticsearch",
        11211: "memcached", 27017: "mongodb",
    }

    @classmethod
    def label(cls, port: int) -> str:
        return cls.WELL_KNOWN.get(port, "unknown")

    @classmethod
    def annotate(cls, counter: collections.Counter[int], limit: int = 20) -> list[dict[str, Any]]:
        return [{"port": int(item["value"]), "service": cls.label(int(item["value"])), "count": item["count"]} for item in ranked_counter(counter, limit)]


class BaselineInspector:
    @staticmethod
    def summarize(baseline: SlidingBaseline) -> dict[str, Any]:
        states = baseline.states
        lengths = [len(state.history) for state in states.values()]
        ages = [max(0, time.time() - state.first_seen) for state in states.values()]
        detections = sum(state.detections for state in states.values())
        return {
            "tracked_sources": len(states),
            "total_detections": detections,
            "history_lengths": quantiles(lengths),
            "source_ages": quantiles(ages),
            "sources_with_full_history": sum(len(state.history) == baseline.config.history_size for state in states.values()),
            "sources_with_min_samples": sum(len(state.history) >= baseline.config.min_samples for state in states.values()),
        }


class DetectionInspector:
    @staticmethod
    def summarize(detections: Iterable[Detection]) -> dict[str, Any]:
        items = list(detections)
        severities: collections.Counter[str] = collections.Counter()
        reasons: collections.Counter[str] = collections.Counter()
        for item in items:
            severities[item.severity] += 1
            reasons[item.reason] += 1
        return {
            "total": len(items),
            "severities": dict(severities),
            "reasons": dict(reasons),
            "largest_counts": sorted((item.count for item in items), reverse=True)[:20],
            "source_ips": [item.ip for item in items[:100]],
        }


class RunMetadata:
    @staticmethod
    def collect(config: Config) -> dict[str, Any]:
        return {
            "app": APP_NAME,
            "version": APP_VERSION,
            "python": sys.version.split()[0],
            "pid": os.getpid(),
            "uid": os.getuid() if hasattr(os, "getuid") else None,
            "platform": sys.platform,
            "host": socket.gethostname(),
            "started_utc": iso_time(time.time()),
            "interval": config.interval,
            "history_size": config.history_size,
            "min_samples": config.min_samples,
            "max_sources": config.max_sources,
            "source": config.source,
            "enforcement_enabled": config.enforce,
            "theme": config.theme,
        }


class ReportComposer:
    @staticmethod
    def assemble(cycle: Cycle, config: Config, baseline: SlidingBaseline, engine: IntelligenceEngine) -> dict[str, Any]:
        return {
            "metadata": RunMetadata.collect(config),
            "host": HostContext.summary(),
            "cycle": cycle.as_dict(config.top_n),
            "flow_statistics": FlowStatistics.summarize(cycle.sources),
            "address_statistics": AddressInspector.summarize(cycle.sources),
            "baseline": BaselineInspector.summarize(baseline),
            "detections": DetectionInspector.summarize(cycle.detections),
            "sampling": SamplingInspector.analyze(engine.history),
        }


class StateHealth:
    @staticmethod
    def check(baseline: SlidingBaseline) -> dict[str, Any]:
        problems = []
        now = time.time()
        for ip, state in baseline.states.items():
            if state.first_seen > now + 60:
                problems.append({"ip": ip, "problem": "first_seen in future"})
            if state.last_seen < state.first_seen:
                problems.append({"ip": ip, "problem": "last_seen precedes first_seen"})
            if len(state.history) > baseline.config.history_size:
                problems.append({"ip": ip, "problem": "history exceeds configured capacity"})
            if any(value < 0 for value in state.history):
                problems.append({"ip": ip, "problem": "negative connection count"})
            if len(problems) >= 100:
                break
        return {"healthy": not problems, "problems": problems, "checked_sources": len(baseline.states)}


class RecommendationEngine:
    @staticmethod
    def recommend(intelligence: dict[str, Any]) -> list[dict[str, str]]:
        findings = intelligence.get("findings", [])
        categories = {finding["category"] for finding in findings}
        suggestions = []
        if "syn-concentration" in categories:
            suggestions.append({"topic": "tcp", "action": "Review SYN backlog metrics, application listeners, and upstream firewall counters."})
        if "port-fanout" in categories or "sparse-port-distribution" in categories:
            suggestions.append({"topic": "reconnaissance", "action": "Correlate broad port targeting with firewall logs and authorized network discovery activity."})
        if "destination-fanout" in categories:
            suggestions.append({"topic": "destination", "action": "Check whether fanout originates from a proxy, scanner, container host, or orchestration component."})
        if "unreplied" in categories:
            suggestions.append({"topic": "network", "action": "Inspect routing, firewall policy, and application availability for flows lacking replies."})
        if "volume" in categories:
            suggestions.append({"topic": "capacity", "action": "Compare tracked connection volume with conntrack table utilization and normal workload peaks."})
        if not suggestions:
            suggestions.append({"topic": "baseline", "action": "Continue sampling to establish a representative baseline across workload cycles."})
        return suggestions


class SchemaInspector:
    @staticmethod
    def snapshot_schema() -> dict[str, Any]:
        return {
            "name": "garden-warden-forensic-snapshot",
            "version": 1,
            "required": ["format", "schema_version", "fingerprint_sha256", "cycle"],
            "cycle_required": ["timestamp", "parse", "top_sources", "detections", "enforcements"],
            "intelligence_fields": ["summary", "trends", "profiles", "findings", "limitations"],
            "fingerprint_scope": "canonical JSON of retained profiles and findings",
            "comparison_scope": "retained profiles and aggregate connection count",
        }


class NumericSafety:
    @staticmethod
    def finite(value: Any, default: float = 0.0) -> float:
        try:
            result = float(value)
        except (ValueError, TypeError, OverflowError):
            return default
        return result if math.isfinite(result) else default

    @staticmethod
    def bounded(value: Any, low: float, high: float) -> float:
        return max(low, min(high, NumericSafety.finite(value, low)))

    @staticmethod
    def integer(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return default


class TimelineInspector:
    @staticmethod
    def events(history: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        records = list(history)
        output = []
        for index, record in enumerate(records):
            previous = records[index - 1] if index else None
            output.append({
                "timestamp": record["timestamp"],
                "timestamp_iso": iso_time(record["timestamp"]),
                "connections": record["connections"],
                "sources": record["sources"],
                "findings": record["findings"],
                "connections_delta": record["connections"] - previous["connections"] if previous else None,
                "sources_delta": record["sources"] - previous["sources"] if previous else None,
            })
        return output


class SeverityInspector:
    ORDER = {"critical": 0, "high": 1, "warning": 2, "moderate": 3, "info": 4, "informational": 5}

    @classmethod
    def sort_findings(cls, findings: Iterable[Finding]) -> list[Finding]:
        return sorted(findings, key=lambda item: (cls.ORDER.get(item.severity, 9), item.source, item.category))

    @classmethod
    def counts(cls, findings: Iterable[Finding]) -> dict[str, int]:
        return dict(collections.Counter(finding.severity for finding in findings))


class ProtocolInspector:
    @staticmethod
    def summarize(snapshots: dict[str, SourceSnapshot]) -> dict[str, Any]:
        by_protocol: collections.Counter[str] = collections.Counter()
        by_state: collections.Counter[str] = collections.Counter()
        by_protocol_state: collections.Counter[str] = collections.Counter()
        for source in snapshots.values():
            by_protocol.update(source.protocols)
            by_state.update(source.states)
            by_protocol_state.update(source.flows)
        total = sum(by_protocol.values())
        return {
            "total": total,
            "by_protocol": dict(by_protocol),
            "by_state": dict(by_state),
            "by_protocol_state": dict(by_protocol_state),
            "protocol_fractions": {key: round(safe_fraction(value, total), 6) for key, value in by_protocol.items()},
            "protocol_entropy": round(shannon_entropy(by_protocol), 6),
            "state_entropy": round(shannon_entropy(by_state), 6),
        }


class AttributionInspector:
    @staticmethod
    def explain(entry: ConntrackEntry, config: Config) -> dict[str, Any]:
        attribution = Attribution(config)
        source = entry.original_src
        destination = entry.original_dst
        return {
            "source": str(source),
            "destination": str(destination),
            "eligible": attribution.eligible(entry),
            "source_is_local": belongs(source, config.local_networks),
            "destination_is_local": belongs(destination, config.local_networks),
            "source_is_trusted": belongs(source, config.trusted_networks),
            "direction_confident": bool(config.local_networks),
            "enforcement_safe": attribution.safe_to_enforce(source)[0],
            "enforcement_reason": attribution.safe_to_enforce(source)[1],
        }


class ForensicStatistics:
    @staticmethod
    def correlations(history: Iterable[dict[str, Any]]) -> dict[str, Any]:
        records = list(history)
        if len(records) < 3:
            return {"samples": len(records), "connection_source_correlation": None}
        connections = [record["connections"] for record in records]
        sources = [record["sources"] for record in records]
        sx = statistics.pstdev(connections)
        sy = statistics.pstdev(sources)
        if sx == 0 or sy == 0:
            correlation = None
        else:
            mx = statistics.fmean(connections)
            my = statistics.fmean(sources)
            covariance = statistics.fmean((x - mx) * (y - my) for x, y in zip(connections, sources))
            correlation = round(covariance / (sx * sy), 6)
        return {"samples": len(records), "connection_source_correlation": correlation}


class HealthSummary:
    @staticmethod
    def compile(cycle: Cycle, engine: IntelligenceEngine, baseline: SlidingBaseline) -> dict[str, Any]:
        intelligence = cycle.intelligence or {}
        summary = intelligence.get("summary", {})
        table = HostContext.conntrack_limits()
        utilization = table.get("utilization")
        issues = []
        if utilization is not None and utilization >= 0.9:
            issues.append("conntrack table utilization is at least 90 percent")
        if cycle.parse.malformed_lines:
            issues.append("some conntrack records could not be parsed")
        if summary.get("critical_findings", 0):
            issues.append("critical heuristic findings require review")
        if cycle.parse.ambiguous_entries:
            issues.append("source attribution is ambiguous without local-network boundaries")
        return {
            "status": "review" if issues else "ok",
            "issues": issues,
            "conntrack_table": table,
            "baseline": BaselineInspector.summarize(baseline),
            "sampling": SamplingInspector.analyze(engine.history),
        }


class ReportFormatter:
    @staticmethod
    def summary_lines(cycle: Cycle, engine: IntelligenceEngine, baseline: SlidingBaseline) -> list[str]:
        health = HealthSummary.compile(cycle, engine, baseline)
        lines = [f"Health status: {health['status']}"]
        for issue in health["issues"]:
            lines.append(f"  - {issue}")
        table = health["conntrack_table"]
        if table["current"] is not None:
            lines.append(f"Conntrack entries: {table['current']} / {table['maximum']}")
        return lines


class EvidenceBuilder:
    @staticmethod
    def source_evidence(profile: SourceProfile) -> dict[str, Any]:
        return {
            "ip": profile.ip,
            "family": profile.family,
            "connections": profile.connections,
            "protocols": profile.protocols,
            "states": profile.states,
            "top_ports": profile.common_ports,
            "top_destinations": profile.common_destinations,
            "entropy": {"ports": profile.port_entropy, "destinations": profile.destination_entropy},
            "risk": {"score": profile.risk_score, "band": profile.risk_band},
        }


class SnapshotAudit:
    @staticmethod
    def audit(path: str, max_bytes: int = 32 * 1024 * 1024) -> dict[str, Any]:
        snapshot = load_snapshot(path, max_bytes)
        verification = IntegrityInspector.verify(snapshot)
        return {
            "path": path,
            "verification": verification,
            "created_utc": snapshot.get("created_utc"),
            "host": snapshot.get("host"),
            "schema_version": snapshot.get("schema_version"),
            "connections": snapshot.get("cycle", {}).get("total_connections"),
        }


class ResourceBudget:
    @staticmethod
    def estimate(config: Config) -> dict[str, Any]:
        return {
            "max_input_bytes": config.max_bytes,
            "max_input_lines": config.max_lines,
            "max_input_line_bytes": config.max_line_size,
            "max_tracked_sources": config.max_sources,
            "baseline_history_slots": config.max_sources * config.history_size,
            "max_retained_profiles": config.profile_limit,
            "max_history_cycles": config.snapshot_history,
            "max_snapshot_bytes": config.max_snapshot_bytes,
            "command_timeout_seconds": config.max_command_seconds,
            "note": "These are configured limits, not a strict upper bound on process RSS.",
        }


class Diagnostics:
    @staticmethod
    def inspect(config: Config) -> dict[str, Any]:
        return {
            "host": HostContext.summary(),
            "resource_budget": ResourceBudget.estimate(config),
            "runtime": RunMetadata.collect(config),
            "schema": SchemaInspector.snapshot_schema(),
            "source_paths": list(InputSource.PROC_PATHS),
            "conntrack_executable": shutil.which(config.conntrack_command),
            "ipset_executable": shutil.which(config.ipset_path),
        }

if __name__ == "__main__":
    raise SystemExit(main())
