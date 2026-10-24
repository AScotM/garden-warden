#!/usr/bin/env python3
from __future__ import annotations

import argparse
import collections
import dataclasses
import datetime
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
APP_VERSION = "0.2.0"
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


@dataclasses.dataclass(slots=True)
class SourceSnapshot:
    ip: str
    family: str
    connections: int = 0
    protocols: collections.Counter[str] = dataclasses.field(default_factory=collections.Counter)
    states: collections.Counter[str] = dataclasses.field(default_factory=collections.Counter)
    destinations: set[str] = dataclasses.field(default_factory=set)
    ports: set[int] = dataclasses.field(default_factory=set)

    def add(self, entry: ConntrackEntry) -> None:
        self.connections += 1
        self.protocols[entry.protocol] += 1
        self.states[entry.state] += 1
        self.destinations.add(str(entry.original_dst))
        if entry.original_dport is not None:
            self.ports.add(entry.original_dport)

    def as_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "family": self.family,
            "connections": self.connections,
            "protocols": dict(self.protocols),
            "states": dict(self.states),
            "unique_destinations": len(self.destinations),
            "unique_destination_ports": len(self.ports),
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
        for token in parts[:7]:
            if token.isdigit():
                candidate = int(token)
                if candidate > 0:
                    timeout = candidate
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
            if not all(isinstance(v, int) and 0 <= v <= 10**9 for v in values):
                continue
            restored[key] = SourceState(
                history=collections.deque(values[-self.config.history_size:], maxlen=self.config.history_size),
                first_seen=float(item.get("first_seen", 0)),
                last_seen=float(item.get("last_seen", 0)),
                last_alert=float(item.get("last_alert", 0)),
                last_enforced=float(item.get("last_enforced", 0)),
                detections=int(item.get("detections", 0)),
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
        )

    def emit(self, cycle: Cycle) -> None:
        result = (
            Renderer.json(cycle, self.config)
            if self.config.json_output
            else Renderer.text(cycle, self.config)
        )
        print(result, flush=True)

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
    return parser


def validate(config: Config) -> None:
    positive = (
        "interval", "history_size", "min_samples", "zscore_warn", "zscore_crit",
        "count_warn", "count_crit", "ratio_warn", "ratio_crit", "absolute_delta",
        "expire_seconds", "cooldown_seconds", "top_n", "max_sources", "max_bytes",
        "max_lines", "max_line_size", "ipset_timeout", "max_enforcements",
        "max_command_seconds",
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


if __name__ == "__main__":
    raise SystemExit(main())
