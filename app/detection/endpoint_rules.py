"""Endpoint rules over process events: fixed tables of named, documented patterns matched against
the process name, parent process and command line. Matches by one user on one host are grouped
into sessions, one alert per session."""

from __future__ import annotations

import ntpath
import re
from collections.abc import Sequence
from typing import ClassVar

from app.detection.base import DetectionContext, Rule, fmt_ts, qualifying_runs, sessions
from app.domain.enums import EventType, Severity
from app.domain.models import NormalizedEvent
from app.storage.alerts import Finding
from app.storage.repositories import EventFilters


def image_name(value: str | None) -> str:
    """Lower-case file name of a process path, Windows or POSIX ("C:\\x\\A.EXE" -> "a.exe")."""
    if not value:
        return ""
    return ntpath.basename(value.strip().strip('"')).rsplit("/", 1)[-1].lower()


def _rx(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


def _process_history(ctx: DetectionContext, host: str) -> list[NormalizedEvent]:
    return ctx.events.query(EventFilters(equals={"event_type": EventType.PROCESS, "host": host}))


class IndicatorRule(Rule):
    """Base for rules that flag single process events by named indicators."""

    default_config: ClassVar[dict[str, int]] = {"min_indicators": 1, "session_gap_seconds": 900}
    config_help: ClassVar[dict[str, str]] = {
        "min_indicators": "Distinct indicator types one event needs",
        "session_gap_seconds": "Matches on one host/user closer than this share an alert",
    }
    patterns: ClassVar[dict[str, re.Pattern[str]]] = {}
    alert_noun: ClassVar[str] = "suspicious activity"

    def indicators(self, event: NormalizedEvent) -> list[str]:
        if event.event_type is not EventType.PROCESS:
            return []
        text = " ".join(filter(None, (event.process_name, event.command_line)))
        if not text:
            return []
        return [name for name, pattern in self.patterns.items() if pattern.search(text)]

    def evaluate(
        self, new_events: Sequence[NormalizedEvent], ctx: DetectionContext, config: dict[str, int]
    ) -> list[Finding]:
        needed = self.setting(config, "min_indicators")
        gap = self.setting(config, "session_gap_seconds")
        scopes = sorted(
            {
                (e.host, e.user or "")
                for e in new_events
                if e.host and len(self.indicators(e)) >= needed
            }
        )
        findings: list[Finding] = []
        for host, user in scopes:
            history = _process_history(ctx, host)
            hits: dict[str, list[str]] = {}
            for e in history:
                names = self.indicators(e) if (e.user or "") == user else []
                if len(names) >= needed:
                    hits[e.event_id] = names
            matched = [e for e in history if e.event_id in hits]
            for group in sessions(matched, gap):
                names = sorted({n for e in group for n in hits[e.event_id]})
                who = f" as {user}" if user else ""
                findings.append(
                    self.finding(
                        key_parts=[host, user],
                        title=f"{self.alert_noun[0].upper()}{self.alert_noun[1:]} on {host}{who}",
                        explanation=(
                            f"{len(group)} process event(s) on {host}{who} between "
                            f"{fmt_ts(group[0].event_time)} and {fmt_ts(group[-1].event_time)} "
                            f"matched: {', '.join(names)}. Rule: {self.title.lower()}, at least "
                            f"{needed} indicator type(s) per event."
                        ),
                        matched=[(e, "indicators: " + ", ".join(hits[e.event_id])) for e in group],
                    )
                )
        return findings


class CredentialDumping(IndicatorRule):
    rule_id: ClassVar[str] = "process.credential_dumping"
    category: ClassVar[str] = "credential_access"
    mitre: ClassVar[tuple[str, ...]] = ("T1003.001", "T1003.002", "T1003.003")
    version: ClassVar[int] = 1
    title: ClassVar[str] = "Credential dumping tool or technique"
    description: ClassVar[str] = (
        "Mimikatz-style commands, LSASS memory dumps (procdump, comsvcs MiniDump), saving the "
        "SAM/SECURITY/SYSTEM hives, or copying the AD database with ntdsutil."
    )
    severity: ClassVar[Severity] = Severity.CRITICAL
    alert_noun: ClassVar[str] = "credential dumping"
    patterns: ClassVar[dict[str, re.Pattern[str]]] = {
        "mimikatz": _rx(r"\bmimikatz\b|sekurlsa::|lsadump::|kerberos::(?:golden|ptt)"),
        "lsass dump": _rx(r"\b(?:procdump(?:64)?(?:\.exe)?\b.*\blsass|minidump\b.*\blsass)"),
        "comsvcs minidump": _rx(r"comsvcs(?:\.dll)?[,\s]+#?(?:minidump|24)\b"),
        "registry hive save": _rx(r"\breg(?:\.exe)?\s+save\s+\S*hklm\\(?:sam|security|system)\b"),
        "ntds copy": _rx(r"\bntdsutil\b.*\b(?:ifm|ac\s+i\s+ntds)\b|\\ntds\.dit\b"),
    }


class InhibitSystemRecovery(IndicatorRule):
    rule_id: ClassVar[str] = "process.inhibit_recovery"
    category: ClassVar[str] = "impact"
    mitre: ClassVar[tuple[str, ...]] = ("T1490",)
    version: ClassVar[int] = 1
    title: ClassVar[str] = "Backup or recovery deletion"
    description: ClassVar[str] = (
        "Deleting shadow copies or backup catalogs, or disabling Windows recovery: a common "
        "step right before ransomware encrypts files."
    )
    severity: ClassVar[Severity] = Severity.CRITICAL
    alert_noun: ClassVar[str] = "recovery inhibition"
    patterns: ClassVar[dict[str, re.Pattern[str]]] = {
        "shadow copy deletion": _rx(
            r"\bvssadmin(?:\.exe)?\s+(?:delete\s+shadows|resize\s+shadowstorage)"
            r"|\bshadowcopy\s+delete\b|win32_shadowcopy.*\b(?:delete|remove-(?:wmi|cim)object)"
        ),
        "backup catalog deletion": _rx(r"\bwbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstate)"),
        "recovery disabled": _rx(
            r"\bbcdedit(?:\.exe)?\b.*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)"
        ),
    }


class LogClearing(IndicatorRule):
    rule_id: ClassVar[str] = "process.log_clearing"
    category: ClassVar[str] = "defense_evasion"
    mitre: ClassVar[tuple[str, ...]] = ("T1070.001", "T1070.003")
    version: ClassVar[int] = 1
    title: ClassVar[str] = "Event log or history clearing"
    description: ClassVar[str] = (
        "Clearing Windows event logs (wevtutil cl, Clear-EventLog), deleting system log files "
        "on Linux, or wiping shell history: attackers covering their tracks."
    )
    severity: ClassVar[Severity] = Severity.HIGH
    alert_noun: ClassVar[str] = "log clearing"
    patterns: ClassVar[dict[str, re.Pattern[str]]] = {
        "wevtutil clear": _rx(r"\bwevtutil(?:\.exe)?\s+(?:cl|clear-log)\b"),
        "powershell clear log": _rx(r"\b(?:clear-eventlog|remove-eventlog)\b"),
        "linux log wipe": _rx(
            r"\b(?:rm|shred|truncate)\b[^|;&]*/var/log/|>\s*/var/log/(?:auth|secure|syslog)"
        ),
        "shell history wipe": _rx(r"\bhistory\s+-c\b|\bunset\s+histfile\b|>\s*\S*bash_history"),
    }


class LolbinAbuse(IndicatorRule):
    rule_id: ClassVar[str] = "process.lolbin_abuse"
    category: ClassVar[str] = "defense_evasion"
    mitre: ClassVar[tuple[str, ...]] = ("T1218", "T1105", "T1140")
    version: ClassVar[int] = 1
    title: ClassVar[str] = "Living-off-the-land binary abuse"
    description: ClassVar[str] = (
        "Built-in Windows binaries used to download or run remote code: certutil -urlcache or "
        "-decode, bitsadmin /transfer, mshta with a URL or script, regsvr32 scriptlets, "
        "rundll32 with JavaScript, msiexec installing from a URL."
    )
    severity: ClassVar[Severity] = Severity.HIGH
    alert_noun: ClassVar[str] = "LOLBin abuse"
    patterns: ClassVar[dict[str, re.Pattern[str]]] = {
        "certutil download/decode": _rx(r"\bcertutil(?:\.exe)?\b.*[-/](?:urlcache|decode)\b"),
        "bitsadmin transfer": _rx(r"\bbitsadmin(?:\.exe)?\b.*/(?:transfer|addfile)\b"),
        "mshta remote/script": _rx(r"\bmshta(?:\.exe)?\b.*(?:https?://|javascript:|vbscript:)"),
        "regsvr32 scriptlet": _rx(r"\bregsvr32(?:\.exe)?\b.*/i:\s*\S*(?:https?://|\.sct)"),
        "rundll32 script": _rx(r"\brundll32(?:\.exe)?\b.*(?:javascript:|runhtmlapplication)"),
        "msiexec remote": _rx(r"\bmsiexec(?:\.exe)?\b.*/[iq]\S*\s+\S*https?://"),
    }


class PersistenceCreated(IndicatorRule):
    rule_id: ClassVar[str] = "process.persistence"
    category: ClassVar[str] = "persistence"
    mitre: ClassVar[tuple[str, ...]] = ("T1053.005", "T1547.001", "T1543.003", "T1053.003")
    version: ClassVar[int] = 1
    title: ClassVar[str] = "Persistence mechanism created"
    description: ClassVar[str] = (
        "A scheduled task, Run/RunOnce registry key, new service or cron entry created from the "
        "command line. Installers do this too, so severity is medium; check the parent process."
    )
    severity: ClassVar[Severity] = Severity.MEDIUM
    alert_noun: ClassVar[str] = "persistence created"
    patterns: ClassVar[dict[str, re.Pattern[str]]] = {
        "scheduled task": _rx(r"\bschtasks(?:\.exe)?\s+/create\b|\bregister-scheduledtask\b"),
        "run key": _rx(
            r"\b(?:reg(?:\.exe)?\s+add|set-itemproperty|new-itemproperty)\b.*"
            r"\\currentversion\\run(?:once)?\b"
        ),
        "new service": _rx(r"\bsc(?:\.exe)?\s+(?:create|config\s+\S+\s+binpath=)|\bnew-service\b"),
        "cron entry": _rx(r"\|\s*crontab\s+-\s*$|>>?\s*/etc/cron"),
    }


class AccountManipulation(IndicatorRule):
    rule_id: ClassVar[str] = "process.account_manipulation"
    category: ClassVar[str] = "persistence"
    mitre: ClassVar[tuple[str, ...]] = ("T1136.001", "T1098")
    version: ClassVar[int] = 1
    title: ClassVar[str] = "Local account created or added to admins"
    description: ClassVar[str] = (
        "A local user created, or a user added to the Administrators, Remote Desktop Users, "
        "sudo or wheel group, from the command line."
    )
    severity: ClassVar[Severity] = Severity.HIGH
    alert_noun: ClassVar[str] = "account manipulation"
    patterns: ClassVar[dict[str, re.Pattern[str]]] = {
        "user created": _rx(
            r"\bnet1?(?:\.exe)?\s+user\s+\S+.*\s/add\b|\bnew-localuser\b|\b(?:useradd|adduser)\s"
        ),
        "added to privileged group": _rx(
            r"\bnet1?(?:\.exe)?\s+localgroup\s+\"?(?:administrators|remote desktop users)\"?"
            r"\s+\S+.*\s/add\b|\badd-localgroupmember\b.*\b(?:administrators|remote desktop)"
            r"|\busermod\b.*-a?G\s*\S*\b(?:sudo|wheel|admin)\b"
        ),
    }


OFFICE_APPS = frozenset(
    {
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
        "msaccess.exe",
        "mspub.exe",
        "onenote.exe",
        "visio.exe",
    }
)
SCRIPT_CHILDREN = frozenset(
    {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "msbuild.exe",
        "installutil.exe",
        "wmic.exe",
    }
)


class OfficeSpawnsShell(IndicatorRule):
    rule_id: ClassVar[str] = "process.office_child_shell"
    category: ClassVar[str] = "initial_access"
    mitre: ClassVar[tuple[str, ...]] = ("T1566.001", "T1204.002")
    version: ClassVar[int] = 1
    title: ClassVar[str] = "Office application started a shell or script host"
    description: ClassVar[str] = (
        "Word, Excel, Outlook or another Office app is the parent of cmd, PowerShell, a script "
        "host or a LOLBin: the usual sign of a malicious macro or attachment. Needs the "
        "parent_process field."
    )
    severity: ClassVar[Severity] = Severity.HIGH
    alert_noun: ClassVar[str] = "Office app spawned a shell"

    def indicators(self, event: NormalizedEvent) -> list[str]:
        if event.event_type is not EventType.PROCESS:
            return []
        parent, child = image_name(event.parent_process), image_name(event.process_name)
        if parent in OFFICE_APPS and child in SCRIPT_CHILDREN:
            return [f"{parent} -> {child}"]
        return []


# Discovery commands. Each is its own indicator, so the rule counts *different* commands.
DISCOVERY: dict[str, re.Pattern[str]] = {
    "whoami": _rx(r"\bwhoami\b"),
    "net user/group": _rx(r"\bnet1?(?:\.exe)?\s+(?:user|group|localgroup|accounts)\b(?!.*/add)"),
    "net view/share": _rx(r"\bnet1?(?:\.exe)?\s+(?:view|share|session)\b"),
    "nltest": _rx(r"\bnltest\b"),
    "domain query": _rx(r"\b(?:dsquery|adfind|get-ad(?:user|group|computer|domain))\b"),
    "systeminfo": _rx(r"\bsysteminfo\b"),
    "ipconfig/ifconfig": _rx(r"\b(?:ipconfig|ifconfig)\b"),
    "network connections": _rx(r"\b(?:netstat|arp\s+-a|route\s+print)\b"),
    "logged-on users": _rx(r"\b(?:quser|query\s+user|qwinsta)\b"),
    "process list": _rx(r"\btasklist\b"),
}


class DiscoveryBurst(Rule):
    rule_id: ClassVar[str] = "process.discovery_burst"
    category: ClassVar[str] = "discovery"
    mitre: ClassVar[tuple[str, ...]] = ("T1087", "T1069", "T1082", "T1016", "T1033")
    version: ClassVar[int] = 1
    title: ClassVar[str] = "Burst of discovery commands"
    description: ClassVar[str] = (
        "Several different reconnaissance commands (whoami, net user/group, nltest, systeminfo, "
        "ipconfig, ...) by one user on one host in a short time. Admins run these one at a "
        "time; an intruder getting their bearings runs many together."
    )
    severity: ClassVar[Severity] = Severity.MEDIUM
    default_config: ClassVar[dict[str, int]] = {"distinct_commands": 3, "window_seconds": 600}
    config_help: ClassVar[dict[str, str]] = {
        "distinct_commands": "Different discovery commands needed to alert",
        "window_seconds": "Window the commands must fall in (inclusive)",
    }

    @staticmethod
    def commands(event: NormalizedEvent) -> list[str]:
        if event.event_type is not EventType.PROCESS or not event.command_line:
            return []
        return [name for name, rx in DISCOVERY.items() if rx.search(event.command_line)]

    def evaluate(
        self, new_events: Sequence[NormalizedEvent], ctx: DetectionContext, config: dict[str, int]
    ) -> list[Finding]:
        needed = self.setting(config, "distinct_commands")
        window = self.setting(config, "window_seconds")
        scopes = sorted({(e.host, e.user or "") for e in new_events if e.host and self.commands(e)})
        findings: list[Finding] = []
        for host, user in scopes:
            history = _process_history(ctx, host)
            hits: dict[str, list[str]] = {}
            for e in history:
                names = self.commands(e) if (e.user or "") == user else []
                if names:
                    hits[e.event_id] = names
            events = [e for e in history if e.event_id in hits]

            def enough(window_events: Sequence[NormalizedEvent], hits=hits) -> bool:
                return len({n for e in window_events for n in hits[e.event_id]}) >= needed

            for run in qualifying_runs(events, window, enough):
                names = sorted({n for e in run for n in hits[e.event_id]})
                who = f" as {user}" if user else ""
                findings.append(
                    self.finding(
                        key_parts=[host, user],
                        title=f"{len(names)} discovery commands on {host}{who}",
                        explanation=(
                            f"{len(run)} discovery command(s) on {host}{who} between "
                            f"{fmt_ts(run[0].event_time)} and {fmt_ts(run[-1].event_time)}: "
                            f"{', '.join(names)}. Rule: at least {needed} different discovery "
                            f"commands within {window}s."
                        ),
                        matched=[(e, "discovery: " + ", ".join(hits[e.event_id])) for e in run],
                    )
                )
        return findings
