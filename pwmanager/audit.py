"""Vault security audit and health score."""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, TYPE_CHECKING

from pwmanager.colors import C
from pwmanager.constants import OLD_PASSWORD_DAYS, WEAK_ENTROPY_BITS
from pwmanager.generators import password_entropy_bits

if TYPE_CHECKING:
    from pwmanager.models import Entry
    from pwmanager.vault import Vault


@dataclass
class AuditReport:
    """Structured audit findings (never includes actual passwords)."""

    total_entries: int = 0
    reused_groups: List[List[str]] = field(default_factory=list)  # groups of names
    weak: List[str] = field(default_factory=list)  # name list
    old: List[str] = field(default_factory=list)
    missing_totp: List[str] = field(default_factory=list)  # has url, no totp
    empty_usernames: List[str] = field(default_factory=list)
    health_score: int = 100

    @property
    def reused_count(self) -> int:
        return sum(len(g) for g in self.reused_groups)

    @property
    def issue_count(self) -> int:
        return (
            self.reused_count
            + len(self.weak)
            + len(self.old)
            + len(self.missing_totp)
            + len(self.empty_usernames)
        )


def audit_vault(vault: "Vault") -> AuditReport:
    """Analyze an unlocked vault for common security issues."""
    report = AuditReport(total_entries=len(vault.entries))
    if not vault.entries:
        report.health_score = 100
        return report

    # Reused passwords: group by password value, never expose the password itself
    by_pw: Dict[str, List[str]] = defaultdict(list)
    now = time.time()
    old_cutoff = OLD_PASSWORD_DAYS * 24 * 3600

    for name, entry in vault.entries.items():
        if entry.password:
            by_pw[entry.password].append(name)

        bits = password_entropy_bits(entry.password)
        if bits < WEAK_ENTROPY_BITS:
            report.weak.append(name)

        # Old: no update timestamp treated as old, or updated_at > 365 days
        updated = entry.updated_at or entry.created_at or 0
        if updated == 0 or (now - updated) > old_cutoff:
            report.old.append(name)

        if entry.url and not entry.totp_secret:
            report.missing_totp.append(name)

        if not (entry.username or "").strip():
            report.empty_usernames.append(name)

    for names in by_pw.values():
        if len(names) > 1:
            report.reused_groups.append(sorted(names))

    report.weak.sort()
    report.old.sort()
    report.missing_totp.sort()
    report.empty_usernames.sort()
    report.health_score = compute_health_score(report)
    return report


def compute_health_score(report: AuditReport) -> int:
    """Overall 0–100 health score from audit findings."""
    if report.total_entries == 0:
        return 100

    n = report.total_entries
    # Weighted deductions (capped so score stays in range)
    score = 100.0

    # Reused passwords are severe
    reused_ratio = report.reused_count / n
    score -= reused_ratio * 40

    # Weak passwords
    weak_ratio = len(report.weak) / n
    score -= weak_ratio * 30

    # Old passwords
    old_ratio = len(report.old) / n
    score -= old_ratio * 15

    # Missing TOTP (hint-level — lighter penalty)
    totp_ratio = len(report.missing_totp) / n
    score -= totp_ratio * 10

    # Empty usernames
    empty_ratio = len(report.empty_usernames) / n
    score -= empty_ratio * 5

    return max(0, min(100, int(round(score))))


def health_score_color(score: int) -> str:
    """Colorized health score string."""
    label = f"{score}/100"
    if score >= 80:
        return C.green(label)
    if score >= 50:
        return C.yellow(label)
    return C.red(label)


def format_audit_report(report: AuditReport) -> str:
    """Rich-ish colorized audit report. Never prints actual passwords."""
    lines: List[str] = []
    lines.append("")
    lines.append(C.bold(C.cyan("=== Vault Security Audit ===")))
    lines.append(C.dim(f"Entries: {report.total_entries}"))
    lines.append(
        f"Health score: {health_score_color(report.health_score)}"
    )
    lines.append("")

    def section(title: str, count: int, names: List[str], hint: str = "") -> None:
        color = C.red if count else C.green
        status = color(f"{count}")
        lines.append(f"{C.bold(title)}: {status}")
        if hint and count:
            lines.append(C.dim(f"  {hint}"))
        for name in names:
            lines.append(f"  • {name}")
        if not names and count == 0:
            lines.append(C.dim("  (none)"))
        lines.append("")

    # Reused: show groups
    reused_n = report.reused_count
    color = C.red if reused_n else C.green
    lines.append(f"{C.bold('Reused passwords')}: {color(str(reused_n))} entries")
    if report.reused_groups:
        lines.append(C.dim("  Same password shared across these entry groups:"))
        for group in report.reused_groups:
            lines.append(f"  • {', '.join(group)}")
    else:
        lines.append(C.dim("  (none)"))
    lines.append("")

    section(
        "Weak passwords",
        len(report.weak),
        report.weak,
        f"Entropy below {int(WEAK_ENTROPY_BITS)} bits — consider regenerating.",
    )
    section(
        "Old passwords",
        len(report.old),
        report.old,
        f"Not updated in over {OLD_PASSWORD_DAYS} days (or never).",
    )
    section(
        "Missing TOTP (hint)",
        len(report.missing_totp),
        report.missing_totp,
        "Entries with a URL but no TOTP secret — enable 2FA where possible.",
    )
    section(
        "Empty usernames",
        len(report.empty_usernames),
        report.empty_usernames,
        "No username/email stored for these entries.",
    )

    if report.issue_count == 0:
        lines.append(C.green("No issues found. Vault looks healthy."))
    else:
        lines.append(
            C.yellow(
                f"Found {report.issue_count} issue(s). Review and fix when you can."
            )
        )
    lines.append("")
    return "\n".join(lines)


def print_audit_report(report: AuditReport) -> None:
    print(format_audit_report(report))
