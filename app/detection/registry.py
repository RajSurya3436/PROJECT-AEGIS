from __future__ import annotations

from app.detection.auth_rules import (
    DistributedBruteForce,
    FailuresThenSuccess,
    PasswordSpray,
    RepeatedFailedLogins,
    SuccessFromIocAddress,
)
from app.detection.base import Rule
from app.detection.endpoint_rules import (
    AccountManipulation,
    CredentialDumping,
    DiscoveryBurst,
    InhibitSystemRecovery,
    LogClearing,
    LolbinAbuse,
    OfficeSpawnsShell,
    PersistenceCreated,
)
from app.detection.network_rules import (
    LargeOutboundTransfer,
    LateralMovementFanOut,
    LocalIocConnection,
    PortScan,
    SuspiciousPortConnection,
)
from app.detection.process_rules import SuspiciousPowerShell
from app.detection.siem_rules import SiemHighSeverityAlert

# Display names for Rule.category, in kill-chain order (the UI groups rules by these).
CATEGORIES: dict[str, str] = {
    "initial_access": "Initial access",
    "execution": "Execution",
    "persistence": "Persistence",
    "defense_evasion": "Defense evasion",
    "credential_access": "Credential access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral movement",
    "command_and_control": "Command and control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "siem": "Upstream SIEM",
    "other": "Other",
}


def default_rules() -> list[Rule]:
    return [
        # authentication
        RepeatedFailedLogins(),
        FailuresThenSuccess(),
        PasswordSpray(),
        DistributedBruteForce(),
        SuccessFromIocAddress(),
        # endpoint
        SuspiciousPowerShell(),
        OfficeSpawnsShell(),
        CredentialDumping(),
        DiscoveryBurst(),
        PersistenceCreated(),
        AccountManipulation(),
        LolbinAbuse(),
        LogClearing(),
        InhibitSystemRecovery(),
        # network
        LocalIocConnection(),
        PortScan(),
        LateralMovementFanOut(),
        SuspiciousPortConnection(),
        LargeOutboundTransfer(),
        # upstream SIEM
        SiemHighSeverityAlert(),
    ]
