from __future__ import annotations

from app.detection.auth_rules import FailuresThenSuccess, PasswordSpray, RepeatedFailedLogins
from app.detection.base import Rule
from app.detection.network_rules import LocalIocConnection
from app.detection.process_rules import SuspiciousPowerShell


def default_rules() -> list[Rule]:
    return [
        RepeatedFailedLogins(),
        FailuresThenSuccess(),
        PasswordSpray(),
        SuspiciousPowerShell(),
        LocalIocConnection(),
    ]
