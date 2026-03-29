import enum

class LogLevel(str, enum.Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

class AlertSeverity(str, enum.Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

class AlertStatus(str, enum.Enum):
    OPEN            = "OPEN"
    ACKNOWLEDGED    = "ACKNOWLEDGED"
    RESOLVED        = "RESOLVED"
    FALSE_POSITIVE  = "FALSE_POSITIVE"