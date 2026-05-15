import os
import stat
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

LOGS_TYPES = ["app", "sys", "auth"]
ROOT_DIR_NAME = "logStorage"
MAX_LOG_FILE_SIZE = 100 * 1024 * 1024  # 100MB
FILE_TYPE = "log"

FIRST_RANDOM_HASH="dc249ec444585efba16c603b4f3bc06f175141e54dcdebb798e78d81470f699e"

from NTP import NTP

def getPath() -> str:
    """Return the absolute path to the log storage directory.

    Uses the project directory (this file's directory) instead of the process CWD,
    so running from other folders doesn't accidentally create logs elsewhere.
    """

    storage_dir = Path(__file__).resolve().parent / ROOT_DIR_NAME
    storage_dir.mkdir(parents=True, exist_ok=True)
    return str(storage_dir)


@dataclass(frozen=True)
class log:
    """Immutable log entry in the tamper-evident chain.

    Attributes:
        timestamp: ISO-8601 timestamp when the event occurred.
        type: Log type ('auth', 'sys', 'app').
        description: Human-readable description of the event.
        hash: SHA-256 hash linking to the previous entry.
    """

    timestamp: str
    type: str
    description: str
    hash: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "timestamp", self.timestamp.strip())
        object.__setattr__(self, "type", self.type.strip())
        object.__setattr__(self, "description", self.description.strip())
        object.__setattr__(self, "hash", self.hash.strip())
        
    def __iter__(self):
        return iter([
            self.timestamp,
            self.type,
            self.description,
            self.hash
        ])
        
    @staticmethod
    def _unquote_description(description: str) -> str:
        desc = description.strip()
        if len(desc) >= 2 and ((desc[0] == "'" and desc[-1] == "'") or (desc[0] == '"' and desc[-1] == '"')):
            desc = desc[1:-1]
        return desc.strip()

    @classmethod
    def fromStr(cls, stringLog: str) -> "log":
        """Parse one legacy log line.

        Format: <timestamp> <type> <hash> <description>
        Description is usually single-quoted.
        """

        logParts = stringLog.rstrip("\n").split(" ", 3)
        if len(logParts) < 4:
            raise ValueError(f"Invalid log format: {stringLog!r}")

        timestamp = logParts[0].strip()
        log_type = logParts[1].strip()
        hash_value = logParts[2].strip()
        description_raw = logParts[3].strip()

        return cls(
            timestamp=timestamp,
            type=log_type,
            description=cls._unquote_description(description_raw),
            hash=hash_value,
        )

    def toStr(self, *, quote_description: bool = True) -> str:
        """Serialize the log entry to a single-line format suitable for storage.

        Args:
            quote_description: If True, wrap description in single quotes.

        Returns:
            Formatted log line with trailing newline.
        """
        desc = self.description
        if quote_description:
            desc = f"'{desc}'"
        return f"{self.timestamp} {self.type} {self.hash} {desc}\n"
        
        
    def view(self) -> None:
        """Print the log entry in a human-readable format."""
        print(f"Timestamp : {self.timestamp}")
        print(f"Type : {self.type}")
        print(f"Hash : {self.hash}")
        print(f"Description : {self.description}")


class StorageFiles:
    """Manage log file storage, rotation, and initialization.

    Args:
        path: Directory to store log files (defaults to ./logStorage/).
        logType: Log category ('auth', 'sys', 'app').
    """

    def __init__(self, path: Optional[str] = None, logType: str = "sys") -> None:
        self.path = path if path is not None else getPath()
        self.logtype = logType

    def getLogFilePath(self) -> Optional[str]:
        """Get or initialize the log file for this type.

        Handles:
        - Validating the log type
        - Rotating the file if it exceeds MAX_LOG_FILE_SIZE
        - Creating a fresh file with genesis entry if missing

        Returns:
            Absolute path to the log file, or None if type is invalid.
        """
        if self.logtype not in LOGS_TYPES:
            print(f"Invalid log type: {self.logtype}")
            print(f"Valid log types: {LOGS_TYPES}")
            return None
        filePath = os.path.join(self.path, f"{self.logtype}.{FILE_TYPE}")

        # Rotate if file grows too large.
        if os.path.exists(filePath):
            try:
                if os.path.getsize(filePath) >= MAX_LOG_FILE_SIZE:
                    suffix = datetime.now().strftime("%Y%m%dT%H%M%S")
                    rotated = f"{filePath}.{suffix}"
                    os.replace(filePath, rotated)
            except OSError:
                # Best-effort rotation; if it fails, keep using the same file.
                pass

        # Initialize file with genesis entry if missing.
        if not os.path.exists(filePath):
            with open(filePath, "a", encoding="utf-8") as file:
                file.write(f"{NTP()} {self.logtype} {FIRST_RANDOM_HASH} 'Log file created'\n")

            # Best-effort permissions: os.chmod has limited effect on Windows.
            if os.name != "nt":
                os.chmod(filePath, stat.S_IRUSR | stat.S_IWUSR)

        return filePath
    