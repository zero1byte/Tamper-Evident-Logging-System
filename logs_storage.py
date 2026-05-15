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
    timestamp: str
    type: str
    description: str
    hash: str

    def __post_init__(self):
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
        desc = self.description
        if quote_description:
            desc = f"'{desc}'"
        return f"{self.timestamp} {self.type} {self.hash} {desc}\n"
        
        
    def view(self):
        print(f"Timestamp : {self.timestamp}")
        print(f"Type : {self.type}")
        print(f"Hash : {self.hash}")
        print(f"Description : {self.description}")


class StorageFiles:
    def __init__(self, path: Optional[str] = None, logType: str = "sys"):
        self.path = path if path is not None else getPath()
        self.logtype = logType
    
    #check if log categories if exists and return file path
    def getLogFilePath(self):
        if(self.logtype not in LOGS_TYPES):
            print(f"Invalid log type : {self.logtype}")
            print("Valid Logs Types : ",LOGS_TYPES)
            return
        filePath = os.path.join(self.path, self.logtype + "." + FILE_TYPE)

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

        # Check if first log file exists
        if(not os.path.exists(filePath)):
            with open(filePath,'+a') as file:
                file.write(f"{NTP()} {self.logtype} {FIRST_RANDOM_HASH} 'Log file created'\n")

            # Best-effort permissions: os.chmod is limited on Windows.
            if os.name != "nt":
                os.chmod(filePath, stat.S_IRUSR | stat.S_IWUSR)
        return filePath
    