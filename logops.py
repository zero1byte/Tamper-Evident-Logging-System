
import argparse
import os
import sys
from typing import Optional

from hashmodule import hashUtils
from logs_storage import FIRST_RANDOM_HASH, StorageFiles, log
from NTP import NTP


class logops:
    """Manage tamper-evident log operations: insert, view, and verify integrity.

    Args:
        logObject: An existing log entry to operate on (provides type and description).
        type: Log type ('auth', 'sys', 'app'). Required if logObject is None.

    Raises:
        ValueError: If neither logObject nor type is provided.
    """

    def __init__(self, logObject: Optional[log] = None, type: Optional[str] = None):
        if logObject is None and type is None:
            raise ValueError("Either logObject or type must be provided.")

        self.type = logObject.type if type is None else type
        self.current_log: Optional[log] = logObject
        self.logFileClass = StorageFiles(logType=self.type)
        self.logfilepath = self.logFileClass.getLogFilePath()
        self.hashLibrary = hashUtils()
    
    def islogfileexists(self) -> bool:
        """Check if the log file exists on disk."""
        return os.path.exists(self.logfilepath)
        
        
    def previousLog(self) -> Optional[log]:
        """Retrieve the last log entry in the file, or None if file is empty/missing.

        Returns:
            The last log entry, or None if not found.
        """
        if not self.islogfileexists():
            return None

        try:
            last_line = ""
            with open(self.logfilepath, "r", encoding="utf-8") as f:
                for last_line in f:
                    pass
            if last_line.strip():
                return log.fromStr(last_line)
            return None
        except FileNotFoundError:
            return None
        
    def insert(self) -> bool:
        """Insert the current log entry, computing its hash from the previous entry.

        The hash is computed as SHA-256(previous_hash + timestamp + type + description).

        Returns:
            True on success.

        Raises:
            ValueError: If no logObject was provided to __init__.
            FileNotFoundError: If the log file doesn't exist.
        """
        if self.current_log is None:
            raise ValueError("insert() requires a logObject")

        if not self.islogfileexists():
            raise FileNotFoundError("Log file does not exist.")

        last_log = self.previousLog()
        previous_hash = last_log.hash if last_log is not None else FIRST_RANDOM_HASH

        current_hash = self.hashLibrary.create(previous_hash, self.current_log)
        to_write = log(
            timestamp=self.current_log.timestamp,
            type=self.current_log.type,
            hash=current_hash,
            description=self.current_log.description,
        )

        with open(self.logfilepath, "a", encoding="utf-8") as file:
            file.write(to_write.toStr(quote_description=True))
        return True

    def append(self, description: str, timestamp: Optional[str] = None) -> bool:
        """Create a new log entry and insert it (convenience method).

        Args:
            description: What happened (e.g., "unauthorized access").
            timestamp: ISO-8601 timestamp (optional; uses NTP if None).

        Returns:
            True on success.
        """
        ts = timestamp if timestamp is not None else str(NTP())
        entry = log(timestamp=ts, type=self.type, description=description, hash=FIRST_RANDOM_HASH)
        self.current_log = entry
        return self.insert()
        
    def view(self) -> bool:
        """Display all log entries in a human-readable format.

        Returns:
            True on success.

        Raises:
            FileNotFoundError: If the log file doesn't exist.
        """
        if not self.islogfileexists():
            raise FileNotFoundError("Log file does not exist.")

        with open(self.logfilepath, "r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue
                logObj = log.fromStr(line)
                logObj.view()
        return True
        
    def checkIntegrity(self) -> bool:
        """Verify the integrity of the log chain by recomputing all hashes.

        Detects tampering by checking that each entry's hash is consistent with
        its predecessor. Returns False if any entry is compromised.

        Returns:
            True if all logs are intact, False if tampering is detected.

        Raises:
            FileNotFoundError: If the log file doesn't exist.
        """
        if not self.islogfileexists():
            raise FileNotFoundError("Log file does not exist.")

        with open(self.logfilepath, "r", encoding="utf-8") as file:
            previous_log = None
            for line in file:
                if not line.strip():
                    continue

                logObj = log.fromStr(line)
                if previous_log is not None:
                    if not self.hashLibrary.verifyHash(previous_log.hash, logObj):
                        print("Log integrity compromised at log:", logObj.timestamp)
                        return False
                else:
                    # Sanity check for the first line
                    if logObj.hash != FIRST_RANDOM_HASH:
                        print("Unexpected first hash; chain may be invalid")

                previous_log = logObj

        print("All logs are intact.")
        return True


def _build_cli() -> argparse.ArgumentParser:
    """Build the command-line argument parser.

    Returns:
        Configured ArgumentParser with subcommands: insert, view, check.
    """
    parser = argparse.ArgumentParser(
        description="Tamper-evident log operations",
        epilog="Example: python logops.py insert --type auth --desc 'user login'",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_insert = sub.add_parser("insert", help="Append a new log entry")
    p_insert.add_argument("--type", required=True, choices=["app", "sys", "auth"], help="Log type")
    p_insert.add_argument("--desc", required=True, help="Log description")

    p_view = sub.add_parser("view", help="View logs")
    p_view.add_argument("--type", required=True, choices=["app", "sys", "auth"], help="Log type")

    p_check = sub.add_parser("check", help="Verify log integrity")
    p_check.add_argument("--type", required=True, choices=["app", "sys", "auth"], help="Log type")

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """Main entry point for the CLI.

    Args:
        argv: Command-line arguments (defaults to sys.argv[1:]).

    Returns:
        Exit code: 0 on success, 2 on integrity failure or error.
    """
    parser = _build_cli()
    try:
        args = parser.parse_args(argv)
    except SystemExit:
        return 2

    try:
        if args.cmd == "insert":
            logops(type=args.type).append(args.desc)
            return 0
        elif args.cmd == "view":
            logops(type=args.type).view()
            return 0
        elif args.cmd == "check":
            ok = logops(type=args.type).checkIntegrity()
            return 0 if ok else 2
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    raise SystemExit(main())