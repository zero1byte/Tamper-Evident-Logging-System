
import argparse
import os
import sys
from typing import Optional

from hashmodule import hashUtils
from logs_storage import FIRST_RANDOM_HASH, StorageFiles, log
from NTP import NTP

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False


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
        
    def view(self, format_type: str = "text") -> bool:
        """Display all log entries in a human-readable format.

        Args:
            format_type: Output format ('text' or 'table'). Default is 'text'.

        Returns:
            True on success.

        Raises:
            FileNotFoundError: If the log file doesn't exist.
        """
        if not self.islogfileexists():
            raise FileNotFoundError("Log file does not exist.")

        logs = []
        with open(self.logfilepath, "r", encoding="utf-8") as file:
            for line in file:
                if not line.strip():
                    continue
                logs.append(log.fromStr(line))

        if format_type == "table":
            self._view_as_table(logs)
        else:
            for logObj in logs:
                logObj.view()

        return True

    def _view_as_table(self, logs: list) -> None:
        """Display logs as a formatted table.

        Args:
            logs: List of log entries to display.
        """
        if not logs:
            print("No logs found.")
            return

        if HAS_TABULATE:
            # Create table with full hash visible
            headers = ["#", "Timestamp", "Type", "Hash (first 16 chars)", "Description"]
            rows = []
            for idx, log_entry in enumerate(logs, 1):
                rows.append([
                    idx,
                    log_entry.timestamp,
                    log_entry.type,
                    log_entry.hash[:16] + "...",
                    log_entry.description
                ])
            print(tabulate(rows, headers=headers, tablefmt="grid"))
        else:
            # Fallback to simple text table if tabulate is not available
            print("\n" + "="*120)
            print(f"{'#':<3} | {'Timestamp':<20} | {'Type':<6} | {'Hash (first 16)':<18} | Description")
            print("="*120)
            for idx, log_entry in enumerate(logs, 1):
                print(f"{idx:<3} | {log_entry.timestamp:<20} | {log_entry.type:<6} | {log_entry.hash[:16]:<18} | {log_entry.description}")
            print("="*120 + "\n")
        
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
    p_view.add_argument("--format", choices=["text", "table"], default="text", help="Output format (default: text)")

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
            logops(type=args.type).view(format_type=args.format)
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