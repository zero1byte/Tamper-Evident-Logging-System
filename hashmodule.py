import hashlib

from typing import Optional


class hashUtils:
    """Compute and verify SHA-256 hash chains for tamper detection."""

    def __init__(self) -> None:
        pass

    @staticmethod
    def _normalize_description(description: str) -> str:
        """Normalize description by removing spaces for consistent hashing.

        Backward-compatible with existing hashes that were computed this way.
        """
        return str(description).strip().replace(" ", "")
    
    def create(self, previousHash: Optional[str], logObj) -> str:
        """Compute the SHA-256 hash for a log entry.

        The hash is computed as:
            SHA-256(previousHash + timestamp + type + normalized_description)

        Args:
            previousHash: SHA-256 hash of the previous log entry.
            logObj: The log entry to hash.

        Returns:
            Hexadecimal SHA-256 hash string.

        Raises:
            ValueError: If previousHash is None or empty.
        """
        if not previousHash:
            raise ValueError("previousHash must be provided")

        data = (
            str(previousHash)
            + str(logObj.timestamp)
            + str(logObj.type)
            + self._normalize_description(getattr(logObj, "description", ""))
        )

        current_hash = hashlib.sha256(data=data.encode()).hexdigest()
        return current_hash
    
    def verifyHash(self, previousHash: str, logObj) -> bool:
        """Verify that a log entry's hash is consistent with its predecessor.

        Recomputes the hash and compares it to the stored hash.

        Args:
            previousHash: SHA-256 hash of the previous log entry.
            logObj: The log entry to verify.

        Returns:
            True if the hash is valid, False otherwise.
        """
        res = self.create(previousHash, logObj).strip()
        return res == str(getattr(logObj, "hash", "")).strip()
            