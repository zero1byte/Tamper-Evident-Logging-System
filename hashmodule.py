import hashlib

from typing import Optional



class hashUtils:
    def __init__(self):
        pass

    @staticmethod
    def _normalize_description(description: str) -> str:
        # Keep backward compatibility with existing hashes: remove spaces.
        # (If you want stronger semantics, we can introduce a v2 format later.)
        return str(description).strip().replace(" ", "")
    
    def create(self, previousHash: Optional[str], logObj) -> str:
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
        res = self.create(previousHash, logObj).strip()
        return res == str(getattr(logObj, "hash", "")).strip()
            