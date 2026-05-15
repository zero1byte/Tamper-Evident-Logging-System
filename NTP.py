import ntplib
from time import ctime
from datetime import datetime


def NTP() -> str:
    """Fetch an ISO-8601 timestamp from NTP; fall back to local time.

    Attempts to contact time.google.com via NTP protocol. If NTP is unavailable
    (offline, network issues, etc.), falls back to system time.

    Returns:
        ISO-8601 formatted timestamp string (YYYY-MM-DDTHH:MM:SS).
    """
    try:
        client = ntplib.NTPClient()
        response = client.request("time.google.com", version=3)
        date_format = "%a %b %d %H:%M:%S %Y"
        timestamp = datetime.strptime(ctime(response.tx_time), date_format).strftime("%Y-%m-%dT%H:%M:%S")
        return timestamp
    except Exception:
        # Fallback to local system time if NTP fails
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")