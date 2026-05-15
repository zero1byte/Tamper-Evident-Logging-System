import ntplib
from time import ctime
from datetime import datetime

def NTP() -> str:
    """Return an ISO-8601 timestamp from NTP; fall back to local time."""

    try:
        client = ntplib.NTPClient()
        response = client.request("time.google.com", version=3)
        date_format = "%a %b %d %H:%M:%S %Y"
        timestamp = datetime.strptime(ctime(response.tx_time), date_format).strftime("%Y-%m-%dT%H:%M:%S")
        return timestamp
    except Exception:
        return datetime.now().strftime("%Y-%m-%dT%H:%M:%S")