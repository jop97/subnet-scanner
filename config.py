import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "subnet-scanner-secret-key-change-me")
    MAX_THREADS = int(os.environ.get("MAX_THREADS", 100))
    PING_TIMEOUT = int(os.environ.get("PING_TIMEOUT", 1))
    NMAP_TIMEOUT = int(os.environ.get("NMAP_TIMEOUT", 30))
