import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "subnet-scanner-secret-key-change-me")
    MAX_THREADS = int(os.environ.get("MAX_THREADS", 100))
    PING_TIMEOUT = int(os.environ.get("PING_TIMEOUT", 1))
    NMAP_TIMEOUT = int(os.environ.get("NMAP_TIMEOUT", 30))
    DEFAULT_NMAP_ARGS = os.environ.get("DEFAULT_NMAP_ARGS", "-sV -sC -O --top-ports 100")
