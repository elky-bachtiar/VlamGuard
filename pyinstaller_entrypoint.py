"""PyInstaller entry-point shim for VlamGuard CLI."""
from vlamguard.cli import app

if __name__ == "__main__":
    app()
