"""Load the private lab dotenv file without executing shell commands."""
from pathlib import Path
from dotenv import load_dotenv


def load_lab_env(path=None):
    # Explicit process environment overrides local defaults. No ${...} expansion.
    location = Path(path) if path else Path(__file__).resolve().parent / '.env'
    return load_dotenv(location, override=False, interpolate=False)
