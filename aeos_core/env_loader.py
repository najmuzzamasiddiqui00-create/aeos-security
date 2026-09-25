import os
from pathlib import Path

def load_env(env_path: str = None):
    """
    Zero-dependency robust .env loader.
    Loads key-value pairs into os.environ if not already present.
    """
    if env_path is None:
        # Default to repo root .env
        root_dir = Path(__file__).resolve().parent.parent
        env_path = root_dir / ".env"
    else:
        env_path = Path(env_path)

    if not env_path.exists():
        return

    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip("'\"")
                if key not in os.environ:
                    os.environ[key] = val
    except Exception:
        pass

# Automatically load upon import
load_env()
