import json
import re

from .constants import CONFIG_FILE, DATA_DIR, MODEL_DEFAULTS, MODEL_NAME, MODEL_PROFILE_ALIASES, MODEL_PROFILES


def default_config() -> dict:
    return {
        "models": dict(MODEL_DEFAULTS)
    }


def load_config() -> dict:
    config = default_config()

    if not CONFIG_FILE.exists():
        return config

    try:
        raw_config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return config

    if not isinstance(raw_config, dict):
        return config

    raw_models = raw_config.get("models", {})

    if isinstance(raw_models, dict):
        for profile in MODEL_PROFILES:
            model_name = raw_models.get(profile)

            if isinstance(model_name, str) and model_name.strip():
                config["models"][profile] = model_name.strip()

    return config


def save_config(config: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def normalize_model_profile(profile: str) -> str | None:
    return MODEL_PROFILE_ALIASES.get(profile.lower().strip())


def validate_model_name(model_name: str) -> bool:
    return bool(re.match(r"^[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,127}$", model_name))


def configured_model(profile: str) -> str:
    clean_profile = normalize_model_profile(profile) or profile
    return str(load_config()["models"].get(clean_profile, MODEL_NAME))
