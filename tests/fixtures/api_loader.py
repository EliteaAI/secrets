"""
Loads the secrets plugin's API modules as real modules for testing.

The plugin package is registered under the alias `secretsplugin` rather than `secrets`
because the latter shadows the stdlib `secrets` module for anything else on sys.path.
Relative imports inside the loaded files resolve against that alias.
"""
import importlib.util
import sys
import types
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parent.parent.parent
ALIAS = "secretsplugin"


def _load_file_as_module(name, path, package):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    module.__package__ = package
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def load_api_module(module_name):
    """Load `api/v2/<module_name>.py`, wiring up the fake parent packages on first call."""
    full_name = f"{ALIAS}.api.v2.{module_name}"
    cached = sys.modules.get(full_name)
    if cached is not None:
        return cached

    for name, subpath in (
        (ALIAS, PLUGIN_ROOT),
        (f"{ALIAS}.pd", PLUGIN_ROOT / "pd"),
        (f"{ALIAS}.api", PLUGIN_ROOT / "api"),
        (f"{ALIAS}.api.v2", PLUGIN_ROOT / "api" / "v2"),
    ):
        if name not in sys.modules:
            package = types.ModuleType(name)
            package.__path__ = [str(subpath)]
            sys.modules[name] = package

    if f"{ALIAS}.pd.secrets" not in sys.modules:
        _load_file_as_module(
            f"{ALIAS}.pd.secrets", PLUGIN_ROOT / "pd" / "secrets.py",
            package=f"{ALIAS}.pd",
        )

    return _load_file_as_module(
        full_name, PLUGIN_ROOT / "api" / "v2" / f"{module_name}.py",
        package=f"{ALIAS}.api.v2",
    )
