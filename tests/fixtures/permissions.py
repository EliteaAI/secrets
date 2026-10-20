"""The effective roles of a permission registration, as the auth plugin computes them.

``auth.register_permissions`` parses the dict through ``Permissions`` / ``ModeRoles``, whose fields default to true
for ``system``, ``super_admin`` and ``admin``: a role that a registration leaves out is granted. Tests therefore
look at the parsed model, not at the dict that was passed. The model is loaded from the sibling ``auth`` plugin
(found by walking up from this checkout, so it also works from a git worktree).
"""
import importlib.util
from pathlib import Path

import pytest

_RELATIVE = Path("auth") / "models" / "pd" / "permissions.py"


def _model_file():
    for parent in Path(__file__).resolve().parents:
        for candidate in (parent / _RELATIVE, parent / "plugins" / _RELATIVE):
            if candidate.is_file():
                return candidate
    return None


def effective_roles(recommended_roles):
    """``{mode: {role: bool}}`` for every role the auth plugin knows, after its defaults are applied."""
    path = _model_file()
    if path is None:
        pytest.skip("the auth plugin's Permissions model is not next to this checkout")
    spec = importlib.util.spec_from_file_location("auth_permissions_model", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    parsed = module.Permissions.parse_obj({"permissions": ["x"], "recommended_roles": recommended_roles})
    return {mode: dict(roles) for mode, roles in parsed.recommended_roles.dict().items()}
