import pytest
import sqlalchemy as sa

from geonature.utils.env import db
from geonature.core.gn_permissions.models import Permission
from geonature.core.gn_commons.models import TModules

from pypnusershub.db.models import User

from gn_module_permrequests.models import PermissionRequest


@pytest.fixture
def modules() -> dict[str, TModules]:
    modules = {}
    with db.session.begin_nested():
        for label in ["a", "b"]:
            modules[label] = TModules(
                module_code=label.upper(),
                module_label=label,
                module_path=label,
                active_frontend=False,
                active_backend=False,
            )
            db.session.add(modules[label])
    return modules


@pytest.fixture
def requests(actions, modules, users) -> dict[str, PermissionRequest]:
    reqs: dict[str, PermissionRequest] = {}
    with db.session.begin_nested():
        reqs["r1"] = PermissionRequest(
            permission=Permission(
                role=users["user"],
                action=actions["C"],
                module=modules["a"],
                validated=sa.null(),
            )
        )
        db.session.add(reqs["r1"])
        reqs["r2"] = PermissionRequest(
            permission=Permission(
                role=users["self_user"],
                action=actions["C"],
                module=modules["a"],
                validated=sa.null(),
            )
        )
        db.session.add(reqs["r2"])
        reqs["r3"] = PermissionRequest(
            permission=Permission(
                role=users["stranger_user"],
                action=actions["C"],
                module=modules["a"],
                validated=sa.null(),
            )
        )
        db.session.add(reqs["r3"])
    return reqs
