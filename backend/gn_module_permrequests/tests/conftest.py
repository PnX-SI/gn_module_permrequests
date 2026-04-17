import pytest
from sqlalchemy import select

from geonature.tests.fixtures import *
from geonature.tests.fixtures import _session, app, _app, users
from geonature.tests.test_permissions import g_permissions
from geonature.utils.env import db
from geonature.core.gn_commons.models import TModules
from geonature.core.gn_permissions.models import PermAction, PermObject, Permission

from gn_module_permission_request import MODULE_CODE, MODULE_LABEL, MODULE_PICTO


@pytest.fixture(scope="session", autouse=True)
def ensure_permission_request_module(app, users):
    """Ensure the module record and baseline permissions exist for tests."""
    module = db.session.scalar(select(TModules).filter_by(module_code=MODULE_CODE))
    if module is None:
        with db.session.begin_nested():
            module = TModules(
                module_code=MODULE_CODE,
                module_label=MODULE_LABEL,
                module_path=MODULE_CODE.lower(),
                module_picto=MODULE_PICTO,
                active_frontend=True,
                active_backend=True,
                ng_module=MODULE_CODE.lower(),
            )
            db.session.add(module)
        module = db.session.scalar(select(TModules).filter_by(module_code=MODULE_CODE))

    actions = {
        code: db.session.scalar(select(PermAction).filter_by(code_action=code)) for code in "CRUDV"
    }
    object_all = db.session.scalar(select(PermObject).filter_by(code_object="ALL"))

    target_permissions = {
        "admin_user": {"actions": "CRUDV", "scope": None},
        "self_user": {"actions": "R", "scope": 1},
    }

    with db.session.begin_nested():
        for username, config in target_permissions.items():
            user = users.get(username)
            if user is None:
                continue
            for action_code in config["actions"]:
                action = actions.get(action_code)
                if action is None or object_all is None:
                    continue
                exists = db.session.scalar(
                    select(Permission).where(
                        Permission.id_role == user.id_role,
                        Permission.id_module == module.id_module,
                        Permission.id_action == action.id_action,
                        Permission.id_object == object_all.id_object,
                    )
                )
                if exists is None:
                    permission = Permission(
                        id_role=user.id_role,
                        id_module=module.id_module,
                        id_action=action.id_action,
                        id_object=object_all.id_object,
                        scope_value=config["scope"],
                    )
                    db.session.add(permission)

    return module
