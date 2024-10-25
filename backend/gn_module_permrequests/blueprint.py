from datetime import datetime
from flask import Blueprint, request, g
from geonature.tests.fixtures import perm_object
import sqlalchemy as sa
from sqlalchemy.orm import joinedload
from marshmallow import Schema, fields
from werkzeug.exceptions import BadRequest, Forbidden, NotFound, Conflict

from geonature.utils.env import db, ma
from geonature.utils.config import config
from geonature.core.gn_commons.models import TModules
from geonature.core.gn_permissions.models import PermAction, PermObject, Permission
from geonature.core.gn_permissions.decorators import check_cruved_scope
from geonature.core.notifications.utils import dispatch_notifications

from pypnusershub.db.models import User

from gn_module_permrequests import MODULE_CODE
from gn_module_permrequests.models import PermissionRequest
from gn_module_permrequests.schemas import PermissionRequestSchema


blueprint: Blueprint = Blueprint(name="permissions_requests", import_name=__name__)


writable_fields = [
    "extras",
    "permission.id_role",
    "permission.id_action",
    "permission.id_module",
    "permission.id_object",
    "permission.expire_on",
    "permission.scope_value",
    "permission.sensitivity_filter",
    "permission.areas_filter.id_area",
    "permission.taxons_filter.cd_nom",
]

dump_schema = PermissionRequestSchema(
    only=[
        "permission",
        "permission.role",
        "permission.action",
        "permission.module",
        "permission.object",
        "permission.expire_on",
        "permission.validated",
        "permission.scope_value",
        "permission.sensitivity_filter",
        "permission.areas_filter",
        "permission.taxons_filter",
    ],
)

select_stmt = sa.select(PermissionRequest).options(
    joinedload(PermissionRequest.permission).options(
        joinedload(Permission.role),
        joinedload(Permission.action),
        joinedload(Permission.module),
        joinedload(Permission.object),
    )
)


@blueprint.route(rule="/", methods=["GET"])
@check_cruved_scope(action="R", module_code=MODULE_CODE, get_scope=True)
def list_requests(scope):
    requests = db.session.scalars(select_stmt.where(PermissionRequest.filter_by_scope(scope))).all()
    return dump_schema.dump(requests, many=True)


@blueprint.route(rule="/", methods=["PUT"])
@check_cruved_scope(action="C", module_code=MODULE_CODE, get_scope=True)
def create_request(scope):
    schema = PermissionRequestSchema(only=writable_fields)
    perm_req = schema.load(
        request.json,
        partial=("permission.id_role",),  # facultative, default to g.current_user
        session=db.session,
    )
    perm_req.permission.validated = sa.null()  # force NULL instead of db default value
    if perm_req.permission.id_role is None:
        perm_req.permission.id_role = g.current_user.id_role
    # we call db.session() to get the current session because enable_relationship_loading methods
    # is not correctly proxied by scoped_session
    db.session().enable_relationship_loading(perm_req.permission)
    if not perm_req.permission.role:
        raise BadRequest("Role not found")
    if not perm_req.has_instance_permission(scope):
        raise Forbidden("You can not create permission request for this user")
    if not perm_req.permission.action:
        raise BadRequest("Action not found")
    if not perm_req.permission.module:
        raise BadRequest("Module not found")
    if not perm_req.permission.object:
        raise BadRequest("object not found")
    db.session.add(perm_req)
    db.session.commit()
    dispatch_notifications(
        code_categories=["PERMISSIONS-REQUESTS-CREATED%"],
        id_roles=config[MODULE_CODE]["NOTIFY_ON_NEW_REQUEST"],
        title="Nouvelle demande de permission",
        # url=config["URL_APPLICATION"] + "/#/TODO",
        context={
            "request": perm_req,
        },
    )
    return dump_schema.dump(perm_req)


@blueprint.route(rule="/<int:id_permission>", methods=["GET"])
@check_cruved_scope(action="R", module_code=MODULE_CODE, get_scope=True)
def get_request(id_permission, scope):
    perm_req = db.session.execute(
        select_stmt.where(PermissionRequest.id_permission == id_permission)
    ).scalar_one_or_none()
    if not perm_req:
        raise NotFound
    if not perm_req.has_instance_permission(scope):
        raise Forbidden
    return dump_schema.dump(perm_req)


@blueprint.route(rule="/<int:id_permission>", methods=["POST"])
@check_cruved_scope(action="U", module_code=MODULE_CODE, get_scope=True)
def update_request(id_permission, scope):
    perm_req = db.session.execute(
        select_stmt.where(PermissionRequest.id_permission == id_permission)
    ).scalar_one_or_none()
    if not perm_req:
        raise NotFound
    if not perm_req.has_instance_permission(scope):
        raise Forbidden
    # Users can not modify permissions after validation (except admins)
    if scope < 3 and perm_req.permission.validated is not None:
        raise Forbidden
    schema = PermissionRequestSchema(
        only=[
            "permission.id_permission",  # required for load_instance to work
        ]
        + writable_fields
    )
    schema.load(request.json, instance=perm_req, partial=writable_fields)
    # No-autoflush block to avoid updating actual permission when refreshing
    # relationship while the controls are not yet completed.
    with db.session.no_autoflush:
        if perm_req.permission.id_permission != id_permission:
            raise BadRequest("Permission pk does not match request")
        # We expire relationships (but not FK fields!) to verify
        # that updated FK are still valid values.
        db.session.expire(perm_req.permission, ["role", "action", "module", "object"])
        if not perm_req.permission.role:
            raise BadRequest("Role not found")
        if not perm_req.has_instance_permission(scope):
            raise Forbidden("You can not create permission request for this user")
        if not perm_req.permission.action:
            raise BadRequest("Action not found")
        if not perm_req.permission.module:
            raise BadRequest("Module not found")
        if not perm_req.permission.object:
            raise BadRequest("object not found")
    db.session.commit()
    return dump_schema.dump(perm_req)


@blueprint.route(rule="/<int:id_permission>", methods=["DELETE"])
@check_cruved_scope(action="D", module_code=MODULE_CODE, get_scope=True)
def delete_request(id_permission, scope):
    perm_req = db.session.execute(
        select_stmt.where(PermissionRequest.id_permission == id_permission)
    ).scalar_one_or_none()
    if not perm_req:
        raise NotFound
    if not perm_req.has_instance_permission(scope):
        raise Forbidden
    # Removing the permission will remove the request, but not the other way round!
    db.session.delete(perm_req.permission)
    db.session.commit()
    return "", 204


@blueprint.route(rule="/<int:id_permission>/validate", methods=["POST"])
@check_cruved_scope(action="V", module_code=MODULE_CODE)
def validate_request(id_permission):
    """
    Change permission validation status
    - no payload: set validation status to pending
    - {"validated": true}: set validation status to True
    - {"validated": false}: set validation status to False
    """
    perm_req = db.session.execute(
        select_stmt.where(PermissionRequest.id_permission == id_permission)
    ).scalar_one_or_none()
    if not perm_req:
        raise NotFound
    ValidateRequestSchema = Schema.from_dict(
        fields={"validated": fields.Bool(required=True, allow_none=True)}
    )
    validated = ValidateRequestSchema().load(request.json)["validated"]
    if validated == perm_req.permission.validated:
        raise Conflict
    perm_req.permission.validated = validated
    perm_req.validated_on = datetime.now()
    perm_req.validated_by = g.current_user.id_role
    db.session.commit()
    dispatch_notifications(
        code_categories=["PERMISSIONS-REQUESTS-VALIDATED%"],
        id_roles=[perm_req.permission.role.id_role],
        title="Modération de votre demande de permission",
        # url=config["URL_APPLICATION"] + "/#/TODO",
        context={
            "request": perm_req,
        },
    )
    return dump_schema.dump(perm_req)
