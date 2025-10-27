"""
Définition des routes du module export
"""

from datetime import datetime

from flask import Blueprint, request, g
from sqlalchemy import desc, asc
from werkzeug.exceptions import BadRequest, NotFound, Forbidden

from geonature.core.gn_permissions import decorators as permissions
from geonature.core.gn_permissions.decorators import login_required
from geonature.utils.env import db
from utils_flask_sqla.response import json_resp

from . import MODULE_CODE
from .models import AccessRequest
from .schemas import AccessRequestSchema
from pypnnomenclature.models import (
    BibNomenclaturesTypes,
    TNomenclatures as Nomenclature,
)


blueprint = Blueprint("access_request", __name__, cli_group="access_request")
access_requests_schema = AccessRequestSchema(many=True)
access_request_schema = AccessRequestSchema()

NOMENCLATURE_TYPE = f"{MODULE_CODE}_VALIDATION"
PENDING_STATUS_CODE = "PENDING"

from enum import Enum


class SortOrder(Enum):
    ASC = "asc"
    DESC = "desc"


def _get_validation_status_id(code: str) -> int:
    type_id = (
        BibNomenclaturesTypes.query.with_entities(BibNomenclaturesTypes.id_type)
        .filter(BibNomenclaturesTypes.mnemonique == NOMENCLATURE_TYPE)
        .scalar()
    )
    if type_id is None:
        raise NotFound(f"Le type de nomenclature {NOMENCLATURE_TYPE} est introuvable.")

    nomenclature = (
        Nomenclature.query.with_entities(Nomenclature.id_nomenclature)
        .filter(
            Nomenclature.id_type == type_id,
            Nomenclature.cd_nomenclature == code,
        )
        .scalar()
    )
    if nomenclature is None:
        raise NotFound(f"La nomenclature {code} n'est pas disponible pour {NOMENCLATURE_TYPE}.")
    return nomenclature


"""
#################################################################
    Commandes
#################################################################
"""


@blueprint.route("/", methods=["GET"])
@login_required
@permissions.check_cruved_scope("R", get_scope=True, module_code=MODULE_CODE)
@json_resp
def list_access_requests(scope):
    page = request.args.get("page", default=1, type=int)
    per_page = request.args.get("per_page", default=20, type=int)
    orderby = request.args.get("orderby", "id_access_request")
    sort = request.args.get("sort", SortOrder.ASC, SortOrder)
    if page <= 0:
        raise BadRequest(f"Invalid page {page} requested")
    if per_page <= 0:
        raise BadRequest(f"Invalid per_page {per_page} requested")

    query = AccessRequest.filter_by_scope(scope)
    if sort == SortOrder.ASC:
        query = query.order_by(asc(orderby))
    query = query.order_by(desc(orderby))

    # Paginate
    pagination = db.paginate(query, page=page, per_page=per_page, error_out=False)

    return {
        "items": access_requests_schema.dump(pagination.items),
        "total": pagination.total,
        "page": pagination.page,
        "per_page": pagination.per_page,
    }


@blueprint.route("/<int(signed=True):id_access_request>", methods=["GET"])
@login_required
@permissions.check_cruved_scope("R", get_scope=True, module_code=MODULE_CODE)
@json_resp
def access_request(scope, id_access_request):
    query = AccessRequest.filter_by_scope(scope)
    access_request = query.filter_by(
        id_access_request=id_access_request
    )
    if access_request is None:
        raise NotFound(f"Access request {id_access_request} not found")
    return access_request_schema.dump(access_request)


@blueprint.route("/", methods=["POST"])
@login_required
@permissions.check_cruved_scope("C", module_code=MODULE_CODE)
@json_resp
def create_access_request():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise BadRequest("A JSON object is required.")

    forbidden_fields = {
        "validation_status",
        "id_validation_status",
        "id_validator",
        "id_author",
        "author",
        "validator",
    }
    if forbidden_fields.intersection(payload.keys()):
        raise BadRequest(
            "Fields validation_status, id_validation_status, id_validator, "
            "id_author and author are not allowed during creation."
        )

    allowed_fields = {"description", "expiration_date"}
    unexpected_fields = set(payload.keys()) - allowed_fields
    if unexpected_fields:
        raise BadRequest(f"Unsupported fields provided: {', '.join(sorted(unexpected_fields))}.")
    expiration_value = payload.get("expiration_date")
    if not isinstance(expiration_value, str):
        raise BadRequest("expiration_date is required and must be a string (YYYY-MM-DD).")
    try:
        expiration_date = datetime.strptime(expiration_value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise BadRequest("expiration_date must follow the YYYY-MM-DD format.") from exc

    description_value = payload.get("description")
    if description_value is not None and not isinstance(description_value, str):
        raise BadRequest("description must be a string or null.")

    current_user = getattr(g, "current_user", None)
    if current_user is None or not hasattr(current_user, "id_role"):
        raise Forbidden("Current user context is missing.")

    access_request = AccessRequest(
        id_author=current_user.id_role,
        id_validator=None,
        expiration_date=expiration_date,
        description=description_value,
        id_validation_status=_get_validation_status_id(PENDING_STATUS_CODE),
    )

    db.session.add(access_request)
    db.session.commit()

    return access_request_schema.dump(access_request), 201


@blueprint.route("/<int(signed=True):id_access_request>", methods=["PATCH"])
@login_required
@permissions.check_cruved_scope("U", get_scope=True, module_code=MODULE_CODE)
@json_resp
def update_access_request(scope, id_access_request):
    if scope < 2:
        raise Forbidden("User is not allowed to update access requests.")

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise BadRequest("A JSON object is required.")

    forbidden_fields = {"validation_status", "id_validation_status"}
    if forbidden_fields.intersection(payload.keys()):
        raise BadRequest("Field 'validation_status' cannot be updated.")

    allowed_fields = {"description", "expiration_date", "id_validator"}
    if not allowed_fields.intersection(payload.keys()):
        raise BadRequest("No updatable fields were provided.")

    query = AccessRequest.filter_by_scope(scope)
    access_request = query.filter_by(
        id_access_request=id_access_request
    )
    if access_request is None:
        raise NotFound(f"Access request {id_access_request} not found")

    if "description" in payload:
        access_request.description = payload.get("description")

    if "expiration_date" in payload:
        expiration_value = payload.get("expiration_date")
        if not isinstance(expiration_value, str):
            raise BadRequest("expiration_date must be a string in YYYY-MM-DD format.")
        try:
            access_request.expiration_date = datetime.strptime(expiration_value, "%Y-%m-%d").date()
        except ValueError as exc:
            raise BadRequest("expiration_date must be a valid date in YYYY-MM-DD format.") from exc

    db.session.commit()

    return access_request_schema.dump(access_request)


@blueprint.route("/<int(signed=True):id_access_request>", methods=["DELETE"])
@permissions.check_cruved_scope("D", get_scope=True, module_code=MODULE_CODE)
@json_resp
def delete_access_request(scope, id_access_request):
    if scope < 2:
        raise Forbidden("User is not allowed to delete access requests.")

    query = AccessRequest.filter_by_scope(scope)
    access_request = query.filter_by(
        id_access_request=id_access_request
    ).one_or_none()
    if access_request is None:
        raise NotFound(f"Access request {id_access_request} not found")

    db.session.delete(access_request)
    db.session.commit()

    return None, 204
