"""
Définition des routes du module export
"""

from datetime import datetime
from typing import Sequence

from flask import Blueprint, request, g
from sqlalchemy import desc, asc
from sqlalchemy.orm import aliased
from werkzeug.exceptions import BadRequest, NotFound, Forbidden

from geonature.core.gn_permissions import decorators as permissions
from geonature.core.gn_permissions.decorators import login_required
from geonature.utils.env import db
from utils_flask_sqla.response import json_resp

from . import MODULE_CODE
from .models import AccessRequest
from .schemas import AccessRequestSchema
from pypnusershub.db.models import User
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


def _get_validation_status_ids(codes: Sequence[str]) -> list[int]:
    normalized_codes = list(
        dict.fromkeys(
            code.strip() for code in codes if isinstance(code, str) and code.strip()
        )
    )
    if not normalized_codes:
        return []

    type_id = (
        BibNomenclaturesTypes.query.with_entities(BibNomenclaturesTypes.id_type)
        .filter(BibNomenclaturesTypes.mnemonique == NOMENCLATURE_TYPE)
        .scalar()
    )
    if type_id is None:
        raise NotFound(f"Le type de nomenclature {NOMENCLATURE_TYPE} est introuvable.")

    query = (
        Nomenclature.query.with_entities(Nomenclature.cd_nomenclature, Nomenclature.id_nomenclature)
        .filter(
            Nomenclature.id_type == type_id,
            Nomenclature.cd_nomenclature.in_(normalized_codes),
        )
    )

    rows = query.all()
    results = {code: identifier for code, identifier in rows}
    missing_codes = sorted({code for code in normalized_codes if code not in results})
    if missing_codes:
        raise NotFound(
            f"Les codes de validation suivants sont introuvables pour {NOMENCLATURE_TYPE}: {', '.join(missing_codes)}."
        )

    return [results[code] for code in normalized_codes]


"""
#################################################################
    Commandes
#################################################################
"""

## ########################################################################
## COLLECTION
## ########################################################################

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

    # Order by
    orderable_columns = {
        "id_access_request": AccessRequest.id_access_request,
        "initialization_date": AccessRequest.initialization_date,
        "expiration_date": AccessRequest.expiration_date,
        "author.nom_complet": User.nom_complet,
        "validator.nom_complet": User.nom_complet,
    }
    order_column = orderable_columns.get(orderby)
    if order_column is None:
        column = getattr(AccessRequest, orderby, None)
        if column is None:
            raise BadRequest(f"Invalid orderby value '{orderby}'.")
        order_column = column

    # The query
    query = AccessRequest.filter_by_scope(scope)

    validation_codes_params = request.args.getlist("validation_codes")
    validation_codes: list[str] = []
    for raw_value in validation_codes_params:
        if not raw_value:
            continue
        validation_codes.extend([code.strip() for code in raw_value.split(",") if code.strip()])

    if validation_codes:
        validation_status_ids = _get_validation_status_ids(validation_codes)
        if validation_status_ids:
            query = query.where(AccessRequest.id_validation_status.in_(validation_status_ids))

    if orderby in "author.nom_complet":
        query = query.join(User, AccessRequest.author.of_type(User))
    elif orderby in "validator.nom_complet":
        query = query.outerjoin(User, AccessRequest.validator.of_type(User))

    if sort == SortOrder.ASC:
        query = query.order_by(asc(order_column))
    else:
        query = query.order_by(desc(order_column))

    # Paginate
    pagination = db.paginate(query, page=page, per_page=per_page, error_out=False)

    return {
        "items": access_requests_schema.dump(pagination.items),
        "total": pagination.total,
        "page": pagination.page,
        "per_page": pagination.per_page,
    }

## ########################################################################
## ENTITY - GET
## ########################################################################

@blueprint.route("/<int(signed=True):id_access_request>", methods=["GET"])
@login_required
@permissions.check_cruved_scope("R", get_scope=True, module_code=MODULE_CODE)
@json_resp
def access_request(scope, id_access_request):
    query = AccessRequest.filter_by_scope(scope)
    access_request = (
        db.session.scalars(query.filter_by(id_access_request=id_access_request))
        .unique()
        .one_or_none()
    )
    if access_request is None:
        raise NotFound(f"Access request {id_access_request} not found")
    return access_request_schema.dump(access_request)

## ########################################################################
## ENTITY - POST
## ########################################################################

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

    allowed_fields = {"description", "expiration_date", "initialization_date"}
    unexpected_fields = set(payload.keys()) - allowed_fields
    if unexpected_fields:
        raise BadRequest(f"Unsupported fields provided: {', '.join(sorted(unexpected_fields))}.")
    initialization_date = None
    if "initialization_date" in payload:
        initialization_value = payload.get("initialization_date")
        if initialization_value is None:
            initialization_date = None
        elif not isinstance(initialization_value, str):
            raise BadRequest("initialization_date must be a string in YYYY-MM-DD format or null.")
        else:
            try:
                initialization_date = datetime.strptime(initialization_value, "%Y-%m-%d").date()
            except ValueError as exc:
                raise BadRequest("initialization_date must follow the YYYY-MM-DD format.") from exc
    expiration_value = payload.get("expiration_date")
    if not isinstance(expiration_value, str):
        raise BadRequest("expiration_date is required and must be a string (YYYY-MM-DD).")
    try:
        expiration_date = datetime.strptime(expiration_value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise BadRequest("expiration_date must follow the YYYY-MM-DD format.") from exc
    if initialization_date and initialization_date > expiration_date:
        raise BadRequest("initialization_date must be before or equal to expiration_date.")

    description_value = payload.get("description")
    if description_value is not None and not isinstance(description_value, str):
        raise BadRequest("description must be a string or null.")

    current_user = getattr(g, "current_user", None)
    if current_user is None or not hasattr(current_user, "id_role"):
        raise Forbidden("Current user context is missing.")

    access_request = AccessRequest(
        id_author=current_user.id_role,
        id_validator=None,
        initialization_date=initialization_date,
        expiration_date=expiration_date,
        description=description_value,
        id_validation_status=_get_validation_status_id(PENDING_STATUS_CODE),
    )

    db.session.add(access_request)
    db.session.commit()

    return access_request_schema.dump(access_request), 201

## ########################################################################
## ENTITY - PATCH
## ########################################################################7

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

    allowed_fields = {"description", "expiration_date", "initialization_date", "id_validator"}
    if not allowed_fields.intersection(payload.keys()):
        raise BadRequest("No updatable fields were provided.")

    query = AccessRequest.filter_by_scope(scope)
    access_request = (
        db.session.scalars(query.filter_by(id_access_request=id_access_request))
        .unique()
        .one_or_none()
    )
    if access_request is None:
        raise NotFound(f"Access request {id_access_request} not found")

    if "description" in payload:
        access_request.description = payload.get("description")

    if "initialization_date" in payload:
        initialization_value = payload.get("initialization_date")
        if initialization_value is None:
            access_request.initialization_date = None
        elif not isinstance(initialization_value, str):
            raise BadRequest("initialization_date must be a string in YYYY-MM-DD format or null.")
        else:
            try:
                access_request.initialization_date = datetime.strptime(
                    initialization_value, "%Y-%m-%d"
                ).date()
            except ValueError as exc:
                raise BadRequest(
                    "initialization_date must be a valid date in YYYY-MM-DD format."
                ) from exc

    if "expiration_date" in payload:
        expiration_value = payload.get("expiration_date")
        if not isinstance(expiration_value, str):
            raise BadRequest("expiration_date must be a string in YYYY-MM-DD format.")
        try:
            access_request.expiration_date = datetime.strptime(expiration_value, "%Y-%m-%d").date()
        except ValueError as exc:
            raise BadRequest("expiration_date must be a valid date in YYYY-MM-DD format.") from exc
    if (
        ("initialization_date" in payload or "expiration_date" in payload)
        and access_request.initialization_date is not None
        and access_request.expiration_date is not None
    ):
        if access_request.initialization_date > access_request.expiration_date:
            raise BadRequest("initialization_date must be before or equal to expiration_date.")

    if "id_validator" in payload:
        id_validator_value = payload.get("id_validator")
        if id_validator_value is not None and not isinstance(id_validator_value, int):
            raise BadRequest("id_validator must be an integer or null.")
        access_request.id_validator = id_validator_value

    db.session.commit()

    return access_request_schema.dump(access_request)

## ########################################################################
## ENTITY - DELETE
## ########################################################################

@blueprint.route("/<int(signed=True):id_access_request>", methods=["DELETE"])
@permissions.check_cruved_scope("D", get_scope=True, module_code=MODULE_CODE)
@json_resp
def delete_access_request(scope, id_access_request):
    if scope < 2:
        raise Forbidden("User is not allowed to delete access requests.")

    query = AccessRequest.filter_by_scope(scope)
    access_request = (
        db.session.scalars(query.filter_by(id_access_request=id_access_request))
        .unique()
        .one_or_none()
    )
    if access_request is None:
        raise NotFound(f"Access request {id_access_request} not found")

    db.session.delete(access_request)
    db.session.commit()

    return None, 204

## ########################################################################
## VALIDATION
## ########################################################################

@blueprint.route("/<int(signed=True):id_access_request>/validation-status", methods=["PATCH"])
@login_required
@permissions.check_cruved_scope("V", get_scope=True, module_code=MODULE_CODE)
@json_resp
def update_validation_status(scope, id_access_request):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise BadRequest("A JSON object is required.")

    allowed_fields = {"validation_code"}
    unexpected_fields = set(payload.keys()) - allowed_fields
    if unexpected_fields:
        raise BadRequest(f"Unsupported fields provided: {', '.join(sorted(unexpected_fields))}.")

    validation_code = payload.get("validation_code")

    if validation_code is None:
        raise BadRequest("validation_code must be provided.")
    if validation_code is not None and not isinstance(validation_code, str):
        raise BadRequest("validation_code must be a string.")

    validation_id = _get_validation_status_id(validation_code)

    query = AccessRequest.filter_by_scope(scope)
    access_request = db.session.scalars(
        query.filter_by(id_access_request=id_access_request)
    ).unique().one_or_none()
    if access_request is None:
        raise NotFound(f"Access request {id_access_request} not found")

    current_user = getattr(g, "current_user", None)
    if current_user is None or not hasattr(current_user, "id_role"):
        raise Forbidden("Current user context is missing.")

    access_request.id_validation_status = validation_id
    access_request.id_validator = current_user.id_role

    db.session.commit()

    return access_request_schema.dump(access_request)
