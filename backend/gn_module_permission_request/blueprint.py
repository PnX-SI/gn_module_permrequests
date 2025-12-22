"""
Définition des routes du module export
"""

from datetime import datetime
from flask import Blueprint, request, g
from sqlalchemy import desc, asc, select, case
import sqlalchemy as sa
from werkzeug.exceptions import BadRequest, NotFound, Forbidden, InternalServerError

from geonature.core.gn_commons.models.base import TModules
from geonature.core.gn_permissions import decorators as permissions
from geonature.core.gn_permissions.decorators import login_required
from geonature.core.gn_permissions.models import Permission, PermAction, PermObject
from geonature.core.notifications.utils import dispatch_notifications
from geonature.utils.env import db
from utils_flask_sqla.response import json_resp

from . import MODULE_CODE
from .models import PermissionRequest, SCOPE_USER, SCOPE_ORGANISM
from .schemas import PermissionRequestSchema
from .status_utils import status_order_case, Status, status_filter_expression
from .notifications_utils import PermissionRequestCodes
from pypnusershub.db.models import User
from apptax.taxonomie.models import Taxref
from ref_geo.models import LAreas
from sqlalchemy.orm import aliased


blueprint = Blueprint("permission_request", __name__, cli_group="permission_request")
permission_requests_schema = PermissionRequestSchema(many=True)
permission_request_schema = PermissionRequestSchema()

from enum import Enum


class SortOrder(Enum):
    ASC = "asc"
    DESC = "desc"


ALLOWED_SCOPES = {SCOPE_USER, SCOPE_ORGANISM}
ALLOWED_AREA_TYPE_CODES = {"COM", "DEP", "REG"}


def _normalize_scope(value):
    if isinstance(value, str):
        return value.strip().upper()
    return None


def _resolve_permission_role(scope_value, *, author_role_id, author_organism_id):
    if scope_value == SCOPE_USER:
        if author_role_id is None:
            raise InternalServerError("Author role is missing.")
        return author_role_id

    if scope_value == SCOPE_ORGANISM:
        if author_organism_id is None:
            raise BadRequest("Author is not associated with any organism.")
        group_role_id = db.session.scalar(
            select(User.id_role)
            .where(User.groupe.is_(True), User.id_organisme == author_organism_id)
            .limit(1)
        )
        if group_role_id is None:
            raise BadRequest(
                "No group role found for the author's organism to assign the permission."
            )
        return group_role_id

    raise BadRequest(f"Unsupported scope value '{scope_value}'.")


def _parse_boolean_param(value, field_name):
    if value is None:
        return None
    lowered = value.lower()
    if lowered in {"true", "1", "yes", "y"}:
        return True
    if lowered in {"false", "0", "no", "n"}:
        return False
    raise BadRequest(f"Parameter '{field_name}' must be a boolean value.")


def _normalize_validated_filter(value):
    if value is None:
        return None
    lowered = value.lower()
    if lowered in {"true", "1", "yes", "y"}:
        return True
    if lowered in {"false", "0", "no", "n"}:
        return False
    if lowered in {"none", "null"}:
        return "none"
    raise BadRequest("Parameter 'validated' must be true, false or none.")


def _get_permission_request_module_id():
    module_id = db.session.scalar(
        select(TModules.id_module).where(TModules.module_code == MODULE_CODE)
    )
    if module_id is None:
        raise InternalServerError(
            "Permission request module is missing from permissions configuration."
        )
    return module_id


def _get_validation_action_id():
    action_id = db.session.scalar(
        select(PermAction.id_action).where(PermAction.code_action == "V")
    )
    if action_id is None:
        raise InternalServerError("Validation action (code 'V') not found in configuration.")
    return action_id


def _deduplicate_role_ids(role_ids):
    return [role_id for role_id in dict.fromkeys(role_ids) if role_id is not None]


def _get_validator_role_ids():
    module_id = _get_permission_request_module_id()
    validation_action_id = _get_validation_action_id()
    role_query = (
        select(Permission.id_role)
        .where(
            Permission.id_module == module_id,
            Permission.id_action == validation_action_id,
            Permission.active_filter(),
        )
        .distinct()
    )
    role_ids = db.session.scalars(role_query).all()
    return _deduplicate_role_ids(role_ids)


def _build_role_recipient_ids(*role_ids):
    return _deduplicate_role_ids(role_ids)


## ########################################################################
## COLLECTION
## ########################################################################


@blueprint.route("/", methods=["GET"])
@login_required
@permissions.check_cruved_scope("R", get_scope=True, module_code=MODULE_CODE)
@json_resp
def list_permission_requests(scope):
    page = request.args.get("page", default=1, type=int)
    per_page = request.args.get("per_page", default=20, type=int)
    orderby = request.args.get("orderby", "id_permission_request")
    sort = request.args.get("sort", SortOrder.ASC, SortOrder)
    if page <= 0:
        raise BadRequest(f"Invalid page {page} requested")
    if per_page <= 0:
        raise BadRequest(f"Invalid per_page {per_page} requested")

    status_order_column = status_order_case(
        PermissionRequest.validated,
        PermissionRequest.created_on,
        PermissionRequest.expiration_date,
        PermissionRequest.id_validator,
    ).label("status_order")

    # Order by
    query = PermissionRequest.filter_by_scope(scope)

    orderable_columns = {
        "id_permission_request": PermissionRequest.id_permission_request,
        "created_on": PermissionRequest.created_on,
        "expiration_date": PermissionRequest.expiration_date,
        "author.nom_complet": User.nom_complet,
        "validator.nom_complet": User.nom_complet,
        "status": status_order_column,
        "sensitivity_filter": PermissionRequest.sensitivity_filter,
        "scope": None,
    }
    status_filters = []
    for status_value in request.args.getlist("status"):
        try:
            status_filters.append(Status(status_value.upper()))
        except ValueError as exc:
            raise BadRequest(f"Unsupported status value '{status_value}'.") from exc

    scope_filters = []
    for scope_value in request.args.getlist("scope"):
        normalized_scope = _normalize_scope(scope_value)
        if normalized_scope not in ALLOWED_SCOPES:
            raise BadRequest(f"Unsupported scope value '{scope_value}'.")
        scope_filters.append(normalized_scope)

    validated_filters = []
    for validated_value in request.args.getlist("validated"):
        validated_filters.append(_normalize_validated_filter(validated_value))

    my_validations = _parse_boolean_param(
        request.args.get("my_validations"),
        "my_validations",
    )

    sensitivity_filters = []
    for sensitivity_value in request.args.getlist("sensitivity_filter"):
        parsed = _parse_boolean_param(sensitivity_value, "sensitivity_filter")
        if parsed is not None:
            sensitivity_filters.append(parsed)

    permission_alias = None
    author_alias = None
    permission_role_alias = None

    needs_permission_join = (
        orderby == "scope"
        or bool(scope_filters)
        or bool(validated_filters)
        or bool(sensitivity_filters)
    )

    if needs_permission_join:
        permission_alias = aliased(Permission)
        query = query.outerjoin(permission_alias, PermissionRequest.permission)

    needs_scope_join = orderby == "scope" or bool(scope_filters)
    if needs_scope_join:
        author_alias = aliased(User)
        permission_role_alias = aliased(User)
        query = query.outerjoin(author_alias, PermissionRequest.author.of_type(author_alias))
        query = query.outerjoin(
            permission_role_alias, permission_alias.role.of_type(permission_role_alias)
        )

    if orderby == "scope":
        order_column = case(
            (permission_alias.id_role == PermissionRequest.id_author, 0),
            (
                sa.and_(
                    permission_role_alias.groupe.is_(True),
                    permission_role_alias.id_organisme.isnot(None),
                    author_alias.id_organisme.isnot(None),
                    permission_role_alias.id_organisme == author_alias.id_organisme,
                ),
                1,
            ),
            else_=2,
        )
    else:
        order_column = orderable_columns.get(orderby)
        if order_column is None:
            column = getattr(PermissionRequest, orderby, None)
            if column is None:
                raise BadRequest(f"Invalid orderby value '{orderby}'.")
            order_column = column

    if orderby in "author.nom_complet":
        query = query.join(User, PermissionRequest.author.of_type(User))
    elif orderby in "validator.nom_complet":
        query = query.outerjoin(User, PermissionRequest.validator.of_type(User))

    if sort == SortOrder.ASC:
        order_by_clauses = [asc(order_column)]
    else:
        order_by_clauses = [desc(order_column)]

    if orderby == "status":
        secondary = (
            asc(PermissionRequest.expiration_date)
            if sort == SortOrder.ASC
            else desc(PermissionRequest.expiration_date)
        )
        order_by_clauses.append(secondary)
    elif orderby == "scope":
        secondary = (
            asc(PermissionRequest.id_permission_request)
            if sort == SortOrder.ASC
            else desc(PermissionRequest.id_permission_request)
        )
        order_by_clauses.append(secondary)

    if status_filters:
        status_clauses = [
            status_filter_expression(
                status,
                validated_column=PermissionRequest.validated,
                created_on_column=PermissionRequest.created_on,
                expiration_column=PermissionRequest.expiration_date,
                id_validator_column=PermissionRequest.id_validator,
            )
            for status in set(status_filters)
        ]
        query = query.where(sa.or_(*status_clauses))

    if scope_filters and needs_scope_join:
        scope_clauses = []
        scope_set = set(scope_filters)
        if SCOPE_USER in scope_set:
            scope_clauses.append(permission_alias.id_role == PermissionRequest.id_author)
        if SCOPE_ORGANISM in scope_set:
            scope_clauses.append(
                sa.and_(
                    permission_alias.id_role.isnot(None),
                    permission_role_alias.groupe.is_(True),
                    permission_role_alias.id_organisme.isnot(None),
                    author_alias.id_organisme.isnot(None),
                    permission_role_alias.id_organisme == author_alias.id_organisme,
                )
            )
        if scope_clauses:
            query = query.where(sa.or_(*scope_clauses))

    if sensitivity_filters:
        sensitivity_set = set(sensitivity_filters)
        if permission_alias is not None:
            clauses = [permission_alias.sensitivity_filter.is_(value) for value in sensitivity_set]
            query = query.where(sa.or_(*clauses))
        else:
            clauses = [Permission.sensitivity_filter.is_(value) for value in sensitivity_set]
            query = query.where(
                sa.or_(*[PermissionRequest.permission.has(clause) for clause in clauses])
            )

    if validated_filters:
        validated_set = set(validated_filters)
        if permission_alias is not None:
            clauses = []
            for validated_value in validated_set:
                if validated_value == "none":
                    clauses.append(permission_alias.validated.is_(None))
                else:
                    clauses.append(permission_alias.validated.is_(validated_value))
            query = query.where(sa.or_(*clauses))
        else:
            clauses = []
            for validated_value in validated_set:
                if validated_value == "none":
                    clauses.append(Permission.validated.is_(None))
                else:
                    clauses.append(Permission.validated.is_(validated_value))
            query = query.where(
                sa.or_(*[PermissionRequest.permission.has(clause) for clause in clauses])
            )

    if my_validations:
        current_user = g.current_user
        if current_user is None or not hasattr(current_user, "id_role"):
            raise Forbidden("Current user context is missing.")
        query = query.where(PermissionRequest.id_validator == current_user.id_role)

    query = query.order_by(*order_by_clauses)

    # Paginate
    pagination = db.paginate(query, page=page, per_page=per_page, error_out=False)

    return {
        "items": permission_requests_schema.dump(pagination.items),
        "total": pagination.total,
        "page": pagination.page,
        "per_page": pagination.per_page,
    }


## ########################################################################
## ENTITY - GET
## ########################################################################


@blueprint.route("/<int(signed=True):id_permission_request>", methods=["GET"])
@login_required
@permissions.check_cruved_scope("R", get_scope=True, module_code=MODULE_CODE)
@json_resp
def permission_request(scope, id_permission_request):
    query = PermissionRequest.filter_by_scope(scope)
    permission_request = (
        db.session.scalars(query.filter_by(id_permission_request=id_permission_request))
        .unique()
        .one_or_none()
    )
    if permission_request is None:
        raise NotFound(f"Permission request {id_permission_request} not found")
    return permission_request_schema.dump(permission_request)


## ########################################################################
## ENTITY - POST
## ########################################################################


@blueprint.route("/", methods=["POST"])
@login_required
@permissions.check_cruved_scope("C", module_code=MODULE_CODE)
@json_resp
def create_permission_request():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise BadRequest("A JSON object is required.")

    forbidden_fields = {"status", "validated", "id_validator", "id_author", "author", "validator"}
    if forbidden_fields.intersection(payload.keys()):
        raise BadRequest(
            "Fields status, id_validator, " "id_author and author are not allowed during creation."
        )

    allowed_fields = {
        "description",
        "expiration_date",
        "created_on",
        "taxa",
        "areas",
        "sensitivity_filter",
        "scope",
    }
    unexpected_fields = set(payload.keys()) - allowed_fields
    if unexpected_fields:
        raise BadRequest(f"Unsupported fields provided: {', '.join(sorted(unexpected_fields))}.")
    created_on = None
    if "created_on" in payload:
        created_on_value = payload.get("created_on")
        if created_on_value is None:
            created_on = None
        elif not isinstance(created_on_value, str):
            raise BadRequest("created_on must be a string in YYYY-MM-DD format or null.")
        else:
            try:
                created_on = datetime.strptime(created_on_value, "%Y-%m-%d").date()
            except ValueError as exc:
                raise BadRequest("created_on must follow the YYYY-MM-DD format.") from exc
    expiration_value = payload.get("expiration_date")
    if not isinstance(expiration_value, str):
        raise BadRequest("expiration_date is required and must be a string (YYYY-MM-DD).")
    try:
        expiration_date = datetime.strptime(expiration_value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise BadRequest("expiration_date must follow the YYYY-MM-DD format.") from exc
    if created_on and created_on > expiration_date:
        raise BadRequest("created_on must be before or equal to expiration_date.")

    description_value = payload.get("description")
    if description_value is not None and not isinstance(description_value, str):
        raise BadRequest("description must be a string or null.")

    scope_value = _normalize_scope(payload.get("scope", SCOPE_USER))
    if scope_value is None:
        raise BadRequest("scope must be provided as a string.")
    if scope_value not in ALLOWED_SCOPES:
        raise BadRequest(f"Unsupported scope value '{scope_value}'.")

    taxa_ids = payload.get("taxa")
    if taxa_ids is None:
        raise BadRequest("Field 'taxa' is required.")
    if not isinstance(taxa_ids, list):
        raise BadRequest("taxa must be an array of integers.")
    try:
        normalized_taxa_ids = [int(taxon_id) for taxon_id in taxa_ids]
    except (TypeError, ValueError) as exc:
        raise BadRequest("taxa must contain only integer values.") from exc
    if not normalized_taxa_ids:
        raise BadRequest("taxa must contain at least one value.")

    taxa_query = select(Taxref).where(Taxref.cd_nom.in_(normalized_taxa_ids))
    taxa_items = db.session.scalars(taxa_query).all()
    taxa_by_id = {taxon.cd_nom: taxon for taxon in taxa_items}
    missing_taxa = sorted(
        {taxon_id for taxon_id in normalized_taxa_ids if taxon_id not in taxa_by_id}
    )
    if missing_taxa:
        raise BadRequest(
            f"Some taxa identifiers are invalid or unknown: {', '.join(map(str, missing_taxa))}."
        )

    taxa_list = [taxa_by_id[taxon_id] for taxon_id in normalized_taxa_ids]

    raw_areas = payload.get("areas", [])
    if raw_areas is None:
        raw_areas = []
    if not isinstance(raw_areas, list):
        raise BadRequest("areas must be an array of integers.")
    try:
        normalized_area_ids = [int(area_id) for area_id in raw_areas]
    except (TypeError, ValueError) as exc:
        raise BadRequest("areas must contain only integer values.") from exc
    areas_items = (
        db.session.scalars(select(LAreas).where(LAreas.id_area.in_(normalized_area_ids))).all()
        if normalized_area_ids
        else []
    )
    areas_by_id = {area.id_area: area for area in areas_items}
    missing_areas = sorted(
        {area_id for area_id in normalized_area_ids if area_id not in areas_by_id}
    )
    if missing_areas:
        raise BadRequest(
            f"Some area identifiers are invalid or unknown: {', '.join(map(str, missing_areas))}."
        )
    invalid_area_types = sorted(
        {
            area_id
            for area_id in normalized_area_ids
            if area_id in areas_by_id
            and getattr(areas_by_id[area_id].area_type, "type_code", None)
            not in ALLOWED_AREA_TYPE_CODES
        }
    )
    if invalid_area_types:
        allowed_codes = ", ".join(sorted(ALLOWED_AREA_TYPE_CODES))
        raise BadRequest(
            f"Areas must belong to one of the allowed types ({allowed_codes}). Invalid areas: {', '.join(map(str, invalid_area_types))}."
        )
    areas_list = [areas_by_id[area_id] for area_id in normalized_area_ids]

    sensitivity_filter_value = payload.get("sensitivity_filter", True)
    if not isinstance(sensitivity_filter_value, bool):
        raise BadRequest("sensitivity_filter must be a boolean value.")

    current_user = g.current_user
    if current_user is None or not hasattr(current_user, "id_role"):
        raise Forbidden("Current user context is missing.")

    author_role_id = current_user.id_role
    author_organism_id = current_user.id_organisme
    permission_role_id = _resolve_permission_role(
        scope_value,
        author_role_id=author_role_id,
        author_organism_id=author_organism_id,
    )

    module_id = db.session.scalars(
        select(TModules.id_module).where(TModules.module_code == "SYNTHESE")
    ).one_or_none()
    if module_id is None:
        module_id = db.session.scalars(
            select(TModules.id_module).where(TModules.module_label == "Synthèse")
        ).one_or_none()
    if module_id is None:
        raise InternalServerError("Synthèse module not found in permissions configuration.")

    read_action_id = db.session.scalars(
        select(PermAction.id_action).where(PermAction.code_action == "R")
    ).one_or_none()
    if read_action_id is None:
        raise InternalServerError("Read action (code 'R') not found in permissions configuration.")

    object_id = db.session.scalars(
        select(PermObject.id_object).where(PermObject.code_object == "ALL")
    ).one_or_none()
    if object_id is None:
        raise InternalServerError(
            "Permission object 'ALL' not found in permissions configuration."
        )

    created_on_value = (
        datetime.combine(created_on, datetime.min.time())
        if created_on is not None
        else datetime.now()
    )
    expire_on_value = datetime.combine(expiration_date, datetime.min.time())

    permission_request = PermissionRequest(
        id_author=current_user.id_role,
        id_validator=None,
        description=description_value,
    )

    permission = Permission(
        id_role=permission_role_id,
        id_action=read_action_id,
        id_module=module_id,
        id_object=object_id,
        scope_value=None,
        sensitivity_filter=sensitivity_filter_value,
        created_on=created_on_value,
        expire_on=expire_on_value,
        validated=None,
    )
    permission.taxons_filter = list(taxa_list)
    permission.areas_filter = list(areas_list)

    permission_request.permission = permission

    desired_validated = permission.validated

    db.session.add(permission_request)
    db.session.flush()
    if permission.validated != desired_validated:
        permission.validated = desired_validated

    db.session.commit()

    notifications_role_ids = _get_validator_role_ids()
    notifications_role_ids.append(g.current_user.id_role)
    if notifications_role_ids:
        dispatch_notifications(
            code_categories=[PermissionRequestCodes.PERMISSION_REQUEST_NEW],
            id_roles=notifications_role_ids,
            context={
                "permission_request": permission_request,
                "user": g.current_user,
            },
        )
    db.session.commit()

    return permission_request_schema.dump(permission_request), 201


## ########################################################################
## ENTITY - PATCH
## ########################################################################7


@blueprint.route("/<int(signed=True):id_permission_request>", methods=["PATCH"])
@login_required
@permissions.check_cruved_scope("U", get_scope=True, module_code=MODULE_CODE)
@json_resp
def update_permission_request(scope, id_permission_request):
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        raise BadRequest("A JSON object is required.")

    forbidden_fields = {"status", "validated", "id_validator"}
    if forbidden_fields.intersection(payload.keys()):
        raise BadRequest("Fields status, validated and id_validator cannot be updated.")

    allowed_fields = {
        "description",
        "expiration_date",
        "created_on",
        "taxa",
        "areas",
        "sensitivity_filter",
        "scope",
    }
    if not allowed_fields.intersection(payload.keys()):
        raise BadRequest("No updatable fields were provided.")

    query = PermissionRequest.filter_by_scope(scope)
    permission_request = (
        db.session.scalars(query.filter_by(id_permission_request=id_permission_request))
        .unique()
        .one_or_none()
    )
    if permission_request is None:
        raise NotFound(f"Permission request {id_permission_request} not found")

    if "description" in payload:
        permission_request.description = payload.get("description")

    if "created_on" in payload:
        created_on_value = payload.get("created_on")
        if created_on_value is None:
            permission_request.created_on = None
        elif not isinstance(created_on_value, str):
            raise BadRequest("created_on must be a string in YYYY-MM-DD format or null.")
        else:
            try:
                permission_request.created_on = datetime.strptime(
                    created_on_value, "%Y-%m-%d"
                ).date()
            except ValueError as exc:
                raise BadRequest("created_on must be a valid date in YYYY-MM-DD format.") from exc

    if "expiration_date" in payload:
        expiration_value = payload.get("expiration_date")
        if not isinstance(expiration_value, str):
            raise BadRequest("expiration_date must be a string in YYYY-MM-DD format.")
        try:
            permission_request.expiration_date = datetime.strptime(
                expiration_value, "%Y-%m-%d"
            ).date()
        except ValueError as exc:
            raise BadRequest("expiration_date must be a valid date in YYYY-MM-DD format.") from exc
    if (
        ("created_on" in payload or "expiration_date" in payload)
        and permission_request.created_on is not None
        and permission_request.expiration_date is not None
    ):
        if permission_request.created_on > permission_request.expiration_date:
            raise BadRequest("created_on must be before or equal to expiration_date.")

    if "scope" in payload:
        raw_scope = payload.get("scope")
        if not isinstance(raw_scope, str):
            raise BadRequest("scope must be provided as a string.")
        scope_value = _normalize_scope(raw_scope)
        if scope_value is None or scope_value not in ALLOWED_SCOPES:
            raise BadRequest(f"Unsupported scope value '{raw_scope}'.")
        author = permission_request.author
        new_role_id = _resolve_permission_role(
            scope_value,
            author_role_id=author.id_role,
            author_organism_id=author.id_organisme,
        )
        permission_request.permission.id_role = new_role_id

    if "sensitivity_filter" in payload:
        sensitivity_value = payload.get("sensitivity_filter")
        if not isinstance(sensitivity_value, bool):
            raise BadRequest("sensitivity_filter must be a boolean value.")
        if permission_request.permission is None:
            raise InternalServerError("No permission is linked to this permission request.")
        permission_request.sensitivity_filter = sensitivity_value

    if "taxa" in payload:
        taxa_value = payload.get("taxa")
        if not isinstance(taxa_value, list):
            raise BadRequest("taxa must be an array of integers.")
        try:
            normalized_taxa_ids = [int(taxon_id) for taxon_id in taxa_value]
        except (TypeError, ValueError) as exc:
            raise BadRequest("taxa must contain only integer values.") from exc
        if not normalized_taxa_ids:
            raise BadRequest("taxa must contain at least one value.")

        taxa_query = select(Taxref).where(Taxref.cd_nom.in_(normalized_taxa_ids))
        taxa_items = db.session.scalars(taxa_query).all()
        taxa_by_id = {taxon.cd_nom: taxon for taxon in taxa_items}
        missing_taxa = sorted(
            {taxon_id for taxon_id in normalized_taxa_ids if taxon_id not in taxa_by_id}
        )
        if missing_taxa:
            raise BadRequest(
                f"Some taxa identifiers are invalid or unknown: {', '.join(map(str, missing_taxa))}."
            )
        if permission_request.permission is None:
            raise InternalServerError("No permission is linked to this permission request.")
        permission_request.taxa = [taxa_by_id[taxon_id] for taxon_id in normalized_taxa_ids]

    if "areas" in payload:
        areas_value = payload.get("areas")
        if areas_value is None:
            normalized_area_ids = []
        elif not isinstance(areas_value, list):
            raise BadRequest("areas must be an array of integers.")
        else:
            try:
                normalized_area_ids = [int(area_id) for area_id in areas_value]
            except (TypeError, ValueError) as exc:
                raise BadRequest("areas must contain only integer values.") from exc
        areas_items = (
            db.session.scalars(select(LAreas).where(LAreas.id_area.in_(normalized_area_ids))).all()
            if normalized_area_ids
            else []
        )
        areas_by_id = {area.id_area: area for area in areas_items}
        missing_area_ids = sorted(
            {area_id for area_id in normalized_area_ids if area_id not in areas_by_id}
        )
        if missing_area_ids:
            raise BadRequest(
                f"Some area identifiers are invalid or unknown: {', '.join(map(str, missing_area_ids))}."
            )
        invalid_area_types = sorted(
            {
                area_id
                for area_id in normalized_area_ids
                if area_id in areas_by_id
                and getattr(areas_by_id[area_id].area_type, "type_code", None)
                not in ALLOWED_AREA_TYPE_CODES
            }
        )
        if invalid_area_types:
            allowed_codes = ", ".join(sorted(ALLOWED_AREA_TYPE_CODES))
            raise BadRequest(
                f"Areas must belong to one of the allowed types ({allowed_codes}). Invalid areas: {', '.join(map(str, invalid_area_types))}."
            )
        if permission_request.permission is None:
            raise InternalServerError("No permission is linked to this permission request.")
        permission_request.permission.areas_filter = [
            areas_by_id[area_id] for area_id in normalized_area_ids
        ]

    db.session.commit()

    notification_role_ids = _build_role_recipient_ids(
        permission_request.id_author,
        permission_request.id_validator,
    )
    if notification_role_ids:
        dispatch_notifications(
            code_categories=[PermissionRequestCodes.PERMISSION_REQUEST_MODIFICATION],
            id_roles=notification_role_ids,
            context={
                "permission_request": permission_request,
                "user": g.current_user,
            },
        )
    db.session.commit()

    return permission_request_schema.dump(permission_request)


## ########################################################################
## ENTITY - DELETE
## ########################################################################


@blueprint.route("/<int(signed=True):id_permission_request>", methods=["DELETE"])
@permissions.check_cruved_scope("D", get_scope=True, module_code=MODULE_CODE)
@json_resp
def delete_permission_request(scope, id_permission_request):
    query = PermissionRequest.filter_by_scope(scope)
    permission_request = (
        db.session.scalars(query.filter_by(id_permission_request=id_permission_request))
        .unique()
        .one_or_none()
    )
    if permission_request is None:
        raise NotFound(f"Permission request {id_permission_request} not found")

    notification_role_ids = _build_role_recipient_ids(
        permission_request.id_author,
        permission_request.id_validator,
    )

    db.session.delete(permission_request)
    db.session.commit()

    if notification_role_ids:
        dispatch_notifications(
            code_categories=[PermissionRequestCodes.PERMISSION_REQUEST_DELETE],
            id_roles=notification_role_ids,
            context={
                "permission_request": permission_request,
                "user": g.current_user,
            },
        )
    db.session.commit()

    return None, 204


## ########################################################################
## VALIDATION FLAG
## ########################################################################


@blueprint.route("/<int(signed=True):id_permission_request>/validated", methods=["PATCH"])
@login_required
@permissions.check_cruved_scope("V", get_scope=True, module_code=MODULE_CODE)
@json_resp
def update_validated(scope, id_permission_request):
    payload = request.get_json(silent=True)
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise BadRequest("A JSON object is required.")

    allowed_fields = {"validated", "validation_description"}
    unexpected_fields = set(payload.keys()) - allowed_fields
    if unexpected_fields:
        raise BadRequest(f"Unsupported fields provided: {', '.join(sorted(unexpected_fields))}.")

    query = PermissionRequest.filter_by_scope(scope)
    permission_request = (
        db.session.scalars(query.filter_by(id_permission_request=id_permission_request))
        .unique()
        .one_or_none()
    )
    if permission_request is None:
        raise NotFound(f"Permission request {id_permission_request} not found")

    current_user = g.current_user
    if current_user is None or not hasattr(current_user, "id_role"):
        raise Forbidden("Current user context is missing.")

    if permission_request.permission is None:
        raise InternalServerError("No permission is linked to this permission request.")

    reset_payload = len(payload) == 0

    validated_value = None
    validation_description = None
    if reset_payload:
        validated_value = None
    else:
        if "validated" not in payload:
            raise BadRequest("Field 'validated' must be provided.")

        validated_value = payload.get("validated")
        if validated_value not in (True, False, None):
            raise BadRequest("validated must be true, false or null.")

        description_provided = "validation_description" in payload
        if description_provided:
            raw_description = payload.get("validation_description")
            if raw_description is not None and not isinstance(raw_description, str):
                raise BadRequest("validation_description must be a string or null.")
            if isinstance(raw_description, str):
                trimmed = raw_description.strip()
                validation_description = trimmed or None
        else:
            validation_description = permission_request.validation_description

    permission_request.validated = validated_value
    if reset_payload:
        permission_request.id_validator = None
        permission_request.validation_description = None
    else:
        permission_request.id_validator = current_user.id_role
        if validated_value is None:
            permission_request.validation_description = None
        else:
            permission_request.validation_description = validation_description

    db.session.commit()

    notification_role_ids = _build_role_recipient_ids(
        permission_request.id_author,
        permission_request.id_validator,
    )

    dispatch_notifications(
        code_categories=[PermissionRequestCodes.PERMISSION_REQUEST_VALIDATION_UPDATE],
        id_roles=notification_role_ids,
        context={
            "permission_request": permission_request,
            "user": g.current_user,
        },
    )
    db.session.commit()

    return permission_request_schema.dump(permission_request)
