"""
Définition des routes du module export
"""

from datetime import date, datetime
from enum import Enum

import sqlalchemy as sa
from apptax.taxonomie.models import Taxref
from flask import Blueprint, current_app, g, request
from geonature.core.gn_commons.models.base import TModules
from geonature.core.gn_permissions import decorators as permissions
from geonature.core.gn_permissions.decorators import login_required
from geonature.core.gn_permissions.models import PermAction, Permission, PermObject
from geonature.core.notifications.utils import dispatch_notifications
from geonature.utils.env import db
from pypnusershub.db.models import User
from ref_geo.models import LAreas
from sqlalchemy import asc, case, desc, select
from sqlalchemy.orm import aliased
from utils_flask_sqla.response import json_resp
from werkzeug.exceptions import BadRequest, Forbidden, InternalServerError, NotFound

from . import MODULE_CODE
from .models import SCOPE_ORGANISM, SCOPE_USER, CustomArea, PermissionRequest
from .notifications_utils import PermissionRequestCodes
from .schemas import PermissionRequestSchema
from .status_utils import Status, status_filter_expression, status_order_case

blueprint = Blueprint("permission_request", __name__, cli_group="permission_request")
permission_requests_schema = PermissionRequestSchema(many=True)
permission_request_schema = PermissionRequestSchema()


class SortOrder(Enum):
    ASC = "asc"
    DESC = "desc"


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
    action_id = db.session.scalar(select(PermAction.id_action).where(PermAction.code_action == "V"))
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
## CUSTOM AREA SYNC TO L_AREAS
## ########################################################################

_AREA_TYPE_CODE = MODULE_CODE.upper()


def _get_permission_request_area_type_id():
    result = db.session.execute(
        sa.text("SELECT id_type FROM ref_geo.bib_areas_types WHERE type_code = :code"),
        {"code": _AREA_TYPE_CODE},
    ).scalar_one_or_none()
    if result is None:
        raise InternalServerError(
            f"Area type '{_AREA_TYPE_CODE}' not found in ref_geo.bib_areas_types. "
            "Run the module migration to create it."
        )
    return result


def _area_code_for(id_permission_request):
    return f"PR-{id_permission_request}"


def _area_name_for(custom_area):
    if custom_area.file_name:
        name = custom_area.file_name
        for ext in (".geojson", ".json"):
            if name.lower().endswith(ext):
                name = name[: -len(ext)]
                break
        return name
    return f"Zone personnalisée PR-{custom_area.id_permission_request}"


def _geometries_from_geojson(geojson: dict) -> list:
    """
    Retourne toutes les géométries d'un GeoJSON, qu'il soit une FeatureCollection,
    une Feature ou une géométrie nue.
    """
    if geojson.get("type") == "FeatureCollection":
        return [
            feature["geometry"]
            for feature in geojson.get("features", [])
            if feature.get("geometry") is not None
        ]
    if geojson.get("type") == "Feature":
        geometry = geojson.get("geometry")
        return [geometry] if geometry is not None else []
    return [geojson]


def _sync_custom_area_to_l_areas(permission_request):
    """
    Si la demande est validée et a une custom_area : crée ou met à jour l'entrée dans l_areas
    et l'associe à permission.areas_filter.
    Sinon : supprime l'entrée l_areas associée (si elle existe).
    """
    import json as _json

    if permission_request.custom_area is None and permission_request.validated is not True:
        return

    id_pr = permission_request.id_permission_request
    area_code = _area_code_for(id_pr)
    id_type = _get_permission_request_area_type_id()

    if permission_request.validated is True and permission_request.custom_area is not None:
        custom_area = permission_request.custom_area
        area_name = _area_name_for(custom_area)

        geometries = _geometries_from_geojson(custom_area.geojson_data)
        if not geometries:
            raise InternalServerError(
                "Impossible d'extraire une géométrie du GeoJSON de la custom_area."
            )

        # une seule géométrie en base, agrégeant toutes les features de la couche déposée
        geom_str = _json.dumps({"type": "GeometryCollection", "geometries": geometries})
        local_srid = db.session.execute(sa.func.Find_SRID("ref_geo", "l_areas", "geom")).scalar()

        existing = db.session.execute(
            sa.text(
                "SELECT id_area "
                "FROM ref_geo.l_areas "
                "WHERE id_type = :id_type AND area_code = :area_code"
            ),
            {"id_type": id_type, "area_code": area_code},
        ).scalar_one_or_none()

        if existing is None:
            id_area = db.session.execute(
                sa.text("""
                    INSERT INTO ref_geo.l_areas
                        (id_type, area_code, area_name, geom, geom_4326, enable)
                    VALUES (
                        :id_type,
                        :area_code,
                        :area_name,
                        ST_Multi(
                            ST_Transform(
                                ST_SetSRID(
                                    ST_CollectionExtract(ST_GeomFromGeoJSON(:geom), 3),
                                    4326
                                ),
                                :local_srid
                            )
                        ),
                        ST_Multi(
                            ST_SetSRID(ST_CollectionExtract(ST_GeomFromGeoJSON(:geom), 3), 4326)
                        ),
                        true
                    )
                    RETURNING id_area
                    """),
                {
                    "id_type": id_type,
                    "area_code": area_code,
                    "area_name": area_name,
                    "geom": geom_str,
                    "local_srid": local_srid,
                },
            ).scalar_one()
        else:
            id_area = existing
            db.session.execute(
                sa.text("""
                    UPDATE ref_geo.l_areas
                    SET area_name = :area_name,
                        geom = ST_Multi(
                            ST_Transform(
                                ST_SetSRID(
                                    ST_CollectionExtract(ST_GeomFromGeoJSON(:geom), 3),
                                    4326
                                ),
                                :local_srid
                            )
                        ),
                        geom_4326 = ST_Multi(
                            ST_SetSRID(ST_CollectionExtract(ST_GeomFromGeoJSON(:geom), 3), 4326)
                        ),
                        meta_update_date = now()
                    WHERE id_area = :id_area
                    """),
                {
                    "area_name": area_name,
                    "geom": geom_str,
                    "local_srid": local_srid,
                    "id_area": id_area,
                },
            )

        # Associer l'area à toutes les permissions de la demande
        area = db.session.get(LAreas, id_area)
        if area is not None:
            for perm in permission_request.permissions:
                current_ids = {a.id_area for a in perm.areas_filter}
                if id_area not in current_ids:
                    perm.areas_filter.append(area)

    else:
        # Retirer de areas_filter en premier (supprime cor_permission_area),
        # puis flusher avant de supprimer l_areas (contrainte FK).
        for perm in permission_request.permissions:
            perm.areas_filter = [
                a
                for a in perm.areas_filter
                if not (getattr(a.area_type, "type_code", None) == _AREA_TYPE_CODE)
            ]
        db.session.flush()
        db.session.execute(
            sa.text(
                "DELETE FROM ref_geo.l_areas WHERE id_type = :id_type AND area_code = :area_code"
            ),
            {"id_type": id_type, "area_code": area_code},
        )


## ########################################################################
## MAP DATA
## ########################################################################


@blueprint.route("/<int(signed=True):id_permission_request>/map-data", methods=["GET"])
@login_required
@permissions.check_cruved_scope("R", get_scope=True, module_code=MODULE_CODE)
@json_resp
def map_data(scope, id_permission_request):
    query = PermissionRequest.filter_by_scope(scope)
    permission_request = (
        db.session.scalars(query.filter_by(id_permission_request=id_permission_request))
        .unique()
        .one_or_none()
    )
    if permission_request is None:
        raise NotFound(f"Permission request {id_permission_request} not found")

    if permission_request.custom_area is not None:
        return permission_request.custom_area.geojson_data

    ref = permission_request._ref_permission
    areas = ref.areas_filter if ref is not None else []
    if not areas:
        return {"type": "FeatureCollection", "features": []}

    features = (
        db.session.execute(
            sa.text("""
            SELECT json_build_object(
                'type', 'Feature',
                'geometry', ST_AsGeoJSON(geom_4326)::json,
                'properties', json_build_object('area_name', area_name, 'area_code', area_code)
            )
            FROM ref_geo.l_areas
            WHERE id_area = ANY(:ids)
            """),
            {"ids": [area.id_area for area in areas]},
        )
        .scalars()
        .all()
    )

    return {"type": "FeatureCollection", "features": [f for f in features]}


## ########################################################################
## CUSTOM AREA DOWNLOAD
## ########################################################################


@blueprint.route("/<int(signed=True):id_permission_request>/custom-area/download", methods=["GET"])
@login_required
@permissions.check_cruved_scope("R", get_scope=True, module_code=MODULE_CODE)
def download_custom_area(scope, id_permission_request):
    import json

    from flask import Response

    query = PermissionRequest.filter_by_scope(scope)
    permission_request = (
        db.session.scalars(query.filter_by(id_permission_request=id_permission_request))
        .unique()
        .one_or_none()
    )
    if permission_request is None:
        raise NotFound(f"Permission request {id_permission_request} not found")
    if permission_request.custom_area is None:
        raise NotFound("No custom area for this permission request")

    file_name = permission_request.custom_area.file_name or "custom_area.geojson"
    return Response(
        json.dumps(permission_request.custom_area.geojson_data),
        mimetype="application/geo+json",
        headers={"Content-Disposition": f'attachment; filename="{file_name}"'},
    )


## ########################################################################
## CUSTOM AREA PARSING
## ########################################################################


_INVALID_GEOJSON_MSG = "Le GeoJSON fourni n'est pas valide."


def _parse_custom_area(geojson: dict, file_name: str | None = None) -> CustomArea:
    if geojson.get("type") not in ("FeatureCollection", "Feature"):
        raise BadRequest(_INVALID_GEOJSON_MSG)

    geometries = _geometries_from_geojson(geojson)
    if not geometries:
        raise BadRequest(_INVALID_GEOJSON_MSG)

    # seuls les polygones survivent au ST_CollectionExtract de la mise en base
    if not any(geom.get("type") in ("Polygon", "MultiPolygon") for geom in geometries):
        raise BadRequest("Le GeoJSON fourni ne contient aucun polygone.")

    return CustomArea(geojson_data=geojson, file_name=file_name)


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
    orderby = request.args.get("orderby", "created_on")
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

    module_config = current_app.config[MODULE_CODE]
    allowed_scopes = {
        scope.strip().upper()
        for scope in module_config.get("SCOPE_FILTER", {}).get("ALLOWED_VALUES", [])
    }
    scope_filters = []
    for scope_value in request.args.getlist("scope"):
        normalized_scope = _normalize_scope(scope_value)
        if normalized_scope not in allowed_scopes:
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
        query = query.outerjoin(permission_alias, PermissionRequest.permissions)

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
                sa.or_(*[PermissionRequest.permissions.any(clause) for clause in clauses])
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
                sa.or_(*[PermissionRequest.permissions.any(clause) for clause in clauses])
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

    forbidden_fields = {
        "status",
        "validated",
        "id_validator",
        "id_author",
        "author",
        "validator",
    }
    if forbidden_fields.intersection(payload.keys()):
        raise BadRequest(
            f"Fields {', '.join(sorted(forbidden_fields))} are not allowed during creation."
        )

    allowed_fields = {
        "description",
        "expiration_date",
        "taxa",
        "areas",
        "sensitivity_filter",
        "scope",
        "custom_area",
        "additional_data",
    }
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
    created_on = date.today()
    if created_on > expiration_date:
        raise BadRequest("expiration_date must be on or after today's date.")

    description_value = payload.get("description")
    if description_value is not None and not isinstance(description_value, str):
        raise BadRequest("description must be a string or null.")

    additional_data_value = payload.get("additional_data")
    if additional_data_value is not None and not isinstance(additional_data_value, dict):
        raise BadRequest("additional_data must be a JSON object or null.")

    scope_value = _normalize_scope(payload.get("scope", SCOPE_USER))
    if scope_value is None:
        raise BadRequest("scope must be provided as a string.")
    allowed_scopes = (
        current_app.config[MODULE_CODE].get("SCOPE_FILTER", {}).get("ALLOWED_VALUES", [])
    )
    if scope_value not in allowed_scopes:
        raise BadRequest(f"Unsupported scope value '{scope_value}'.")

    taxa_ids = payload.get("taxa", [])
    if not isinstance(taxa_ids, list):
        raise BadRequest("taxa must be an array of integers.")
    try:
        normalized_taxa_ids = [int(taxon_id) for taxon_id in taxa_ids]
    except (TypeError, ValueError) as exc:
        raise BadRequest("taxa must contain only integer values.") from exc

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
    allowed_area_type_codes = current_app.config[MODULE_CODE].get("ALLOWED_AREA_TYPE_CODES")
    invalid_area_types = sorted(
        {
            area_id
            for area_id in normalized_area_ids
            if area_id in areas_by_id
            and getattr(areas_by_id[area_id].area_type, "type_code", None)
            not in allowed_area_type_codes
        }
    )
    if invalid_area_types:
        allowed_codes = ", ".join(sorted(allowed_area_type_codes))
        raise BadRequest(
            f"Areas must belong to one of the allowed types ({allowed_codes}). "
            f"Invalid areas: {', '.join(map(str, invalid_area_types))}."
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

    object_id = db.session.scalars(
        select(PermObject.id_object).where(PermObject.code_object == "ALL")
    ).one_or_none()
    if object_id is None:
        raise InternalServerError("Permission object 'ALL' not found in permissions configuration.")

    created_on_value = datetime.combine(created_on, datetime.min.time())
    expire_on_value = datetime.combine(expiration_date, datetime.min.time())

    allow_custom_area = current_app.config[MODULE_CODE].get("ALLOW_CUSTOM_AREA", False)
    custom_area_value = payload.get("custom_area")
    custom_area = None
    if custom_area_value is not None:
        if not allow_custom_area:
            raise BadRequest("Custom area is not allowed by the module configuration.")
        if not isinstance(custom_area_value, dict):
            raise BadRequest("custom_area must be an object with a 'geojson' field.")
        raw_geojson = custom_area_value.get("geojson")
        if not isinstance(raw_geojson, dict):
            raise BadRequest("custom_area.geojson is required and must be a GeoJSON object.")
        raw_file_name = custom_area_value.get("file_name")
        file_name = str(raw_file_name).strip() or None if isinstance(raw_file_name, str) else None
        custom_area = _parse_custom_area(raw_geojson, file_name=file_name)

    if not areas_list and custom_area is None:
        raise BadRequest("At least one area or a custom GeoJSON area is required.")

    permissions_to_create = current_app.config[MODULE_CODE].get("PERMISSIONS_TO_CREATE", [])
    if not permissions_to_create:
        raise InternalServerError("PERMISSIONS_TO_CREATE is empty in module configuration.")

    # Resolve module/action ids once per unique (module_code, action_code) pair
    _module_id_cache = {}
    _action_id_cache = {}

    def _get_module_id(module_code):
        if module_code not in _module_id_cache:
            mid = db.session.scalars(
                select(TModules.id_module).where(TModules.module_code == module_code)
            ).one_or_none()
            if mid is None:
                raise InternalServerError(f"Module '{module_code}' not found in configuration.")
            _module_id_cache[module_code] = mid
        return _module_id_cache[module_code]

    def _get_action_id(action_code):
        if action_code not in _action_id_cache:
            aid = db.session.scalars(
                select(PermAction.id_action).where(PermAction.code_action == action_code)
            ).one_or_none()
            if aid is None:
                raise InternalServerError(f"Action '{action_code}' not found in configuration.")
            _action_id_cache[action_code] = aid
        return _action_id_cache[action_code]

    permission_request = PermissionRequest(
        id_author=current_user.id_role,
        id_validator=None,
        description=description_value,
        additional_data=additional_data_value,
    )
    if custom_area is not None:
        permission_request.custom_area = custom_area

    for perm_def in permissions_to_create:
        perm = Permission(
            id_role=permission_role_id,
            id_action=_get_action_id(perm_def["action"]),
            id_module=_get_module_id(perm_def["module"]),
            id_object=object_id,
            scope_value=None,
            sensitivity_filter=sensitivity_filter_value,
            created_on=created_on_value,
            expire_on=expire_on_value,
            validated=None,
        )
        perm.taxons_filter = list(taxa_list)
        perm.areas_filter = list(areas_list)
        permission_request.permissions.append(perm)

    db.session.add(permission_request)

    # WARNING: force NULL (=None) to all permissions validated field to
    # enable PENDING status by default.
    desired_validated = None
    db.session.flush()
    for p in permission_request.permissions:
        if p.validated != desired_validated:
            p.validated = desired_validated

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

    forbidden_fields = {"status", "validated", "id_validator", "created_on"}
    if forbidden_fields.intersection(payload.keys()):
        raise BadRequest("Fields status, validated, id_validator and created_on cannot be updated.")

    allowed_fields = {
        "description",
        "expiration_date",
        "taxa",
        "areas",
        "sensitivity_filter",
        "scope",
        "custom_area",
        "additional_data",
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

    if permission_request.validated is not None:
        permission_request.validated = None
        permission_request.id_validator = None
        permission_request.validation_description = None
        _sync_custom_area_to_l_areas(permission_request)

    if "description" in payload:
        permission_request.description = payload.get("description")

    if "additional_data" in payload:
        additional_data_value = payload.get("additional_data")
        if additional_data_value is not None and not isinstance(additional_data_value, dict):
            raise BadRequest("additional_data must be a JSON object or null.")
        permission_request.additional_data = additional_data_value

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
        allowed_scopes = (
            current_app.config[MODULE_CODE].get("SCOPE_FILTER", {}).get("ALLOWED_VALUES", [])
        )
        if scope_value is None or scope_value not in allowed_scopes:
            raise BadRequest(f"Unsupported scope value '{raw_scope}'.")
        author = permission_request.author
        new_role_id = _resolve_permission_role(
            scope_value,
            author_role_id=author.id_role,
            author_organism_id=author.id_organisme,
        )
        for p in permission_request.permissions:
            p.id_role = new_role_id

    if "sensitivity_filter" in payload:
        sensitivity_value = payload.get("sensitivity_filter")
        if not isinstance(sensitivity_value, bool):
            raise BadRequest("sensitivity_filter must be a boolean value.")
        if not permission_request.permissions:
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
        taxa_query = select(Taxref).where(Taxref.cd_nom.in_(normalized_taxa_ids))
        taxa_items = db.session.scalars(taxa_query).all()
        taxa_by_id = {taxon.cd_nom: taxon for taxon in taxa_items}
        missing_taxa = sorted(
            {taxon_id for taxon_id in normalized_taxa_ids if taxon_id not in taxa_by_id}
        )
        if missing_taxa:
            raise BadRequest(
                "Some taxa identifiers are invalid or unknown: "
                f"{', '.join(map(str, missing_taxa))}."
            )
        if not permission_request.permissions:
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
                "Some area identifiers are invalid or unknown: "
                f"{', '.join(map(str, missing_area_ids))}."
            )
        allowed_area_type_codes = current_app.config[MODULE_CODE].get("ALLOWED_AREA_TYPE_CODES")
        invalid_area_types = sorted(
            {
                area_id
                for area_id in normalized_area_ids
                if area_id in areas_by_id
                and getattr(areas_by_id[area_id].area_type, "type_code", None)
                not in allowed_area_type_codes
            }
        )
        if invalid_area_types:
            allowed_codes = ", ".join(sorted(allowed_area_type_codes))
            raise BadRequest(
                f"Areas must belong to one of the allowed types ({allowed_codes}). "
                f"Invalid areas: {', '.join(map(str, invalid_area_types))}."
            )
        if not permission_request.permissions:
            raise InternalServerError("No permission is linked to this permission request.")
        new_areas = [areas_by_id[area_id] for area_id in normalized_area_ids]
        for p in permission_request.permissions:
            p.areas_filter = list(new_areas)

    if "custom_area" in payload:
        allow_custom_area = current_app.config[MODULE_CODE].get("ALLOW_CUSTOM_AREA", False)
        custom_area_value = payload.get("custom_area")
        if custom_area_value is None:
            permission_request.custom_area = None
        else:
            if not allow_custom_area:
                raise BadRequest("Custom area is not allowed.")
            if not isinstance(custom_area_value, dict):
                raise BadRequest("custom_area must be an object with a 'geojson' field.")
            raw_geojson = custom_area_value.get("geojson")
            if not isinstance(raw_geojson, dict):
                raise BadRequest("custom_area.geojson is required and must be a GeoJSON object.")
            raw_file_name = custom_area_value.get("file_name")
            file_name = (
                str(raw_file_name).strip() or None if isinstance(raw_file_name, str) else None
            )
            new_custom_area = _parse_custom_area(raw_geojson, file_name=file_name)
            if permission_request.custom_area is not None:
                permission_request.custom_area.geojson_data = new_custom_area.geojson_data
                permission_request.custom_area.file_name = new_custom_area.file_name
            else:
                permission_request.custom_area = new_custom_area

    ref = permission_request._ref_permission
    has_areas = bool(ref and ref.areas_filter)
    if not has_areas and permission_request.custom_area is None:
        raise BadRequest("At least one area or a custom GeoJSON area is required.")

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

    permission_request.validated = None
    _sync_custom_area_to_l_areas(permission_request)
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

    if not permission_request.permissions:
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

    _sync_custom_area_to_l_areas(permission_request)
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
