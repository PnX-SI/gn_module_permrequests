"""
Définition des routes du module export
"""


from flask import Blueprint, current_app, request
from sqlalchemy import desc, asc
from werkzeug.exceptions import BadRequest

from geonature.core.gn_permissions import decorators as permissions
from geonature.core.gn_permissions.decorators import login_required
from geonature.utils.env import db
from utils_flask_sqla.response import json_resp

from . import MODULE_CODE
from .models import AccessRequest
from .schemas import AccessRequestSchema


blueprint = Blueprint("access_request", __name__, cli_group="access_request")
access_request_schema = AccessRequestSchema(many=True)

from enum import Enum
class SortOrder(Enum):
    ASC = "asc"
    DESC = "desc"

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


    query = AccessRequest.query

    # Sort
    if sort == SortOrder.ASC:
        query = query.order_by(asc(orderby))
    query = query.order_by(desc(orderby))

    # Paginate
    pagination = db.paginate(query, page=page, per_page=per_page, error_out=False)

    return {
        "items": access_request_schema.dump(pagination.items),
        "total": pagination.total,
        "page": pagination.page,
        "per_page": pagination.per_page,
    }
