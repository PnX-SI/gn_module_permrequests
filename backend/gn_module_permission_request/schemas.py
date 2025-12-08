from marshmallow import fields
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field
from pypnusershub.db.models import User
from apptax.taxonomie.models import Taxref
from ref_geo.models import LAreas

from geonature.utils.schema import CruvedSchemaMixin

from .models import PermissionRequest
from .status_utils import compute_status
from . import MODULE_CODE


class PermissionRequestUserSchema(SQLAlchemySchema):
    class Meta:
        model = User
        load_instance = False
        include_fk = True

    nom_complet = fields.Function(lambda obj: obj.nom_complet)


class PermissionRequestTaxonSchema(SQLAlchemySchema):
    class Meta:
        model = Taxref
        load_instance = False

    cd_nom = auto_field()
    lb_nom = auto_field()


class PermissionRequestAreaSchema(SQLAlchemySchema):
    class Meta:
        model = LAreas
        load_instance = False
        include_fk = True

    id_area = auto_field()
    area_name = auto_field()
    area_code = auto_field()


class PermissionRequestSchema(CruvedSchemaMixin, SQLAlchemySchema):
    class Meta:
        model = PermissionRequest
        load_instance = False
        include_relationships = True
        include_fk = True

    __module_code__ = MODULE_CODE

    id_permission_request = auto_field()
    id_author = auto_field()
    id_validator = auto_field()
    initialization_date = fields.Date(attribute="initialization_date", dump_only=True)
    expiration_date = fields.Date(attribute="expiration_date", dump_only=True)
    validated = fields.Boolean(attribute="validated", allow_none=True, dump_only=True)
    validation_date = fields.DateTime(attribute="validation_date", allow_none=True, dump_only=True)
    sensitivity_filter = fields.Boolean(attribute="sensitivity_filter", dump_only=True)
    scope = fields.Method("get_scope", dump_only=True)
    description = auto_field()
    validation_description = auto_field(dump_only=True)
    taxa = fields.Nested(PermissionRequestTaxonSchema, many=True, dump_only=True)
    areas = fields.Nested(
        PermissionRequestAreaSchema,
        many=True,
        attribute="permission.areas_filter",
        dump_only=True,
    )
    author = fields.Nested(PermissionRequestUserSchema, dump_only=True)
    validator = fields.Nested(PermissionRequestUserSchema, dump_only=True)
    status = fields.Method("get_status", dump_only=True)
    cruved = fields.Method("get_cruved", dump_only=True)

    def get_status(self, obj):
        return compute_status(obj.validated, obj.initialization_date, obj.expiration_date)

    def get_scope(self, obj):
        return obj.scope

    def get_cruved(self, obj):
        base = CruvedSchemaMixin.get_cruved(self, obj)
        if not base:
            return {action: False for action in ["C", "R", "U", "V", "D"]}
        return {action: base.get(action, False) for action in ["C", "R", "U", "V", "D"]}
