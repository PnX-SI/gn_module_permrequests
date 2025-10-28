from datetime import date

from marshmallow import fields
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field
from pypnusershub.db.models import User
from apptax.taxonomie.models import Taxref

from geonature.utils.schema import CruvedSchemaMixin

from .models import AccessRequest
from . import MODULE_CODE


class AccessRequestUserSchema(SQLAlchemySchema):
    class Meta:
        model = User
        load_instance = False
        include_fk = True

    nom_complet = fields.Function(lambda obj: getattr(obj, "nom_complet", None))


class AccessRequestTaxonSchema(SQLAlchemySchema):
    class Meta:
        model = Taxref
        load_instance = False

    cd_nom = auto_field()
    lb_nom = auto_field()


class AccessRequestSchema(CruvedSchemaMixin, SQLAlchemySchema):
    class Meta:
        model = AccessRequest
        load_instance = False
        include_relationships = True
        include_fk = True

    __module_code__ = MODULE_CODE

    id_access_request = auto_field()
    id_author = auto_field()
    id_validator = auto_field()
    initialization_date = fields.Date(attribute="initialization_date", dump_only=True)
    expiration_date = fields.Date(attribute="expiration_date", dump_only=True)
    description = auto_field()
    taxa = fields.Nested(AccessRequestTaxonSchema, many=True, dump_only=True)
    author = fields.Nested(AccessRequestUserSchema, dump_only=True)
    validator = fields.Nested(AccessRequestUserSchema, dump_only=True)
    status = fields.Method("get_status", dump_only=True)
    cruved = fields.Method("get_cruved", dump_only=True)

    def get_status(self, obj):
        expiration = getattr(obj, "expiration_date", None)
        if expiration is None:
            return "demande expirée"
        today = date.today()
        if expiration < today:
            return "demande active"
        return "demande expirée"

    def get_permissions(self, obj):
        return [permission.id_permission for permission in getattr(obj, "permissions", [])]

    def get_cruved(self, obj):
        base = CruvedSchemaMixin.get_cruved(self, obj)
        if not base:
            return {action: False for action in ["C", "R", "U", "V", "D"]}
        return {action: base.get(action, False) for action in ["C", "R", "U", "V", "D"]}
