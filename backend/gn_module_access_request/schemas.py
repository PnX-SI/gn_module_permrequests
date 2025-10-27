from marshmallow import fields
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field
from pypnusershub.db.models import User
from pypnnomenclature.models import TNomenclatures as Nomenclature
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


class AccessRequestValidationSchema(SQLAlchemySchema):
    class Meta:
        model = Nomenclature
        load_instance = False

    code = fields.Function(lambda obj: getattr(obj, "cd_nomenclature", None))
    label = fields.Function(lambda obj: getattr(obj, "label_default", None))


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
    id_validation_status = auto_field()
    id_author = auto_field()
    id_validator = auto_field()
    initialization_date = fields.Date(attribute="initialization_date", dump_only=True)
    expiration_date = fields.Date(attribute="expiration_date", dump_only=True)
    description = auto_field()
    taxa = fields.Nested(AccessRequestTaxonSchema, many=True, dump_only=True)
    author = fields.Nested(AccessRequestUserSchema, dump_only=True)
    validator = fields.Nested(AccessRequestUserSchema, dump_only=True)
    validation_status = fields.Nested(AccessRequestValidationSchema, dump_only=True)
    cruved = fields.Method("get_cruved", dump_only=True)

    def get_permissions(self, obj):
        return [permission.id_permission for permission in getattr(obj, "permissions", [])]

    def get_cruved(self, obj):
        base = CruvedSchemaMixin.get_cruved(self, obj)
        if not base:
            return {action: False for action in ["C", "R", "U", "V", "D"]}
        return {action: base.get(action, False) for action in ["C", "R", "U", "V", "D"]}
