from apptax.taxonomie.models import Taxref
from flask import current_app
from geonature.utils.schema import CruvedSchemaMixin
from marshmallow import fields, post_dump
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field
from pypnusershub.db.models import User
from ref_geo.models import LAreas

from . import MODULE_CODE
from .models import CustomArea, PermissionRequest
from .status_utils import compute_status


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
    nom_valide = auto_field()


class PermissionRequestAreaSchema(SQLAlchemySchema):
    class Meta:
        model = LAreas
        load_instance = False
        include_fk = True

    id_area = auto_field()
    area_name = auto_field()
    area_code = auto_field()
    type_code = fields.Function(
        lambda obj: getattr(getattr(obj, "area_type", None), "type_code", None)
    )


class CustomAreaSchema(SQLAlchemySchema):
    class Meta:
        model = CustomArea
        load_instance = False
        include_fk = True

    id_custom_area = auto_field()
    id_permission_request = auto_field()
    geojson_data = auto_field()
    file_name = auto_field()


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
    created_on = fields.Date(attribute="created_on", dump_only=True)
    expiration_date = fields.Date(attribute="expiration_date", dump_only=True)
    validated = fields.Boolean(attribute="validated", allow_none=True, dump_only=True)
    validation_date = fields.DateTime(attribute="validation_date", allow_none=True, dump_only=True)
    sensitivity_filter = fields.Boolean(attribute="sensitivity_filter", dump_only=True)
    scope = fields.Method("get_scope", dump_only=True)
    description = auto_field()

    additional_data = auto_field()
    custom_fields = fields.Method("get_custom_fields", dump_only=True)

    validation_description = auto_field(dump_only=True)
    taxa = fields.Nested(PermissionRequestTaxonSchema, many=True, dump_only=True)
    areas = fields.Method("get_areas", dump_only=True)
    custom_area = fields.Nested(CustomAreaSchema, allow_none=True, dump_only=True)
    author = fields.Nested(PermissionRequestUserSchema, dump_only=True)
    validator = fields.Nested(PermissionRequestUserSchema, dump_only=True)
    status = fields.Method("get_status", dump_only=True)
    cruved = fields.Method("get_cruved", dump_only=True)

    def get_areas(self, obj):
        ref = obj._ref_permission
        if ref is None:
            return []
        return PermissionRequestAreaSchema(many=True).dump(ref.areas_filter)

    def get_status(self, obj):
        return compute_status(
            obj.validated,
            obj.created_on,
            obj.expiration_date,
            obj.id_validator,
        )

    def get_scope(self, obj):
        return obj.scope

    def get_cruved(self, obj):
        base = CruvedSchemaMixin.get_cruved(self, obj)
        if not base:
            return {action: False for action in ["C", "R", "U", "V", "D"]}
        return {action: base.get(action, False) for action in ["C", "R", "U", "V", "D"]}

    def get_custom_fields(self, obj):
        if not current_app.config[MODULE_CODE]["DYNAMIC_FORM"]:
            return None

        attr_infos = PermissionRequestSchema.build_dynamic_form_infos()
        attr_keys = attr_infos.keys()
        formated_fields = []
        for key, value in (obj.additional_data or {}).items():
            if key in attr_keys:
                cfg = {
                    "key": key,
                    "label": attr_infos.get(key)["label"],
                    "value": value,
                }
                for attr_infos_key, attr_infos_value in attr_infos.get(key).items():
                    cfg[attr_infos_key] = attr_infos_value
                formated_fields.append(cfg)
        return formated_fields

    @staticmethod
    def build_dynamic_form_infos():
        attr_infos = {}
        form_cfg = current_app.config[MODULE_CODE]["DYNAMIC_FORM"]
        for cfg in form_cfg:
            if all(key in cfg for key in ("type_widget", "attribut_name", "attribut_label")):
                attr_infos[cfg["attribut_name"]] = {
                    "type": cfg["type_widget"],
                    "label": cfg["attribut_label"],
                }
            if "icon" in cfg:
                attr_infos[cfg["attribut_name"]]["icon"] = cfg["icon"]
            if "icon_set" in cfg:
                attr_infos[cfg["attribut_name"]]["icon_set"] = cfg["icon_set"]

        return attr_infos

    @post_dump(pass_collection=True)
    def _remove_fields(self, data, many, **kwargs):
        # Remove necessary fields only with DYNAMIC_FORM parameter enabled
        if not current_app.config.get(MODULE_CODE, {}).get("DYNAMIC_FORM"):
            if many and isinstance(data, list):
                for item in data:
                    item.pop("custom_fields", None)
                    item.pop("additional_data", None)
            elif isinstance(data, dict):
                data.pop("custom_fields", None)
                data.pop("additional_data", None)
        return data
