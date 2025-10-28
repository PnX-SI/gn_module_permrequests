"""
Spécification du schéma toml des paramètres de configurations
"""

from geonature.utils.env import ROOT_DIR
from marshmallow import Schema, fields

DEFAULT_VALIDATION_STATUS_INFO = {
    "VALIDATED": {"color": "#8BC34A"},  # validé
    "REFUSED": {"color": "#FF5722"},  # refusé
    "PENDING": {"color": "#0ed8ff"},  # en attent
}

DEFAULT_TERMS_ACKNOWLEDGMENT = {"TEXT": "J'ai lu et j'accepte les conditions."}


class TermsAcknowledgmentSchema(Schema):
    TEXT = fields.String(load_default=DEFAULT_TERMS_ACKNOWLEDGMENT["TEXT"])


class GnModuleSchemaConf(Schema):
    REQUIRE_TERMS_ACKNOWLEDGEMENT = fields.Boolean(load_default=True)
    TERMS_ACKNOWLEDGMENT = fields.Nested(
        TermsAcknowledgmentSchema, load_default=DEFAULT_TERMS_ACKNOWLEDGMENT
    )
    VALIDATION_STATUS_INFO = fields.Dict(
        fields.Dict(), load_default=DEFAULT_VALIDATION_STATUS_INFO
    )
