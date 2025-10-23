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
class GnModuleSchemaConf(Schema):
    MODULE_URL = fields.String(load_default="/access_request")
    VALIDATION_STATUS_INFO = fields.Dict(fields.Dict(), load_default=DEFAULT_VALIDATION_STATUS_INFO)
