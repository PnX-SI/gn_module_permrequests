from geonature.utils.env import db, ma

from marshmallow_sqlalchemy.fields import Nested

from geonature.core.gn_permissions.schemas import PermissionSchema

from utils_flask_sqla.schema import SmartRelationshipsMixin

from gn_module_permrequests.models import PermissionRequest


class PermissionRequestSchema(SmartRelationshipsMixin, ma.SQLAlchemyAutoSchema):
    class Meta:
        model = PermissionRequest
        include_fk = True
        load_instance = True
        sqla_session = db.session

    permission = Nested(PermissionSchema)
