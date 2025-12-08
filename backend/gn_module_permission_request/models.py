from datetime import datetime

from flask import g

import sqlalchemy as sa
from sqlalchemy.ext.hybrid import hybrid_property

from geonature.utils.env import DB
from geonature.core.gn_permissions.models import Permission
from pypnusershub.db.models import User

from utils_flask_sqla.models import qfilter

from . import MODULE_CODE


SCHEMA_NAME = f"pr_{MODULE_CODE.lower()}"
TABLE_NAME = f"t_{MODULE_CODE.lower()}"
PRIMARY_KEY = "id_permission_request"

SCOPE_USER = "USER"
SCOPE_ORGANISM = "ORGANISM"


class PermissionRequest(DB.Model):
    __tablename__ = TABLE_NAME
    __table_args__ = {"schema": SCHEMA_NAME}

    id_permission_request = DB.Column(
        PRIMARY_KEY,
        DB.Integer,
        primary_key=True,
        autoincrement=True,
    )
    id_author = DB.Column(
        "id_author",
        DB.Integer,
        DB.ForeignKey("utilisateurs.t_roles.id_role"),
        nullable=False,
    )
    id_validator = DB.Column(
        "id_validator",
        DB.Integer,
        DB.ForeignKey("utilisateurs.t_roles.id_role"),
        nullable=True,
    )
    validation_description = DB.Column(DB.Text, nullable=True)
    validation_date = DB.Column(DB.DateTime, nullable=True)
    description = DB.Column(DB.Text, nullable=True)
    id_permission = DB.Column(
        DB.Integer,
        DB.ForeignKey("gn_permissions.t_permissions.id_permission", ondelete="SET NULL"),
        nullable=True,
        unique=True,
    )

    author = DB.relationship(
        User,
        foreign_keys=[id_author],
        lazy="joined",
    )
    validator = DB.relationship(
        User,
        foreign_keys=[id_validator],
        lazy="joined",
    )
    permission = DB.relationship(
        Permission,
        cascade="all, delete-orphan",
        single_parent=True,
        lazy="joined",
        backref=DB.backref("permission_request", uselist=False),
    )

    @qfilter(query=True)
    def filter_by_scope(cls, scope, *, query, user=None):
        if user is None:
            user = g.current_user
        if scope == 1:
            query = query.where(PermissionRequest.id_author == user.id_role)
        elif scope == 2:
            query = query.where(
                sa.or_(
                    PermissionRequest.id_author == user.id_role,
                    PermissionRequest.author.has(User.id_organisme == user.id_organisme),
                )
            )
        elif scope == 3:
            query = query.where(sa.true())
        else:
            query = query.where(sa.false())

        return query

    def has_instance_permission(self, scope, user=None):
        """
        Return True if the provided scope value grants permission to this permission request.
        Scope mapping follows the same logic as filter_by_scope:
            0 => no permission
            1 => author only
            2 => author or same organism (if any)
            3+ => full permission
        """
        if scope is None or scope <= 0:
            return False

        if scope >= 3:
            return True

        if user is None:
            user = g.current_user
        if user is None:
            return False

        if scope == 1:
            return self.id_author == user.id_role

        if scope == 2:
            if self.id_author == user.id_role:
                return True

            user_org = user.id_organisme
            author_org = self.author.id_organisme
            return author_org == user_org

        return False

    @hybrid_property
    def initialization_date(self):
        if self.permission is None or self.permission.created_on is None:
            return None
        return self.permission.created_on.date()

    @initialization_date.setter
    def initialization_date(self, value):
        if self.permission is None:
            raise AttributeError("No permission is linked to this permission request.")
        if value is None:
            self.permission.created_on = None
        elif isinstance(value, datetime):
            self.permission.created_on = value
        else:
            self.permission.created_on = datetime.combine(value, datetime.min.time())

    @initialization_date.expression
    def initialization_date(cls):
        return (
            sa.select(sa.func.date(Permission.created_on))
            .where(Permission.id_permission == cls.id_permission)
            .scalar_subquery()
        )

    @hybrid_property
    def expiration_date(self):
        if self.permission is None or self.permission.expire_on is None:
            return None
        expire_on = self.permission.expire_on
        return expire_on.date()

    @expiration_date.setter
    def expiration_date(self, value):
        if self.permission is None:
            raise AttributeError("No permission is linked to this permission request.")
        if value is None:
            self.permission.expire_on = None
        elif isinstance(value, datetime):
            self.permission.expire_on = value
        else:
            self.permission.expire_on = datetime.combine(value, datetime.min.time())

    @expiration_date.expression
    def expiration_date(cls):
        return (
            sa.select(sa.func.date(Permission.expire_on))
            .where(Permission.id_permission == cls.id_permission)
            .scalar_subquery()
        )

    @hybrid_property
    def validated(self):
        if self.permission is None:
            return None
        return self.permission.validated

    @validated.setter
    def validated(self, value):
        if self.permission is None:
            raise AttributeError("No permission is linked to this permission request.")
        previous = self.permission.validated
        if previous != value:
            self.validation_date = datetime.now()
        self.permission.validated = value

    @validated.expression
    def validated(cls):
        return (
            sa.select(Permission.validated)
            .where(Permission.id_permission == cls.id_permission)
            .scalar_subquery()
        )

    @property
    def scope(self):
        if self.permission is None or self.permission.id_role is None or self.author_id is None:
            return None

        if self.permission.id_role == self.author_id:
            return SCOPE_USER

        role = self.permission.role
        author = self.author
        if (
            role is not None
            and role.groupe
            and author is not None
            and author.id_organisme is not None
            and role.id_organisme == author.id_organisme
        ):
            return SCOPE_ORGANISM

        return None

    @hybrid_property
    def sensitivity_filter(self):
        if self.permission is None:
            return None
        return self.permission.sensitivity_filter

    @sensitivity_filter.setter
    def sensitivity_filter(self, value):
        if self.permission is None:
            raise AttributeError("No permission is linked to this permission request.")
        if value is None:
            raise ValueError("sensitivity_filter cannot be null.")
        self.permission.sensitivity_filter = bool(value)

    @sensitivity_filter.expression
    def sensitivity_filter(cls):
        return (
            sa.select(Permission.sensitivity_filter)
            .where(Permission.id_permission == cls.id_permission)
            .scalar_subquery()
        )

    @property
    def taxa(self):
        if self.permission is None:
            return []
        return self.permission.taxons_filter

    @taxa.setter
    def taxa(self, value):
        if self.permission is None:
            raise AttributeError("No permission is linked to this permission request.")
        self.permission.taxons_filter = value
