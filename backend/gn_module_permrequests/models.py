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
SCOPE_USER = "USER"
SCOPE_ORGANISM = "ORGANISM"


cor_request_permission = DB.Table(
    "cor_request_permission",
    DB.Model.metadata,
    DB.Column(
        "id_request", DB.Integer, DB.ForeignKey(f"{SCHEMA_NAME}.t_requests.id_request")
    ),
    DB.Column(
        "id_permission", DB.Integer, DB.ForeignKey("gn_permissions.t_permissions.id_permission")
    ),
    schema=SCHEMA_NAME,
)


class PermissionRequest(DB.Model):
    __tablename__ = "t_requests"
    __table_args__ = {"schema": SCHEMA_NAME}

    id_permission_request = DB.Column(
        "id_request",
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
    permissions = DB.relationship(
        Permission,
        secondary=cor_request_permission,
        cascade="all, delete-orphan",
        single_parent=True,
        lazy="joined",
    )

    @classmethod
    def filter_by_scope(cls, scope, *, user=None):
        if user is None:
            user = g.current_user
        if scope == 0:
            return sa.false()
        elif scope == 1:
            return cls.permission.has(Permission.role == user)
        elif scope == 2:
            return sa.or_(
                cls.permission.has(Permission.role == user),
                cls.permission.has(Permission.role.has(User.id_organisme == user.id_organisme)),
            )
        elif scope == 3:
            return sa.true()

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
    def created_on(self):
        if not self.permissions or self.permissions[0].created_on is None:
            return None
        return self.permissions[0].created_on.date()

    @created_on.setter
    def created_on(self, value):
        if not self.permissions:
            raise AttributeError("No permission is linked to this permission request.")
        new_date = None
        if isinstance(value, datetime):
            new_date = value
        elif value is not None:
            new_date = datetime.combine(value, datetime.min.time())
        for p in self.permissions:
            p.created_on = new_date

    @created_on.expression
    def created_on(cls):
        return (
            sa.select(sa.func.date(Permission.created_on))
            .join(cor_request_permission)
            .where(cor_request_permission.c.id_request == cls.id_permission_request)
            .limit(1)
            .scalar_subquery()
        )

    @hybrid_property
    def expiration_date(self):
        if not self.permissions or self.permissions[0].expire_on is None:
            return None
        expire_on = self.permissions[0].expire_on
        return expire_on.date()

    @expiration_date.setter
    def expiration_date(self, value):
        if not self.permissions:
            raise AttributeError("No permission is linked to this permission request.")
        new_date = None
        if isinstance(value, datetime):
            new_date = value
        elif value is not None:
            new_date = datetime.combine(value, datetime.min.time())
        for p in self.permissions:
            p.expire_on = new_date

    @expiration_date.expression
    def expiration_date(cls):
        return (
            sa.select(sa.func.date(Permission.expire_on))
            .join(cor_request_permission)
            .where(cor_request_permission.c.id_request == cls.id_permission_request)
            .limit(1)
            .scalar_subquery()
        )

    @hybrid_property
    def validated(self):
        if not self.permissions:
            return None
        return self.permissions[0].validated

    @validated.setter
    def validated(self, value):
        if not self.permissions:
            raise AttributeError("No permission is linked to this permission request.")
        previous = self.permissions[0].validated if self.permissions else None
        if previous != value:
            self.validation_date = datetime.now()
        for p in self.permissions:
            p.validated = value

    @validated.expression
    def validated(cls):
        return (
            sa.select(Permission.validated)
            .join(cor_request_permission)
            .where(cor_request_permission.c.id_request == cls.id_permission_request)
            .limit(1)
            .scalar_subquery()
        )

    @property
    def scope(self):
        if not self.permissions or self.permissions[0].id_role is None or self.id_author is None:
            return None

        permission = self.permissions[0]

        if permission.id_role == self.id_author:
            return SCOPE_USER

        role = permission.role
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
        if not self.permissions:
            return None
        return self.permissions[0].sensitivity_filter

    @sensitivity_filter.setter
    def sensitivity_filter(self, value):
        if not self.permissions:
            raise AttributeError("No permission is linked to this permission request.")
        if value is None:
            raise ValueError("sensitivity_filter cannot be null.")
        bool_value = bool(value)
        for p in self.permissions:
            p.sensitivity_filter = bool_value

    @sensitivity_filter.expression
    def sensitivity_filter(cls):
        return (
            sa.select(Permission.sensitivity_filter)
            .join(cor_request_permission)
            .where(cor_request_permission.c.id_request == cls.id_permission_request)
            .limit(1)
            .scalar_subquery()
        )

    @property
    def taxa(self):
        if not self.permissions:
            return []
        # Assuming all permissions have the same taxa filter
        return self.permissions[0].taxons_filter

    @taxa.setter
    def taxa(self, value):
        if not self.permissions:
            raise AttributeError("No permission is linked to this permission request.")
        for p in self.permissions:
            p.taxons_filter = value
