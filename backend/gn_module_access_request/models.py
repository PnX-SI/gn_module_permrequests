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
PRIMARY_KEY = "id_access_request"

SCOPE_USER = "USER"
SCOPE_ORGANISM = "ORGANISM"


class AccessRequest(DB.Model):
    __tablename__ = TABLE_NAME
    __table_args__ = {"schema": SCHEMA_NAME}

    id_access_request = DB.Column(
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
        backref=DB.backref("access_request", uselist=False),
    )

    @qfilter(query=True)
    def filter_by_scope(cls, scope, *, query, user=None):
        if user is None:
            user = g.current_user
        if scope == 1:
            query = query.where(AccessRequest.id_author == user.id_role)
        elif scope == 2:
            query = query.where(
                sa.or_(
                    AccessRequest.id_author == user.id_role,
                    AccessRequest.author.has(User.id_organisme == user.id_organisme),
                )
            )
        elif scope == 3:
            query = query.where(sa.true())
        else:
            query = query.where(sa.false())

        return query

    def has_instance_permission(self, scope, user=None):
        """
        Return True if the provided scope value grants access to this access request.
        Scope mapping follows the same logic as filter_by_scope:
            0 => no access
            1 => author only
            2 => author or same organism (if any)
            3+ => full access
        """
        if scope is None or scope <= 0:
            return False

        if scope >= 3:
            return True

        if user is None:
            user = getattr(g, "current_user", None)
        if user is None:
            return False

        if scope == 1:
            return self.id_author == getattr(user, "id_role", None)

        if scope == 2:
            if self.id_author == getattr(user, "id_role", None):
                return True

            user_org = getattr(user, "id_organisme", None)
            if user_org is None:
                return False

            author_org = getattr(self.author, "id_organisme", None) if self.author else None
            return author_org == user_org

        return False

    @hybrid_property
    def initialization_date(self):
        permission = getattr(self, "permission", None)
        if permission is None or permission.created_on is None:
            return None
        return permission.created_on.date()

    @initialization_date.setter
    def initialization_date(self, value):
        if self.permission is None:
            raise AttributeError("No permission is linked to this access request.")
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
        permission = getattr(self, "permission", None)
        if permission is None or permission.expire_on is None:
            return None
        expire_on = permission.expire_on
        return expire_on.date() if hasattr(expire_on, "date") else expire_on

    @expiration_date.setter
    def expiration_date(self, value):
        if self.permission is None:
            raise AttributeError("No permission is linked to this access request.")
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
        permission = getattr(self, "permission", None)
        if permission is None:
            return None
        return permission.validated

    @validated.setter
    def validated(self, value):
        if self.permission is None:
            raise AttributeError("No permission is linked to this access request.")
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
        permission = getattr(self, "permission", None)
        author_id = getattr(self, "id_author", None)
        if permission is None or permission.id_role is None or author_id is None:
            return None

        if permission.id_role == author_id:
            return SCOPE_USER

        role = getattr(permission, "role", None)
        author = getattr(self, "author", None)
        if (
            role is not None
            and getattr(role, "groupe", False)
            and author is not None
            and getattr(author, "id_organisme", None) is not None
            and getattr(role, "id_organisme", None) == getattr(author, "id_organisme", None)
        ):
            return SCOPE_ORGANISM

        return None

    @hybrid_property
    def sensitivity_filter(self):
        permission = getattr(self, "permission", None)
        if permission is None:
            return None
        return permission.sensitivity_filter

    @sensitivity_filter.setter
    def sensitivity_filter(self, value):
        if self.permission is None:
            raise AttributeError("No permission is linked to this access request.")
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
        permission = getattr(self, "permission", None)
        if permission is None:
            return []
        return permission.taxons_filter

    @taxa.setter
    def taxa(self, value):
        if self.permission is None:
            raise AttributeError("No permission is linked to this access request.")
        self.permission.taxons_filter = value
