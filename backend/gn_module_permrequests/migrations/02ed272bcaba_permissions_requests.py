"""permissions requests

Revision ID: 02ed272bcaba
Revises: 
Create Date: 2024-09-30 17:13:44.650757

"""

from alembic import op
from gn_module_permrequests import MODULE_CODE
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSON


# revision identifiers, used by Alembic.
revision = "02ed272bcaba"
down_revision = None
branch_labels = "permissions_requests"
depends_on = ("707390c722fe",)


def upgrade():
    conn = op.get_bind()
    metadata = sa.MetaData(bind=conn)
    module = sa.Table("t_modules", metadata, schema="gn_commons", autoload_with=conn)
    id_module = conn.execute(sa.select(module).where(module.c.module_code == MODULE_CODE)).scalar()
    object = sa.Table("t_objects", metadata, schema="gn_permissions", autoload_with=conn)
    id_object = conn.execute(sa.select(object).where(object.c.code_object == "ALL")).scalar()
    action = sa.Table("bib_actions", metadata, schema="gn_permissions", autoload_with=conn)
    id_action_create = conn.execute(sa.select(action).where(action.c.code_action == "C")).scalar()
    id_action_read = conn.execute(sa.select(action).where(action.c.code_action == "R")).scalar()
    id_action_update = conn.execute(sa.select(action).where(action.c.code_action == "U")).scalar()
    id_action_validate = conn.execute(sa.select(action).where(action.c.code_action == "V")).scalar()
    id_action_delete = conn.execute(sa.select(action).where(action.c.code_action == "D")).scalar()
    permissions_available = sa.Table(
        "t_permissions_available", metadata, schema="gn_permissions", autoload_with=conn
    )
    op.execute(
        sa.insert(permissions_available).values(
            [
                {
                    "id_module": id_module,
                    "id_object": id_object,
                    "id_action": id_action_create,
                    "label": "Créer des demandes de permissions",
                    "scope_filter": True,
                },
                {
                    "id_module": id_module,
                    "id_object": id_object,
                    "id_action": id_action_read,
                    "label": "Voir les demandes de permissions",
                    "scope_filter": True,
                },
                {
                    "id_module": id_module,
                    "id_object": id_object,
                    "id_action": id_action_update,
                    "label": "Modifier des demandes de permissions",
                    "scope_filter": True,
                },
                {
                    "id_module": id_module,
                    "id_object": id_object,
                    "id_action": id_action_validate,
                    "label": "Valider les demandes de permissions",
                    "scope_filter": False,
                },
                {
                    "id_module": id_module,
                    "id_object": id_object,
                    "id_action": id_action_delete,
                    "label": "Supprimer les demandes de permissions",
                    "scope_filter": True,
                },
            ]
        )
    )

    op.create_table(
        "t_permissions_requests",
        sa.Column(
            "id_permission",
            sa.Integer,
            sa.ForeignKey(
                "gn_permissions.t_permissions.id_permission",
                onupdate="CASCADE",
                ondelete="CASCADE",
            ),
            primary_key=True,
        ),
        sa.Column("created_on", sa.DateTime, server_default=sa.func.now()),
        sa.Column("validated_on", sa.DateTime),
        sa.Column("validated_by", sa.Integer, sa.ForeignKey("utilisateurs.t_roles.id_role")),
        sa.Column("extras", JSON, nullable=True),
        schema="gn_permissions",
    )

    notification_category = sa.Table(
        "bib_notifications_categories",
        metadata,
        schema="gn_notifications",
        autoload_with=conn,
    )
    op.execute(
        sa.insert(notification_category).values(
            [
                {
                    "code": "PERMISSIONS-REQUESTS-CREATED",
                    "label": "Création d’une demande de permissions",
                    "description": "Se déclanche lors de la création d’une nouvelle demande de permissions.",
                },
                {
                    "code": "PERMISSIONS-REQUESTS-VALIDATED",
                    "label": "Validation d’une demande de permissions",
                    "description": "Se déclanche lors de la validation d’une demande de permissions.",
                },
            ]
        )
    )
    notification_template = sa.Table(
        "bib_notifications_templates",
        metadata,
        schema="gn_notifications",
        autoload_with=conn,
    )
    op.execute(
        sa.insert(notification_template).values(
            [
                {
                    "code_category": "PERMISSIONS-REQUESTS-CREATED",
                    "code_method": "DB",
                    "content": "Nouvelle demande de permissions de {{ request.permission.role.nom_complet }}",
                },
                {
                    "code_category": "PERMISSIONS-REQUESTS-CREATED",
                    "code_method": "EMAIL",
                    "content": "Nouvelle demande de permissions de {{ request.permission.role.nom_complet }}",
                },
                {
                    "code_category": "PERMISSIONS-REQUESTS-VALIDATED",
                    "code_method": "DB",
                    "content": "Votre demande de permissions n⁰{{ request.id_permission }} a été {% if request.permission.validated %}acceptée{% else %}refusée{% endif %}.",
                },
                {
                    "code_category": "PERMISSIONS-REQUESTS-VALIDATED",
                    "code_method": "EMAIL",
                    "content": "Votre demande de permissions n⁰{{ request.id_permission }} a été {% if request.permission.validated %}acceptée{% else %}refusée{% endif %}.",
                },
            ]
        )
    )


def downgrade():
    conn = op.get_bind()
    metadata = sa.MetaData(bind=conn)
    notification_template = sa.Table(
        "bib_notifications_templates",
        metadata,
        schema="gn_notifications",
        autoload_with=conn,
    )
    op.execute(
        sa.delete(notification_template).where(
            notification_template.c.code_category.in_(
                ["PERMISSIONS-REQUESTS-CREATED", "PERMISSIONS-REQUESTS-VALIDATED"]
            )
        )
    )
    notification_category = sa.Table(
        "bib_notifications_categories",
        metadata,
        schema="gn_notifications",
        autoload_with=conn,
    )
    op.execute(
        sa.delete(notification_category).where(
            notification_category.c.code.in_(
                ["PERMISSIONS-REQUESTS-CREATED", "PERMISSIONS-REQUESTS-VALIDATED"]
            )
        )
    )
    op.drop_table(table_name="t_permissions_requests", schema="gn_permissions")

    module = sa.Table("t_modules", metadata, schema="gn_commons", autoload_with=conn)
    id_module = conn.execute(sa.select(module).where(module.c.module_code == MODULE_CODE)).scalar()
    permissions_available = sa.Table(
        "t_permissions_available", metadata, schema="gn_permissions", autoload_with=conn
    )
    op.execute(
        sa.delete(permissions_available).where(permissions_available.c.id_module == id_module)
    )
