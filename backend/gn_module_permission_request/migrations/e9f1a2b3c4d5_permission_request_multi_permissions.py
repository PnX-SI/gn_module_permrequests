"""Replace id_permission FK with cor_permission_request_permission join table

Revision ID: a1b2c3d4e5f6
Revises: 7f3a1c8e0d92
Create Date: 2026-04-28 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

revision = "e9f1a2b3c4d5"
down_revision = "7f3a1c8e0d92"
depends_on = None

MODULE_CODE = "PERMISSION_REQUEST"
SCHEMA_NAME = f"pr_{MODULE_CODE.lower()}"
TABLE_NAME = f"t_{MODULE_CODE.lower()}"
COR_TABLE = f"cor_{MODULE_CODE.lower()}_permissions"
FK_TABLE = f"fk_{TABLE_NAME}_id_permission"


def upgrade():
    # Create join table
    op.create_table(
        COR_TABLE,
        sa.Column(
            "id_permission_request",
            sa.Integer(),
            sa.ForeignKey(
                f"{SCHEMA_NAME}.{TABLE_NAME}.id_permission_request",
                name=f"fk_{COR_TABLE}_id_permission_request",
                ondelete="CASCADE",
            ),
            nullable=False,
        ),
        sa.Column(
            "id_permission",
            sa.Integer(),
            sa.ForeignKey(
                "gn_permissions.t_permissions.id_permission",
                name=f"fk_{COR_TABLE}_id_permission",
                ondelete="CASCADE",
            ),
            nullable=False,
            unique=True,
        ),
        sa.PrimaryKeyConstraint("id_permission_request", "id_permission", name=f"pk_{COR_TABLE}"),
        schema=SCHEMA_NAME,
    )

    # Migrate existing rows
    op.execute(
        sa.text(
            f"""
            INSERT INTO {SCHEMA_NAME}.{COR_TABLE} (id_permission_request, id_permission)
            SELECT id_permission_request, id_permission
            FROM {SCHEMA_NAME}.{TABLE_NAME}
            WHERE id_permission IS NOT NULL
            """
        )
    )

    # Drop old FK and column
    op.drop_constraint(FK_TABLE, TABLE_NAME, type_="foreignkey", schema=SCHEMA_NAME)
    op.drop_column(TABLE_NAME, "id_permission", schema=SCHEMA_NAME)


def downgrade():
    # Re-add column
    op.add_column(
        TABLE_NAME,
        sa.Column("id_permission", sa.Integer(), nullable=True),
        schema=SCHEMA_NAME,
    )

    # Restore FK
    op.create_foreign_key(
        FK_TABLE,
        TABLE_NAME,
        "t_permissions",
        ["id_permission"],
        ["id_permission"],
        source_schema=SCHEMA_NAME,
        referent_schema="gn_permissions",
        ondelete="RESTRICT",
    )

    # Migrate back: restore first permission per request
    op.execute(
        sa.text(
            f"""
            UPDATE {SCHEMA_NAME}.{TABLE_NAME} t
            SET id_permission = c.id_permission
            FROM (
                SELECT DISTINCT ON (id_permission_request) id_permission_request, id_permission
                FROM {SCHEMA_NAME}.{COR_TABLE}
                ORDER BY id_permission_request, id_permission
            ) c
            WHERE t.id_permission_request = c.id_permission_request
            """
        )
    )

    op.drop_table(COR_TABLE, schema=SCHEMA_NAME)
