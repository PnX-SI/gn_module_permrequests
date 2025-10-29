"""move dates and validated to permission

Revision ID: e74fb2d90c61
Revises: c8bb2b5a9d21
Create Date: 2024-05-12 00:00:01.000000

"""

from alembic import op
import sqlalchemy as sa

MODULE_CODE = "ACCESS_REQUEST"
SCHEMA_NAME = f"pr_{MODULE_CODE.lower()}"
TABLE_NAME = f"t_{MODULE_CODE.lower()}"
PRIMARY_KEY = "id_access_request"

# revision identifiers, used by Alembic.
revision = "e74fb2d90c61"
down_revision = "c8bb2b5a9d21"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        sa.text(
            f"""
            UPDATE gn_permissions.t_permissions p
            SET created_on = CASE
                    WHEN ar.initialization_date IS NOT NULL
                    THEN ar.initialization_date::timestamp
                    ELSE p.created_on
                END,
                expire_on = COALESCE(ar.expiration_date::timestamp, p.expire_on),
                validated = COALESCE(ar.validated, p.validated)
            FROM {SCHEMA_NAME}.{TABLE_NAME} ar
            WHERE p.id_permission = ar.id_permission
            """
        )
    )

    op.drop_column(TABLE_NAME, "validated", schema=SCHEMA_NAME)
    op.drop_column(TABLE_NAME, "initialization_date", schema=SCHEMA_NAME)
    op.drop_column(TABLE_NAME, "expiration_date", schema=SCHEMA_NAME)


def downgrade():
    op.add_column(
        TABLE_NAME,
        sa.Column("expiration_date", sa.Date(), nullable=True),
        schema=SCHEMA_NAME,
    )
    op.add_column(
        TABLE_NAME,
        sa.Column("initialization_date", sa.Date(), nullable=True),
        schema=SCHEMA_NAME,
    )
    op.add_column(
        TABLE_NAME,
        sa.Column("validated", sa.Boolean(), nullable=True),
        schema=SCHEMA_NAME,
    )

    op.execute(
        sa.text(
            f"""
            UPDATE {SCHEMA_NAME}.{TABLE_NAME} ar
            SET initialization_date = p.created_on::date,
                expiration_date = p.expire_on::date,
                validated = p.validated
            FROM gn_permissions.t_permissions p
            WHERE p.id_permission = ar.id_permission
            """
        )
    )

    op.execute(
        sa.text(
            f"""
            UPDATE {SCHEMA_NAME}.{TABLE_NAME}
            SET expiration_date = CURRENT_DATE
            WHERE expiration_date IS NULL
            """
        )
    )

    op.execute(
        sa.text(
            f"""
            ALTER TABLE {SCHEMA_NAME}.{TABLE_NAME}
            ALTER COLUMN expiration_date SET NOT NULL
            """
        )
    )
