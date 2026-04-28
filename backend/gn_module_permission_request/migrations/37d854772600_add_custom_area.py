"""Add t_custom_area table for user-uploaded GeoJSON areas

Revision ID: 37d854772600
Revises: ab3c0e7a2f1d
Create Date: 2026-04-23 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = "37d854772600"
down_revision = "ab3c0e7a2f1d"
depends_on = None

MODULE_CODE = "PERMISSION_REQUEST"
SCHEMA_NAME = f"pr_{MODULE_CODE.lower()}"
PERMISSION_REQUEST_TABLE = f"t_{MODULE_CODE.lower()}"
CUSTOM_AREA_TABLE = "t_custom_area"


def upgrade():
    op.execute(
        sa.text(
            f"""
            CREATE TABLE {SCHEMA_NAME}.{CUSTOM_AREA_TABLE} (
                id_custom_area      SERIAL PRIMARY KEY,
                id_permission_request INTEGER
                    REFERENCES {SCHEMA_NAME}.{PERMISSION_REQUEST_TABLE}(id_permission_request)
                    ON DELETE CASCADE
                    UNIQUE,
                geojson_data        JSONB NOT NULL
            )
            """
        )
    )


def downgrade():
    op.execute(
        sa.text(f"DROP TABLE IF EXISTS {SCHEMA_NAME}.{CUSTOM_AREA_TABLE}")
    )
