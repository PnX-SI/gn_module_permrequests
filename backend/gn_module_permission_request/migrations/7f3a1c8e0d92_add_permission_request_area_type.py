"""Add PERMISSION_REQUEST area type to ref_geo.bib_areas_types

Revision ID: 7f3a1c8e0d92
Revises: 5e2f8c1a9b04
Create Date: 2026-04-27 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

revision = "7f3a1c8e0d92"
down_revision = "5e2f8c1a9b04"
depends_on = None

AREA_TYPE_CODE = "PERMISSION_REQUEST"
AREA_TYPE_NAME = "Zone de demande de permission"
AREA_TYPE_DESC = "Zone géographique personnalisée associée à une demande de permission"


def upgrade():
    op.execute(
        sa.text(
            """
            INSERT INTO ref_geo.bib_areas_types (type_name, type_code, type_desc)
            VALUES (:type_name, :type_code, :type_desc)
            ON CONFLICT (type_code) DO NOTHING
            """
        ).bindparams(
            type_name=AREA_TYPE_NAME,
            type_code=AREA_TYPE_CODE,
            type_desc=AREA_TYPE_DESC,
        )
    )


def downgrade():
    op.execute(
        sa.text(
            """
            DELETE FROM ref_geo.bib_areas_types WHERE type_code = :type_code
            """
        ).bindparams(type_code=AREA_TYPE_CODE)
    )
