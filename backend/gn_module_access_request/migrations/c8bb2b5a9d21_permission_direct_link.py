"""link permission directly on access_request

Revision ID: c8bb2b5a9d21
Revises: 7b9091d8a643
Create Date: 2024-05-12 00:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

MODULE_CODE = "ACCESS_REQUEST"
SCHEMA_NAME = f"pr_{MODULE_CODE.lower()}"
TABLE_NAME = f"t_{MODULE_CODE.lower()}"
PRIMARY_KEY = "id_access_request"
COR_ACCESS_REQUEST_TAXA_TABLE = f"cor_{MODULE_CODE.lower()}_taxa"
COR_ACCESS_REQUEST_PERMISSIONS_TABLE = f"cor_{MODULE_CODE.lower()}_permissions"


# revision identifiers, used by Alembic.
revision = "c8bb2b5a9d21"
down_revision = "743becffa102"
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        sa.text(
            f"""
            DROP TRIGGER IF EXISTS trg_delete_permissions_after_access_request_delete
            ON {SCHEMA_NAME}.{TABLE_NAME}
            """
        )
    )
    op.execute(
        sa.text(
            f"""
            DROP FUNCTION IF EXISTS {SCHEMA_NAME}.delete_permissions_after_access_request_delete()
            """
        )
    )

    op.add_column(
        TABLE_NAME,
        sa.Column("id_permission", sa.Integer(), nullable=True),
        schema=SCHEMA_NAME,
    )
    op.create_foreign_key(
        "fk_access_request_permission",
        TABLE_NAME,
        "t_permissions",
        ["id_permission"],
        ["id_permission"],
        source_schema=SCHEMA_NAME,
        referent_schema="gn_permissions",
        ondelete="SET NULL",
    )
    op.create_unique_constraint(
        "uq_access_request_id_permission",
        TABLE_NAME,
        ["id_permission"],
        schema=SCHEMA_NAME,
    )

    op.execute(
        sa.text(
            f"""
            UPDATE {SCHEMA_NAME}.{TABLE_NAME} ar
            SET id_permission = cap.id_permission
            FROM {SCHEMA_NAME}.{COR_ACCESS_REQUEST_PERMISSIONS_TABLE} cap
            WHERE cap.id_access_request = ar.{PRIMARY_KEY}
            """
        )
    )

    op.execute(
        sa.text(
            f"""
            INSERT INTO gn_permissions.cor_permission_taxref (id_permission, cd_nom)
            SELECT cap.id_permission, cat.cd_nom
            FROM {SCHEMA_NAME}.{COR_ACCESS_REQUEST_PERMISSIONS_TABLE} cap
            JOIN {SCHEMA_NAME}.{COR_ACCESS_REQUEST_TAXA_TABLE} cat
              ON cat.id_access_request = cap.id_access_request
            ON CONFLICT DO NOTHING
            """
        )
    )

    op.drop_table(COR_ACCESS_REQUEST_TAXA_TABLE, schema=SCHEMA_NAME)
    op.drop_table(COR_ACCESS_REQUEST_PERMISSIONS_TABLE, schema=SCHEMA_NAME)

    op.execute(
        sa.text(
            f"""
            CREATE OR REPLACE FUNCTION {SCHEMA_NAME}.delete_permission_after_access_request_delete()
            RETURNS TRIGGER AS $$
            BEGIN
                IF OLD.id_permission IS NOT NULL THEN
                    DELETE FROM gn_permissions.t_permissions
                    WHERE id_permission = OLD.id_permission;
                END IF;
                RETURN OLD;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
    )
    op.execute(
        sa.text(
            f"""
            CREATE TRIGGER trg_delete_permission_after_access_request_delete
            AFTER DELETE ON {SCHEMA_NAME}.{TABLE_NAME}
            FOR EACH ROW
            EXECUTE FUNCTION {SCHEMA_NAME}.delete_permission_after_access_request_delete();
            """
        )
    )


def downgrade():
    op.execute(
        sa.text(
            f"""
            DROP TRIGGER IF EXISTS trg_delete_permission_after_access_request_delete
            ON {SCHEMA_NAME}.{TABLE_NAME}
            """
        )
    )
    op.execute(
        sa.text(
            f"""
            DROP FUNCTION IF EXISTS {SCHEMA_NAME}.delete_permission_after_access_request_delete()
            """
        )
    )

    op.create_table(
        COR_ACCESS_REQUEST_PERMISSIONS_TABLE,
        sa.Column(
            "id_access_request",
            sa.Integer,
            sa.ForeignKey(
                f"{SCHEMA_NAME}.{TABLE_NAME}.{PRIMARY_KEY}",
                ondelete="CASCADE",
            ),
            primary_key=True,
        ),
        sa.Column(
            "id_permission",
            sa.Integer,
            sa.ForeignKey("gn_permissions.t_permissions.id_permission", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.UniqueConstraint("id_permission"),
        schema=SCHEMA_NAME,
    )
    op.create_table(
        COR_ACCESS_REQUEST_TAXA_TABLE,
        sa.Column(
            "id_access_request",
            sa.Integer,
            sa.ForeignKey(
                f"{SCHEMA_NAME}.{TABLE_NAME}.{PRIMARY_KEY}",
                ondelete="CASCADE",
            ),
            primary_key=True,
        ),
        sa.Column(
            "cd_nom",
            sa.Integer,
            sa.ForeignKey("taxonomie.taxref.cd_nom"),
            primary_key=True,
        ),
        schema=SCHEMA_NAME,
    )

    op.execute(
        sa.text(
            f"""
            INSERT INTO {SCHEMA_NAME}.{COR_ACCESS_REQUEST_PERMISSIONS_TABLE} (id_access_request, id_permission)
            SELECT {PRIMARY_KEY}, id_permission
            FROM {SCHEMA_NAME}.{TABLE_NAME}
            WHERE id_permission IS NOT NULL
            """
        )
    )

    op.execute(
        sa.text(
            f"""
            INSERT INTO {SCHEMA_NAME}.{COR_ACCESS_REQUEST_TAXA_TABLE} (id_access_request, cd_nom)
            SELECT ar.{PRIMARY_KEY}, cpt.cd_nom
            FROM {SCHEMA_NAME}.{TABLE_NAME} ar
            JOIN gn_permissions.cor_permission_taxref cpt
              ON cpt.id_permission = ar.id_permission
            """
        )
    )

    op.drop_constraint(
        "uq_access_request_id_permission",
        TABLE_NAME,
        schema=SCHEMA_NAME,
        type_="unique",
    )
    op.drop_constraint(
        "fk_access_request_permission",
        TABLE_NAME,
        schema=SCHEMA_NAME,
        type_="foreignkey",
    )
    op.drop_column(TABLE_NAME, "id_permission", schema=SCHEMA_NAME)

    op.execute(
        sa.text(
            f"""
            CREATE OR REPLACE FUNCTION {SCHEMA_NAME}.delete_permissions_after_access_request_delete()
            RETURNS TRIGGER AS $$
            BEGIN
                DELETE FROM gn_permissions.t_permissions p
                USING {SCHEMA_NAME}.{COR_ACCESS_REQUEST_PERMISSIONS_TABLE} cap
                WHERE cap.id_permission = p.id_permission
                  AND cap.id_access_request = OLD.{PRIMARY_KEY};
                RETURN OLD;
            END;
            $$ LANGUAGE plpgsql;
            """
        )
    )
    op.execute(
        sa.text(
            f"""
            CREATE TRIGGER trg_delete_permissions_after_access_request_delete
            BEFORE DELETE ON {SCHEMA_NAME}.{TABLE_NAME}
            FOR EACH ROW
            EXECUTE FUNCTION {SCHEMA_NAME}.delete_permissions_after_access_request_delete();
            """
        )
    )
