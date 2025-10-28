"""init model

Revision ID: 743becffa102
Revises: 743becffa102
Create Date: 2023-03-27 11:54:34.602380

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
revision = "743becffa102"
down_revision = None
branch_labels = ("access_request",)
depends_on = None


def upgrade():
    ## ########################################################################
    ## SCHEMA ET TABLES
    ## ########################################################################
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA_NAME}"))
    op.create_table(
        TABLE_NAME,
        sa.Column(PRIMARY_KEY, sa.Integer, primary_key=True, autoincrement=True),
        sa.Column(
            "id_author",
            sa.Integer,
            sa.ForeignKey("utilisateurs.t_roles.id_role"),
            nullable=False,
        ),
        sa.Column(
            "initialization_date",
            sa.Date,
            nullable=True,
        ),
        sa.Column(
            "id_validator",
            sa.Integer,
            sa.ForeignKey("utilisateurs.t_roles.id_role"),
            nullable=True,
        ),
        sa.Column(
            "expiration_date",
            sa.Date,
            nullable=False,
        ),
        sa.Column("validated", sa.Boolean, nullable=True),
        sa.Column("description", sa.Text, nullable=True),
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

    ## ########################################################################
    ## TRIGGER DE SUPPRESSION DES PERMISSIONS
    ## ########################################################################
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

    ## ########################################################################
    ## PERMISSIONS
    ## ########################################################################
    op.execute(
        f"""
      INSERT INTO
          gn_permissions.t_permissions_available (
              id_module,
              id_object,
              id_action,
              label,
              scope_filter
          )
      SELECT
          m.id_module,
          o.id_object,
          a.id_action,
          v.label,
          v.scope_filter
      FROM
          (
              VALUES
                  ('{MODULE_CODE}', 'ALL', 'C', False, 'Créer des requêtes d''accès')
                  ,('{MODULE_CODE}', 'ALL', 'R', True, 'Voir les requêtes d''accès')
                  ,('{MODULE_CODE}', 'ALL', 'U', True, 'Modifier les requêtes d''accès')
                  ,('{MODULE_CODE}', 'ALL', 'V', True, 'Valider les requêtes d''accès')
                  ,('{MODULE_CODE}', 'ALL', 'D', True, 'Supprimer des requêtes d''accès')
          ) AS v (module_code, object_code, action_code, scope_filter, label)
      JOIN
          gn_commons.t_modules m ON m.module_code = v.module_code
      JOIN
          gn_permissions.t_objects o ON o.code_object = v.object_code
      JOIN
          gn_permissions.bib_actions a ON a.code_action = v.action_code
      """
    )


def downgrade():
    ## ########################################################################
    ## PERMISSIONS
    ## ########################################################################
    op.execute(
        f"""
      DELETE FROM
          gn_permissions.t_permissions_available pa
      USING
          gn_commons.t_modules m
      WHERE
          pa.id_module = m.id_module
          AND
          module_code = '{MODULE_CODE}'
      """
    )

    op.execute(
        f"""
      DELETE FROM
          gn_permissions.t_permissions p
      USING
          gn_commons.t_modules m
      WHERE
          p.id_module = m.id_module
          AND
          module_code = '{MODULE_CODE}'
      """
    )

    ## ########################################################################
    ## SCHEMA ET TABLES
    ## ########################################################################
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
    op.drop_table(COR_ACCESS_REQUEST_PERMISSIONS_TABLE, schema=SCHEMA_NAME, if_exists=True)
    op.drop_table(COR_ACCESS_REQUEST_TAXA_TABLE, schema=SCHEMA_NAME, if_exists=True)
    op.drop_table(TABLE_NAME, schema=SCHEMA_NAME, if_exists=True)
    op.execute(sa.text(f"DROP SCHEMA IF EXISTS {SCHEMA_NAME} CASCADE"))
