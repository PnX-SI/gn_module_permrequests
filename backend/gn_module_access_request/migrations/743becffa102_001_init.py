"""init model

Revision ID: 743becffa102
Revises: 743becffa102
Create Date: 2023-03-27 11:54:34.602380

"""

import importlib

from alembic import op
import sqlalchemy as sa
from sqlalchemy import func
from sqlalchemy.sql import text

MODULE_CODE = "ACCESS_REQUEST"
SCHEMA_NAME = f"pr_{MODULE_CODE.lower()}"
TABLE_NAME = f"t_{MODULE_CODE.lower()}"
PRIMARY_KEY = "id_access_request"
COR_ACCESS_REQUEST_TAXA_TABLE = f"cor_{MODULE_CODE.lower()}_taxa"
COR_ACCESS_REQUEST_PERMISSIONS_TABLE = f"cor_{MODULE_CODE.lower()}_permissions"
NOMENCLATURE_TYPE = f"{MODULE_CODE}_VALIDATION"
ACCESS_REQUEST_VALIDATION_VALUES = [
    {"code": "PENDING", "label": "EN ATTENTE"},
    {"code": "VALIDATED", "label": "VALIDE"},
    {"code": "REFUSED", "label": "REFUSE"},
]


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
            "id_validation_status",
            sa.Integer,
            sa.ForeignKey("ref_nomenclatures.t_nomenclatures.id_nomenclature"),
            nullable=True,
        ),
        sa.Column(
            "id_author",
            sa.Integer,
            sa.ForeignKey("utilisateurs.t_roles.id_role"),
            nullable=False,
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
        schema=SCHEMA_NAME,
    )

    ## ########################################################################
    ## NOMENCLATURES
    ## ########################################################################
    conn = op.get_bind()
    conn.execute(
        sa.text(
            """
            INSERT INTO ref_nomenclatures.bib_nomenclatures_types (
                mnemonique,
                label_default,
                label_fr
            )
            SELECT :mnemonique, :label, :label
            WHERE NOT EXISTS (
                SELECT 1
                FROM ref_nomenclatures.bib_nomenclatures_types
                WHERE mnemonique = :mnemonique
            )
            """
        ),
        {
            "mnemonique": NOMENCLATURE_TYPE,
            "label": "Statuts de validation des demandes d'accès",
        },
    )

    type_id = conn.execute(
        sa.text(
            """
            SELECT id_type
            FROM ref_nomenclatures.bib_nomenclatures_types
            WHERE mnemonique = :mnemonique
            """
        ),
        {"mnemonique": NOMENCLATURE_TYPE},
    ).scalar()

    if type_id is None:
        raise RuntimeError(
            f"Le type de nomenclature {NOMENCLATURE_TYPE} est introuvable."
        )

    for value in ACCESS_REQUEST_VALIDATION_VALUES:
        conn.execute(
            sa.text(
                """
                INSERT INTO ref_nomenclatures.t_nomenclatures (
                    id_type,
                    cd_nomenclature,
                    mnemonique,
                    label_default,
                    label_fr,
                    active
                )
                SELECT
                    :id_type,
                    :code,
                    :mnemonique,
                    :label,
                    :label,
                    true
                WHERE NOT EXISTS (
                    SELECT 1
                    FROM ref_nomenclatures.t_nomenclatures
                    WHERE id_type = :id_type
                      AND cd_nomenclature = :code
                )
                """
            ),
            {
                "id_type": type_id,
                "code": value["code"],
                "mnemonique": value["code"],
                "label": value["label"],
            },
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
                  ,('{MODULE_CODE}', 'ALL', 'U', False, 'Modifier les requêtes d''accès')
                  ,('{MODULE_CODE}', 'ALL', 'D', False, 'Supprimer des requêtes d''accès')
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

    ## ########################################################################
    ## NOMENCLATURES
    ## ########################################################################
    conn = op.get_bind()
    type_id = conn.execute(
        sa.text(
            """
            SELECT id_type
            FROM ref_nomenclatures.bib_nomenclatures_types
            WHERE mnemonique = :mnemonique
            """
        ),
        {"mnemonique": NOMENCLATURE_TYPE},
    ).scalar()

    if type_id is not None:
        for value in ACCESS_REQUEST_VALIDATION_VALUES:
            conn.execute(
                sa.text(
                    """
                    DELETE FROM ref_nomenclatures.t_nomenclatures
                    WHERE id_type = :id_type
                      AND cd_nomenclature = :code
                    """
                ),
                {"id_type": type_id, "code": value["code"]},
            )
        conn.execute(
            sa.text(
                """
                DELETE FROM ref_nomenclatures.bib_nomenclatures_types t
                WHERE t.mnemonique = :mnemonique
                  AND NOT EXISTS (
                      SELECT 1
                      FROM ref_nomenclatures.t_nomenclatures n
                      WHERE n.id_type = t.id_type
                  )
                """
            ),
            {"mnemonique": NOMENCLATURE_TYPE},
        )

    ## ########################################################################
    ## SCHEMA ET TABLES
    ## ########################################################################
    op.drop_table(COR_ACCESS_REQUEST_PERMISSIONS_TABLE, schema=SCHEMA_NAME, if_exists=True)
    op.drop_table(COR_ACCESS_REQUEST_TAXA_TABLE, schema=SCHEMA_NAME, if_exists=True)
    op.drop_table(TABLE_NAME, schema=SCHEMA_NAME, if_exists=True)
    op.execute(sa.text(f"DROP SCHEMA IF EXISTS {SCHEMA_NAME} CASCADE"))
