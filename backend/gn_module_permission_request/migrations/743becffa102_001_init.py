"""init model

Revision ID: 743becffa102
Revises: 743becffa102
Create Date: 2023-03-27 11:54:34.602380

"""

from alembic import op
import sqlalchemy as sa

MODULE_CODE = "PERMISSION_REQUEST"
SCHEMA_NAME = f"pr_{MODULE_CODE.lower()}"
TABLE_NAME = f"t_{MODULE_CODE.lower()}"
PRIMARY_KEY = "id_permission_request"
COR_PERMISSION_REQUEST_TAXA_TABLE = f"cor_{MODULE_CODE.lower()}_taxa"
COR_PERMISSION_REQUEST_PERMISSIONS_TABLE = f"cor_{MODULE_CODE.lower()}_permissions"

NOTIFICATION_SCHEMA = "gn_notifications"
NOTIFICATION_CATEGORY_DEFINITIONS = [
      {
        "code": "PERMISSION_REQUEST_DELETE",
        "label": "Suppression d'une demande",
        "description": "Suppression d'une demande de permission",
        "action_code": "C",
        "email_content": (
            "<p>Bonjour,</p>"
            "<p>{{ user.nom_complet }} a supprimé la demande de permission "
            "n°{{ permission_request.id_permission_request }}.</p>"
            "{% if permission_request.description %}"
            "<p><strong>Description :</strong> {{ permission_request.description }}</p>"
            "{% endif %}"
            "<p>Vous recevez cet email automatiquement via le service de notification de GeoNature.</p>"
        ),
        "db_content": (
            "{{ user.nom_complet }} a supprimé la demande de permission n°{{ permission_request.id_permission_request }}"
            "{% if permission_request.description %} — {{ permission_request.description }}{% endif %}"
        ),
    },
    {
        "code": "PERMISSION_REQUEST_NEW",
        "label": "Création d'une demande",
        "description": "Création d'une nouvelle demande de permission",
        "action_code": "C",
        "email_content": (
            "<p>Bonjour,</p>"
            "<p>{{ user.nom_complet }} a créé une nouvelle demande de permission "
            "n°{{ permission_request.id_permission_request }}.</p>"
            "{% if permission_request.description %}"
            "<p><strong>Description :</strong> {{ permission_request.description }}</p>"
            "{% endif %}"
            "<p>Vous recevez cet email automatiquement via le service de notification de GeoNature.</p>"
        ),
        "db_content": (
            "{{ user.nom_complet }} a créé la demande de permission n°{{ permission_request.id_permission_request }}"
            "{% if permission_request.description %} — {{ permission_request.description }}{% endif %}"
        ),
    },
    {
        "code": "PERMISSION_REQUEST_MODIFICATION",
        "label": "Modification d'une demande validée",
        "description": "Modification d'une demande de permission déjà validée.",
        "action_code": "U",
        "email_content": (
            "<p>Bonjour,</p>"
            "<p>{{ user.nom_complet }} a modifié la demande de permission "
            "n°{{ permission_request.id_permission_request }}.</p>"
            "{% if permission_request.description %}"
            "<p><strong>Description :</strong> {{ permission_request.description }}</p>"
            "{% endif %}"
            "<p>Vous recevez cet email automatiquement via le service de notification de GeoNature.</p>"
        ),
        "db_content": (
            "{{ user.nom_complet }} a modifié la demande de permission "
            "n°{{ permission_request.id_permission_request }}"
            "{% if permission_request.description %} — {{ permission_request.description }}{% endif %}"
        ),
    },
    {
        "code": "PERMISSION_REQUEST_VALIDATION_UPDATE",
        "label": "Changement de statut d'une demande",
        "description": "Notification envoyée lors d'un changement de statut d'une demande.",
        "action_code": "V",
        "email_content": (
            "<p>Bonjour,</p>"
            "<p>{{ user.nom_complet }} a modifié le statut de la demande de permission "
            "n°{{ permission_request.id_permission_request }} a été mis à jour.</p>"
            "{% if permission_request.validation_description is defined %}"
            "{{ permission_request.validation_description }}"
            "{% endif %}"
            "<p>Vous recevez cet email automatiquement via le service de notification de GeoNature.</p>"
        ),
        "db_content": (
            "{{ user.nom_complet }} a mis à jour pour la demande de permission n°{{ permission_request.id_permission_request }}"
            "{% if permission_request.validation_description is defined %}"
            "{{ permission_request.validation_description }}"
            "{% endif %}"
        ),
    },
]


# revision identifiers, used by Alembic.
revision = "743becffa102"
down_revision = None
branch_labels = ("permission_request",)
depends_on = None


def upgrade():
    # #########################################################################
    # Schema pr_permission_request
    # #########################################################################
    conn = op.get_bind()
    op.execute(sa.text(f"CREATE SCHEMA IF NOT EXISTS {SCHEMA_NAME}"))

    op.create_table(
        TABLE_NAME,
        sa.Column(
            PRIMARY_KEY,
            sa.Integer(),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column(
            "id_author",
            sa.Integer(),
            sa.ForeignKey(
                "utilisateurs.t_roles.id_role",
                name=f"fk_{TABLE_NAME}_id_author",
            ),
            nullable=False,
        ),
        sa.Column(
            "id_validator",
            sa.Integer(),
            sa.ForeignKey(
                "utilisateurs.t_roles.id_role",
                name=f"fk_{TABLE_NAME}_id_validator",
            ),
            nullable=True,
        ),
        sa.Column("validation_description", sa.Text(), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "id_permission",
            sa.Integer(),
            sa.ForeignKey(
                "gn_permissions.t_permissions.id_permission",
                name=f"fk_{TABLE_NAME}_id_permission",
                ondelete="SET NULL",
            ),
            nullable=True,
            unique=True,
        ),
        schema=SCHEMA_NAME,
    )

    ## ########################################################################
    ## Module permissions
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
                  ('{MODULE_CODE}', 'ALL', 'C', False, 'Créer des requêtes de permission')
                  ,('{MODULE_CODE}', 'ALL', 'R', True, 'Voir les requêtes de permission')
                  ,('{MODULE_CODE}', 'ALL', 'U', True, 'Modifier les requêtes de permission')
                  ,('{MODULE_CODE}', 'ALL', 'V', True, 'Valider les requêtes de permission')
                  ,('{MODULE_CODE}', 'ALL', 'D', True, 'Supprimer des requêtes de permission')
          ) AS v (module_code, object_code, action_code, scope_filter, label)
      JOIN
          gn_commons.t_modules m ON m.module_code = v.module_code
      JOIN
          gn_permissions.t_objects o ON o.code_object = v.object_code
      JOIN
          gn_permissions.bib_actions a ON a.code_action = v.action_code
      """
    )

    ## ########################################################################
    ## Module permissions
    ## ########################################################################

    module_id = conn.execute(
        sa.text(
            """
            SELECT id_module
            FROM gn_commons.t_modules
            WHERE module_code = :module_code
            """
        ),
        {"module_code": MODULE_CODE},
    ).scalar()
    if module_id is None:
        raise RuntimeError("PERMISSION_REQUEST module must be registered before running this migration.")

    object_id = conn.execute(
        sa.text(
            """
            SELECT id_object
            FROM gn_permissions.t_objects
            WHERE code_object = :object_code
            """
        ),
        {"object_code": "ALL"},
    ).scalar()
    if object_id is None:
        raise RuntimeError("Permission object 'ALL' is required to configure notifications.")

    def get_action_id(action_code):
        action_id = conn.execute(
            sa.text(
                """
                SELECT id_action
                FROM gn_permissions.bib_actions
                WHERE code_action = :action_code
                """
            ),
            {"action_code": action_code},
        ).scalar()
        if action_id is None:
            raise RuntimeError(f"Permission action '{action_code}' is required to configure notifications.")
        return action_id

    category_values = []
    template_values = []
    rule_values = []
    for definition in NOTIFICATION_CATEGORY_DEFINITIONS:
        category_values.append(
            {
                "code": definition["code"],
                "label": definition["label"],
                "description": definition["description"],
                "id_module": module_id,
                "id_object": object_id,
                "id_action": get_action_id(definition["action_code"]),
            }
        )
        template_values.extend(
            [
                {
                    "code_category": definition["code"],
                    "code_method": "EMAIL",
                    "content": definition["email_content"],
                },
                {
                    "code_category": definition["code"],
                    "code_method": "DB",
                    "content": definition["db_content"],
                },
            ]
        )
        rule_values.extend(
            [
                {
                    "id_role": None,
                    "code_category": definition["code"],
                    "code_method": "EMAIL",
                },
                {
                    "id_role": None,
                    "code_category": definition["code"],
                    "code_method": "DB",
                },
            ]
        )

    if category_values:
        conn.execute(
            sa.text(
                f"""
                INSERT INTO {NOTIFICATION_SCHEMA}.bib_notifications_categories
                    (code, label, description, id_module, id_object, id_action)
                VALUES
                    (:code, :label, :description, :id_module, :id_object, :id_action)
                """
            ),
            category_values,
        )

    if template_values:
        conn.execute(
            sa.text(
                f"""
                INSERT INTO {NOTIFICATION_SCHEMA}.bib_notifications_templates
                    (code_category, code_method, content)
                VALUES
                    (:code_category, :code_method, :content)
                """
            ),
            template_values,
        )

    if rule_values:
        conn.execute(
            sa.text(
                f"""
                INSERT INTO {NOTIFICATION_SCHEMA}.t_notifications_rules
                    (id_role, code_method, code_category)
                VALUES
                    (:id_role, :code_method, :code_category)
                """
            ),
            rule_values,
        )


def downgrade():
    # #########################################################################
    # Notifications clean-up
    # #########################################################################
    conn = op.get_bind()
    for definition in NOTIFICATION_CATEGORY_DEFINITIONS:
        conn.execute(
            sa.text(
                f"""
                DELETE FROM {NOTIFICATION_SCHEMA}.t_notifications_rules
                WHERE code_category = :code
                """
            ),
            {"code": definition["code"]},
        )
        conn.execute(
            sa.text(
                f"""
                DELETE FROM {NOTIFICATION_SCHEMA}.bib_notifications_templates
                WHERE code_category = :code
                """
            ),
            {"code": definition["code"]},
        )
        conn.execute(
            sa.text(
                f"""
                DELETE FROM {NOTIFICATION_SCHEMA}.bib_notifications_categories
                WHERE code = :code
                """
            ),
            {"code": definition["code"]},
        )

    # #########################################################################
    # Remove existing permission initiated by the module
    # #########################################################################
    module_id = conn.execute(
        sa.text(
            """
            SELECT id_module
            FROM gn_commons.t_modules
            WHERE module_code = :module_code
            """
        ),
        {"module_code": MODULE_CODE},
    ).scalar()

    permission_ids_query = f"""
        SELECT id_permission
        FROM {SCHEMA_NAME}.{TABLE_NAME}
        WHERE id_permission IS NOT NULL
    """

    conn.execute(
        sa.text(
            f"""
            DELETE FROM gn_permissions.cor_permission_area
            WHERE id_permission IN ({permission_ids_query})
            """
        )
    )
    conn.execute(
        sa.text(
            f"""
            DELETE FROM gn_permissions.cor_permission_taxref
            WHERE id_permission IN ({permission_ids_query})
            """
        )
    )
    conn.execute(
        sa.text(
            f"""
            DELETE FROM gn_permissions.t_permissions
            WHERE id_permission IN ({permission_ids_query})
            """
        )
    )

    if module_id is not None:
        module_permission_ids = """
            SELECT id_permission
            FROM gn_permissions.t_permissions
            WHERE id_module = :module_id
        """
        for table_name in ("cor_permission_area", "cor_permission_taxref"):
            conn.execute(
                sa.text(
                    f"""
                    DELETE FROM gn_permissions.{table_name}
                    WHERE id_permission IN ({module_permission_ids})
                    """
                ),
                {"module_id": module_id},
            )

        conn.execute(
            sa.text(
                """
                DELETE FROM gn_permissions.t_permissions
                WHERE id_module = :module_id
                """
            ),
            {"module_id": module_id},
        )
        conn.execute(
            sa.text(
                """
                DELETE FROM gn_permissions.t_permissions_available
                WHERE id_module = :module_id
                """
            ),
            {"module_id": module_id},
        )

    # #########################################################################
    # Schema pr_permission_request
    # #########################################################################
    op.drop_table(TABLE_NAME, schema=SCHEMA_NAME)
    op.execute(sa.text(f"DROP SCHEMA IF EXISTS {SCHEMA_NAME} CASCADE"))
