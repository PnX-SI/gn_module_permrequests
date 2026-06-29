# AGENTS.md

Ce fichier fournit des instructions aux agents de codage et aux outils d’IA travaillant sur ce module.

## Contexte du module

Ce dépôt contient un module GeoNature dédié aux demandes de permissions d’accès à des données sensibles. Le code est organisé autour de :

- backend/ : package Python principal du module
- frontend/ : interface utilisateur et logique côté navigateur utilisant Angular.
- config/ : exemples et fichiers de configuration du module
- migrations/ : scripts de migrations applicatifs si nécessaire

## Principes de travail

- Ce module s'intègre dans une installation GeoNature existante.
- Il ne peut pas fonctionner de manière autonome et s'appuie donc sur le backend (`venv/`) et le frontend (`node_modules/`) de GeoNature.
- Préférer des changements locaux et cohérents avec l’architecture existante.
- Respecter les conventions déjà utilisées dans le module et dans GeoNature.
- Éviter les modifications inutiles sur la configuration, les migrations ou les fichiers de traduction.
- Vérifier la compatibilité avec les points d’entrée déclarés dans pyproject.toml.

## Stack Technique

- **Backend :** Python 3, Flask, SQLAlchemy, Alembic.
- **Frontend :** Angular v15, Angular Material, Bootstrap 4, TypeScript.

## Conventions de développement

- Le formatage et le linting backend sont gérés par Ruff via des règles définies dans [pyproject.toml](./pyproject.toml).
- Les imports doivent être triés et organisés.
- Utilise toujours des **Type Hints** stricts pour les arguments de fonctions et les valeurs de retour.
- Les changements de configuration doivent rester compatibles avec les fichiers de configuration du module.
- Si une modification impacte les permissions, les formulaires ou la logique métier, vérifier les correspondances côté frontend et backend.

## Tests

- Utilise **pytest** pour les tests unitaires et d'intégration.
- Les tests se trouvent dans `backend/gn_module_permrequests/tests/`.
- Repose-toi sur les fixtures définies dans `backend/gn_module_permrequests/tests/conftest.py`.

## Commandes utiles

- Installation des dépendances de développement : `pip install -e ".[dev]"`
- Vérification du style Python : `ruff check .`
- Formatage Python : `ruff format .`
- Tests : `pytest`

## Consignes importantes

- Ne pas publier ou exposer de secrets, jetons ou données sensibles.
- Ne pas modifier les migrations de façon non justifiée sans vérifier leur impact.
- Si un changement touche au comportement métier, documenter les conséquences potentielles dans la PR ou les commentaires associés.
