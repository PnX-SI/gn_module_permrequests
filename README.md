# Module Request Permission

- [Module Request Permission](#module-request-permission)
  - [Présentation](#présentation)
  - [Installation du module](#installation-du-module)
    - [Mise à jour du module](#mise-à-jour-du-module)
  - [Configuration](#configuration)
    - [Paramètres](#paramètres)
  - [Administration du module](#administration-du-module)

Ce module permet de générer de façon générique des interfaces de saisie correspondant à des protocoles de suivi.
Par "suivi", on entend un protocole dont le point d'entrée est un site géographique, sur lequel on va revenir régulièrement effectuer des visites. Il se distingue par sa structure du module "Occtax" dont l'objectif est de faire de la saisie de données opportunistes ou d'inventaire (sans revenir régulièrement sur le même site de suivi).

Le module est articulé autour du concept

- les sites : l'objet géographique de suivi (qui peuvent être regroupés par groupes de sites)
- les visites : une visite est effectuée sur un site (date, observateurs)
- les observations : observations faites durant la visite (espèces)

Les 3 niveaux que sont les sites, les visites et les observations sont fournis avec un tronc commun (les champs génériques) qui peuvent être complétés par des champs spécifiques à chaque protocole. Ces champs spécifiques sont définis par des fichiers de configuration JSON.
Pour chaque sous-module, correspondant à un protocole spécifique de suivi, il est ainsi possible d'ajouter dynamiquement des champs de différents types (liste, nomenclature, booléen, date, radio, observateurs, texte, taxonomie...). Ceux-ci peuvent être obligatoires ou non, affichés ou non et avoir des valeurs par défaut (voir doc détaillée : [Création d'un sous-module](docs/sous_module.md)).

## Présentation

Ce module permet d'ajouter des fonctionnalités de demandes de permission à des données au sein de l'application GeoNature.

Ce module s'articule autour du concept de demande de permission.

Un utilisateur pourra via ce module effectuer une demande de permission à des données. Sa demande sera caractérisée par 3 types d'informations:

- un ou plusieurs groupe taxonomique auxquels il souhaite avoir la permission d'accéder
- un périmètre géographique recouvrant les données auxquelles il souhaite avoir la permission d'accéder
- une plage temporelle représentant la période de permission aux données

Si la demande est acceptée, l'utilisateur pourra accéder à toutes les données taxonmiques données dans le périmètre géogrpahique fourni, durant la plage temporelle demandée.

Un validateur pourra accéder aux différentes demandes en cours, et traiter les différentes demandes de validation.

## Installation du module

> [!NOTE]
>
> Documentation de référence sur l'installation de module: <https://docs.geonature.fr/installation.html#installation-d-un-module-geonature>
>

- Téléchargez le module dans ``/home/<myuser>/``, en remplacant ``X.Y.Z`` par la version souhaitée

```bash
cd
wget https://github.com/PnX-SI/gn_module_permission_request/archive/X.Y.Z.zip
unzip X.Y.Z.zip
rm X.Y.Z.zip
```

- Renommez le répertoire du module

```bash
mv ~/gn_module_permission_request-X.Y.Z ~/gn_module_permission_request
```

- Lancez l'installation du module

```bash
source ~/geonature/backend/venv/bin/activate
geonature install-gn-module ~/gn_module_permission_request PERMISSION_REQUEST
sudo systemctl restart geonature
sudo systemctl restart geonature-worker
deactivate
```

Il vous faut désormais attribuer des permissions aux groupes ou utilisateurs que vous souhaitez, pour qu'ils puissent accéder et utiliser le module (voir <https://docs.geonature.fr/admin-manual.html#gestion-des-droits>). Si besoin une commande permet d'attribuer automatiquement toutes les permissions dans tous les modules à un groupe ou utilisateur administrateur.

### Mise à jour du module

Pour mettre à jour le modue Monitoring, suivre la documentation de [mise à jour d'un module GeoNature](https://docs.geonature.fr/installation.html#mise-a-jour-du-module)

## Configuration

> [!NOTE]
>
> Documentation de référence sur la configuration d'un module: <https://docs.geonature.fr/installation.html#module-config>
>

Dans le cas de ce module, vous pouvez modifier la configuration du module en créant un fichier
`permission_request_config.toml` dans le dossier `config` de GeoNature, en vous inspirant
du fichier `permission_request_config.toml.example` et en surcouchant les paramètres que vous souhaitez.

### Paramètres

- ``ALLOWED_SCOPES`` : liste des scopes autorisés pour les demandes (par défaut ``["USER", "ORGANISM"]``).
- ``ALLOWED_AREA_TYPE_CODES`` : liste des types de zones autorisés (par défaut ``["COM", "DEP", "REG"]``).
- ``REQUIRE_TERMS_ACKNOWLEDGEMENT`` : permet de faire apparaitre / dissimuler dans le formulaire une coche d'acceptation des termes et conditions.
- ``TERMS_ACKNOWLEDGEMENT.URL`` : URL vers les conditions d'utilisations (ouvre un nouvel onglet).

> Le statut visible dans l’interface est calculé automatiquement :
>
> - si la date d’expiration est strictement antérieure à la date du jour, la demande est affichée « active » ;
> - sinon, elle apparaît comme « expirée ».

## Administration du module
