# Module Request Permission

- [Module Request Permission](#module-request-permission)
  - [Présentation](#présentation)
  - [Installation du module](#installation-du-module)
    - [Mise à jour du module](#mise-à-jour-du-module)
  - [Configuration](#configuration)
    - [Paramètres](#paramètres)
  - [Administration du module](#administration-du-module)

## Présentation

Ce module permet d'ajouter des fonctionnalités de demandes de permission à des données au sein de
l'application GeoNature.
Pour l'instant, ces données concernent les observations **sensibles** du module Synthese et leur
accès en consultation et export de manière précise.

Ce module s'articule autour du concept de demande de permission.

Un utilisateur avec des permissions de consultation pourra via ce module effectuer une demande de
permission à des données. Sa demande sera caractérisée par 3 types d'informations:

- un ou plusieurs groupe taxonomique auxquels il souhaite avoir la permission d'accéder
- un périmètre géographique recouvrant les données auxquelles il souhaite avoir la permission d'accéder
- une plage temporelle représentant la période de permission aux données

Si la demande est acceptée par un validateur, l'utilisateur pourra accéder à toutes les données
taxonomiques données dans le périmètre géographique fourni, durant la plage temporelle demandée.

Un validateur et pourra accéder aux différentes demandes en cours, et traiter les différentes
demandes de validation.

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

Il vous faut désormais attribuer des permissions aux groupes ou utilisateurs que vous souhaitez,
pour qu'ils puissent accéder et utiliser le module (voir <https://docs.geonature.fr/admin-manual.html#gestion-des-droits>).
Si besoin une commande permet d'attribuer automatiquement toutes les permissions dans tous
les modules à un groupe ou utilisateur administrateur.

### Mise à jour du module

Pour mettre à jour le modue Monitoring, suivre la documentation de [mise à jour d'un module GeoNature](https://docs.geonature.fr/installation.html#mise-a-jour-du-module)

## Configuration

> [!NOTE]
>
> Documentation de référence sur la configuration d'un module: <https://docs.geonature.fr/installation.html#module-config>
>

Dans le cas de ce module, vous pouvez modifier la configuration du module en créant un fichier
`permrequests_config.toml` dans le dossier `config/` de GeoNature, en vous inspirant
du fichier [`permrequests_config.sample.toml`](config/permrequests_config.sample.toml) présent dans ce module et en surcouchant
les paramètres que vous souhaitez.

Vous pouvez laisser seulement les paramètres que vous avez modifié dans ce fichier et supprimer
les autres.

Il est également envisageable de laisser votre fichier `permresquests_config.toml` dans le
dossier `config/` de ce module puis de créer un lien symbolique vers celui-ci depuis le dossier `config/` de
GeoNature.

### Paramètres

- `ALLOW_CUSTOM_AREA`: autorise (`true`) ou pas (`false`) le téléversement de fichier GeoJSON pour définir une zone géographique personnalisé sur laquelle demande de permission s'appliquera.
- `ALLOWED_AREA_TYPE_CODES` : liste des types de zones autorisés (par défaut `["COM", "DEP", "REG"]`).
- `DYNAMIC_FORM` : listes des champs de la section personnalisable du formulaire de demande d'accès. Par défaut, aucune section personnalisable n'est définie. Pour connaitre les attributs disponible pour chaque type de widget du formulaire dynamique vous pouvez [consulter le code source](https://github.com/PnX-SI/GeoNature/blob/master/frontend/src/app/GN2CommonModule/form/dynamic-form/dynamic-form.component.html) ou [chercher des exemples](./config/permrequests_config.sample.toml). Ce module ajoute 2 attributs spécifiques, `icon` et `icon_set`, permettant respectivement d'indiquer le nom d'une icône et son type de police.
Pour [les icônes FontAwsome](https://fontawesome.com/v4/icons/), utiliser `fa` dans l'attribut `icon_set`. Pour [les icônes Material](https://fonts.google.com/icons?hl=fr), il n'est pas nécessaire d'utiliser le paramètre `icon_set`.

- `PERMISSIONS_DURATION` : section permettant de configurer la durée des permissions accordées lors d'une demande.
  - `DEFAULT_DAYS` : durée par défaut en jours des permissions accordées lors d'une demande. La date d'expiration des permissions dans le formulaire d'une demande sera automatiquement calculée en prenant en compte le nombre de jours défini ici. Par défaut : *30 jours*.
  - `MAX_DAYS` : durée maximale par défaut en jours des permissions accordées lors d'une demande. La date d'expiration maximale sélectionnable dans le formulaire d'une demande sera automatiquement calculée en prenant en compte le nombre de jours défini ici. Par défaut : *365 jours*.
- `PERMISSIONS_TO_CREATE` : contient une liste d'objets permettant de définir les permissions créés par une demande de permission. Le format de chaque objet est le suivant `{"module": "<code-du-module>", "action": "<code-de-l'action>"}`.
- `SCOPE_FILTER` : section permettant de configurer l'affichage du filtre liés à la sensibilité au sein de la demande.
  - `SCOPE_FILTER.DISPLAY_ENABLED` : affiche (`true`) ou pas (`false`) la possibilité de sélectionner la portée d'une demande.
  - `SCOPE_FILTER.ALLOWED_VALUES` : liste des valeurs autorisées pour le filtre de portée vérifiées côté serveur. Par défaut : utilisateur (`USER`) et organisme (`ORGANISM`). Ne devrait pas être modifié.
  - `SCOPE_FILTER.DEFAULT_VALUE` : permet de définir la valeur par défaut (`USER`) pour le filtre de portée de la demande.
- `SENSITIVITY_FILTER` : section permettant de configurer l'affichage du filtre liés à la sensibilité au sein de la demande.
  - `SENSITIVITY_FILTER.DISPLAY_ENABLED` : affiche (`true`) ou pas (`false`) la coche permettant de définir le filtre de sensibilité de la demande.
  - `SENSITIVITY_FILTER.DEFAULT_VALUE` : permet de définir la valeur par défaut (`true`) du filtre de sensibilité de la demande.
- `TERMS_ACKNOWLEDGEMENT` : section permetant de configurer la coche d'acceptation des termes et conditions des demandes d'accès. Le texte et le lien sont configurable via [la surcharge des fichiers de traductions](https://docs.geonature.fr/admin-manual.html#customiser-les-traductions).
  - `TERMS_ACKNOWLEDGEMENT.REQUIRED` : permet de faire apparaitre / dissimuler dans le formulaire une coche d'acceptation des termes et conditions. Par défaut, c'est affiché.
  - `TERMS_ACKNOWLEDGEMENT.URL` : URL vers les conditions d'utilisations (ouvre un nouvel onglet). Si non définit ou vide seul le texte sera affiché. Par défaut, aucun lien n'est défini.
  - `TERMS_ACKNOWLEDGEMENT.CLASS_CSS` : permet de définir des classes CSS sur le lien des conditions d'utilisation. Ex.: `btn btn-primary`.


> Le statut visible dans l’interface est calculé automatiquement :
>
> - si la date d’expiration est strictement antérieure à la date du jour, la demande est affichée « active » ;
> - sinon, elle apparaît comme « expirée ».

## Administration du module

### Zones géographiques personnalisées

Ce module ajouter un nouveau type de zone géographique au référentiel géographique dont le code est `PERMREQUESTS`. Ce type permet de rassembler toutes les zones géographiques téléversées par les utilisateurs lorsque le paramètre `ALLOW_CUSTOM_AREA` est à `true`.

## Développement du module

Ce module utilise un fichier `pyproject.toml` pour centraliser toutes les informations d'installation
et de développement. Privilégier toujours ce fichier à l'utilisation de fichiers supplémentaires.
