from types import SimpleNamespace

from gn_module_permrequests.schemas import PermissionRequestTaxonSchema


def test_taxon_display_name_without_author():
    taxon = SimpleNamespace(
        nom_complet_html="<i>Abies alba</i>",
        lb_nom="Abies alba",
        lb_auteur=None,
        cd_nom=1,
        cd_ref=2,
    )

    assert PermissionRequestTaxonSchema().get_display_name(taxon) == "<i>Abies alba</i>"
