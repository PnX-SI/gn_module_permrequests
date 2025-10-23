import setuptools
from pathlib import Path


root_dir = Path(__file__).absolute().parent
with (root_dir / "VERSION").open() as f:
    version = f.read()
with (root_dir / "README.md").open() as f:
    long_description = f.read()
with (root_dir / "requirements.in").open() as f:
    requirements = f.read().splitlines()


setuptools.setup(
    name="gn_module_access_request",
    version=version,
    description="Module Demande Accès",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    maintainer="Natural Solutions",
    maintainer_email="geonature@natural-solutions.eu",
    url="https://github.com/PnX-SI/gn_module_access_request/",
    packages=setuptools.find_packages("backend"),
    package_dir={"": "backend"},
    package_data={
        "gn_module_access_request": ["templates/**", "static/**"],
        "gn_module_access_request.migrations": ["data/*.sql"],
    },
    install_requires=requirements,
    entry_points={
        "gn_module": [
            "code = gn_module_access_request:MODULE_CODE",
            "label = gn_module_access_request:MODULE_LABEL",
            "picto = gn_module_access_request:MODULE_PICTO",
            "blueprint = gn_module_access_request.blueprint:blueprint",
            "config_schema = gn_module_access_request.conf_schema_toml:GnModuleSchemaConf",
            "migrations = gn_module_access_request:migrations",
        ],
    },
)
