#!/usr/bin/env python
# -*- coding: utf-8 -*-
from saml2 import BINDING_HTTP_REDIRECT, BINDING_URI
from saml2 import BINDING_HTTP_ARTIFACT
from saml2 import BINDING_HTTP_POST
from saml2 import BINDING_SOAP
from saml2.saml import NAME_FORMAT_URI
from saml2.saml import NAMEID_FORMAT_TRANSIENT
from saml2.saml import NAMEID_FORMAT_PERSISTENT
import os.path

try:
    from saml2.sigver import get_xmlsec_binary
except ImportError:
    get_xmlsec_binary = None

if get_xmlsec_binary:
    xmlsec_path = get_xmlsec_binary(["/opt/local/bin"])
else:
    xmlsec_path = '/usr/bin/xmlsec1'

BASE = "http://192.168.215.129:5000"
DESCRIPTION = "my identity provider"
VALID_FOR = 3600
ORGANIZATION = {
    "display_name": "wedgie.org",
    "name": "The Wedgie organization",
    "url": "http://my.wedgie.org"
}
CONTACTS = [
    {
        "contact_type": "technical",
        "given_name": "Jason",
        "sur_name": "Garman",
        "email_address": "jason.garman@gmail.com"
    }
]


BASEDIR = os.path.abspath(os.path.dirname(__file__))

def full_path(local_file):
    return os.path.join(BASEDIR, local_file)

CONFIG = {
    "entityid": "%s/idp.xml" % BASE,
    "description": DESCRIPTION,
    "valid_for": VALID_FOR,
    "service": {
        "idp": {
            "name": "total testing IdP",
            "endpoints": {
                "single_sign_on_service": [
                    ("%s/sso" % BASE, BINDING_HTTP_REDIRECT),
                    ("%s/sso" % BASE, BINDING_HTTP_POST),
                ],
                "single_logout_service": [
                    ("%s/logout" % BASE, BINDING_HTTP_REDIRECT)
                ],
            },
            "policy": {
                "default": {
#                    "lifetime": {"minutes": 15},
#                    "attribute_restrictions": None, # means all I have
                    "name_form": NAME_FORMAT_URI,
#                    "entity_categories": ["swamid", "edugain"]
                },
            },
            "subject_data": "./idp.subject",
            "name_id_format": [NAMEID_FORMAT_TRANSIENT,
                               NAMEID_FORMAT_PERSISTENT]
        },
    },
    "debug": 1,
    "key_file": full_path("secrets/pki/mykey.pem"),
    "cert_file": full_path("secrets/pki/mycert.pem"),
    "metadata": {
    },
    "organization": ORGANIZATION,
    "contact_person": CONTACTS,
    # This database holds the map between a subject's local identifier and
    # the identifier returned to a SP
    "xmlsec_binary": xmlsec_path,
    "attribute_map_dir": full_path("attributemaps"),
    "logger": {
        "rotating": {
            "filename": "logs/idp.log",
            "maxBytes": 500000,
            "backupCount": 5,
        },
        "loglevel": "debug",
    }
}
