__author__ = 'jgarman'

from app.shared import db
from cbapi import CbApi

class CbServer(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    description = db.Column(db.String(255))
    url = db.Column(db.String(255), unique=True)
    admin_key = db.Column(db.String(128))
    saml_sp_config = db.Column(db.Text())

    def __unicode__(self):
        return self.url

    def connect_cb(self):
        return CbApi(self.url, token=self.admin_key, ssl_verify=False)
