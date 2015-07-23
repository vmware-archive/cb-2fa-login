from flask import Flask
from flask_bootstrap import Bootstrap
from flask.ext.login import LoginManager
from ConfigParser import ConfigParser
import os.path

from idp import idp_component
from idp import load_all_metadata

from admin import setup_admin

from shared import db
from models import User, Role, CbServer

app = Flask(__name__)
Bootstrap(app)

class ConfigStruct(object):
    def __init__(self, entries):
        self.__dict__.update(entries)

def generate_config():
    config_parser = ConfigParser()
    current_directory = os.path.dirname(os.path.abspath(__file__))
    config_parser.read(os.path.normpath(os.path.join(current_directory, '..', 'secrets', 'secrets.ini')))

    config = dict(zip([option.upper() for option in config_parser.options('core')],
                [config_parser.get('core', y) for y in config_parser.options('core')]))

    for section in [s for s in config_parser.sections() if s != 'core']:
        config[section] = ConfigStruct(dict(zip(config_parser.options(section),
                [config_parser.get(section, y) for y in config_parser.options(section)])))

    print config
    return config

app.config.update(generate_config())
app.config['DEBUG'] = True
app.config['TESTING'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///idp.db'
app.config['WTF_CSRF_ENABLED'] = True

# load our blueprints:
app.register_blueprint(idp_component)

# Setup Flask-Security
lm = LoginManager(app)
lm.login_view = 'idp.login'

@lm.user_loader
def load_user(user_id):
    """User loader callback for Flask-Login."""
    return User.query.get(int(user_id))

db.init_app(app)
admin = setup_admin(app, db)

@app.before_first_request
def initialize_self():
    load_all_metadata()
    print 'done initializing'

# Create a user to test with
def create_base_data(u):
    with app.app_context():
        db.drop_all()
        db.create_all()

        r = Role(name='admin', description='Superuser')
        u.roles.append(r)

        db.session.add(r)
        db.session.add(u)
        db.session.commit()

