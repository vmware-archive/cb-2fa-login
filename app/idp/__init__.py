__author__ = 'jgarman'

from flask import render_template, flash, redirect, url_for, request, session, Response, Blueprint

idp_component = Blueprint('idp', __name__, template_folder='templates')

from hashlib import sha1
from forms import LoginForm
from lib import duo_web
from flask.ext.login import login_required, logout_user, current_user
from flask import current_app
from saml2 import server, config, sigver, SAMLError
from saml2.mdstore import InMemoryMetaData
import dateutil
from urlparse import urlparse, urljoin
from flask.ext.login import LoginManager, UserMixin, login_user

from saml2.metadata import entity_descriptor, metadata_tostring_fix

from app.models import User

from functools import wraps

from datetime import datetime,timedelta

from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
import base64

import logging

sec_config = config.Config()
sec_config.load_file('idp_conf.py')
sec_config.xmlsec_binary = sigver.get_xmlsec_binary(["/usr/local/bin"])

# temporary
l = logging.getLogger('saml2.mdstore')
l.setLevel(logging.DEBUG)
ch = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
l.addHandler(ch)

def user_to_saml_assertion(user):
    return {
        'surname': user.last_name,
        'givenName': user.first_name,
        'uid': user.cb_username,
        'email': user.email
    }

class Cache(object):
    def __init__(self):
        self.user2uid = {}
        self.uid2user = {}

class MetaDataStream(InMemoryMetaData):
    """
    Handles Metadata file on the same machine. The format of the file is
    the SAML Metadata format.
    """
    def __init__(self, onts, attrc, data=None, cert=None, **kwargs):
        super(MetaDataStream, self).__init__(onts, attrc, **kwargs)
        if not data:
            raise SAMLError('No metadata specified.')
        self.data = data
        self.cert = cert

    def get_metadata_content(self):
        return self.data

    def load(self):
        _txt = self.get_metadata_content()
        return self.parse_and_check_signature(_txt)

IDP = server.Server("./idp_conf.py", cache=Cache())
IDP.ticket = {}

from app.models import CbServer
def load_metadata(id, md):
    mw = MetaDataStream(IDP.metadata.onts, IDP.metadata.attrc, data=md)
    mw.load()
    IDP.metadata.metadata[id] = mw

def load_all_metadata():
    for server in CbServer.query.all():
        load_metadata(server.id, server.saml_sp_config)

def duo_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if need_duo_login():
            return redirect(url_for('idp.duo_login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def need_duo_login():
    if 'duo_expiry' in session:
        try:
            print 'got duo_expiry: %s' % session['duo_expiry']
            duo_expiry = dateutil.parser.parse(session['duo_expiry'])
            if datetime.now() < duo_expiry:
                return False
            else:
                session.pop('duo_expiry')
        except:
            session.pop('duo_expiry')

    return True

@idp_component.route('/')
@login_required
def index():
    return render_template('index.html', title="Home", user=current_user.email)

@idp_component.route('/sso', methods=['GET', 'POST'])
@login_required
def saml_idp_endpoint():
    if 'SAMLRequest' not in request.values:
        return redirect(url_for('.index'))

    key = sha1(request.values.get("SAMLRequest")).hexdigest()
    IDP.ticket[key] = {'SAMLRequest': request.values.get('SAMLRequest'),
                       'RelayState': request.values.get('RelayState')}

    session['saml_key'] = key
    return handle_saml_request()

    # FIXME: this is here for now to ensure that our metadata is properly stored in the metadata cache
    # once we have validated that, then this can be removed... but we *should* validate that the request
    # comes from a valid SAML SP before completing the login process......

def handle_saml_request():
    print 'in handle_saml_request'
    if 'saml_key' not in session or session['saml_key'] not in IDP.ticket:
        flash("Could not find saml key", "danger")
        return redirect("/")

    saml_msg = IDP.ticket[session['saml_key']]
    del IDP.ticket[session['saml_key']]

    request = IDP.parse_authn_request(saml_msg["SAMLRequest"], BINDING_HTTP_REDIRECT)
    response_args = IDP.response_args(request.message)
    # TODO: Note that there is a specific authn type for 2fa tokens:
    # urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken

    # TODO: we should respect the SP's request to optionally force re-authentication
    response_args["authn"] = {'authn_auth': '',
 'class_ref': 'urn:oasis:names:tc:SAML:2.0:ac:classes:Password',
 'level': 10,
 'method': ''}

    resp = IDP.create_authn_response(user_to_saml_assertion(current_user),
           userid=current_user.email.encode('ascii'), sign_assertion=True, **response_args)

    binding_out, destination = IDP.pick_binding("assertion_consumer_service", bindings=[BINDING_HTTP_POST],
                                                entity_id=request.message.issuer.text, request=request.message)

    print '%s' % resp

    # now we post this back to the SP
    post_args = {
        'saml_key': 'SAMLResponse',
        'location': destination,
        'saml_message': base64.b64encode('%s' % resp),
        'relay_state' : saml_msg["RelayState"]
    }

    return render_template("saml_post_back.html", **post_args)

@idp_component.route('/logout')
@login_required
def logout():
    if 'saml_key' in session:
        session.pop('saml_key')
    if 'duo_expiry' in session:
        session.pop('duo_expiry')
    logout_user()
    return redirect('/')

def returns_xml(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        r = f(*args, **kwargs)
        return Response(r, content_type='text/xml; charset=utf-8')
    return decorated_function

@idp_component.route('/idp.xml')
@returns_xml
def saml_metadata():
    ed = entity_descriptor(sec_config)
    return metadata_tostring_fix(ed, {"xs": "http://www.w3.org/2001/XMLSchema"}, None)

def clear_preauth():
    session.pop('preauth', None)

def set_preauth(user):
    session['preauth'] = user.id

@idp_component.route('/2fa/validate', methods=['GET', 'POST'])
def twofactor():
    if current_user.is_authenticated():
        print 'validated'
        return redirect(get_redirect_target())

    user_preauth = session.get('preauth', None)
    try:
        print 'user_preauth = %s' % user_preauth
        u = User.query.get(int(user_preauth))
        print '<user:', u.email, '>'
        if not u: # or not u.active:
            clear_preauth()
            flash("Invalid login", "danger")
            return redirect(url_for('.login'))
    except:
        import traceback
        traceback.print_exc()
        clear_preauth()
        flash("Invalid login", "danger")
        return redirect(url_for('.login'))

    if need_duo_login():
        duo_config = current_app.config['duo']
        if request.method == 'POST':
            # validate response
            print 'in duo POST'
            try:
                sig_response = request.form["sig_response"]
                print 'sig_response', sig_response
                user = duo_web.verify_response(duo_config.ikey, duo_config.skey, duo_config.akey, sig_response)
                print 'user is %s' % user
                if user is None:
                    user = duo_web.verify_enroll_response(duo_config.ikey, duo_config.skey, duo_config.akey, sig_response)
                    if user is None:
                        flash("Invalid duo login", "danger")
                        return redirect(url_for('.twofactor'))
                    else:
                        pass
                        #flash("Enrolled new user %s with Duo" % user, "success")
                        #return redirect('/index')
                else:
                    pass
                    #flash("Successfully logged in with Duo as %s" % user, "success")
                    #return redirect('/index')
            except:
                import traceback
                traceback.print_exc()
                flash("Invalid login attempt", "danger")
                return redirect("/")

            duo_expiry = (datetime.now() + timedelta(minutes=10)).isoformat()
            print duo_expiry
            session['duo_expiry'] = duo_expiry

            clear_preauth()
            login_user(u)

            return redirect(get_redirect_target())
        else:
            print 'user_email is', u.email
            sig_request = duo_web.sign_request(
                        duo_config.ikey, duo_config.skey, duo_config.akey,
                        u.email)

            print 'sig_request is', sig_request
            print 'duo_config_host is', duo_config.host

            return render_template("duo_login.html", host=duo_config.host, sig_request=sig_request)
    else:
        print "don't need duo login"
        clear_preauth()
        login_user(u)
        return redirect(get_redirect_target())

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

def get_redirect_target(default='/'):
    for target in request.values.get('next'), request.referrer:
        if not target:
            continue
        if is_safe_url(target):
            return target

    return default

@idp_component.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated():
        return redirect('/')

    clear_preauth()
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email_address.data).first()
        if user is None or not user.verify_password(form.password.data):
            flash("Invalid login", "danger")
            return redirect(url_for('.login'))

        set_preauth(user)
        return redirect(url_for('.twofactor', next=get_redirect_target()))

    return render_template('login.html', form=form)
