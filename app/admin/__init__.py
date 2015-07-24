__author__ = 'jgarman'

from flask_admin import Admin, BaseView, expose
from flask.ext import admin
from flask_admin.contrib import sqla
from flask import abort, redirect, url_for, request, flash
from flask.ext.login import current_user
from app.models import User, CbServer

from wtforms.fields import PasswordField, BooleanField
from wtforms import Form, validators

from cbapi import CbApi

from app.models import CbServer
from app.idp import load_metadata

import random
import string

class MyAdminIndexView(admin.AdminIndexView):
    @expose('/')
    def index(self):
        if not current_user.is_active() or not current_user.is_authenticated():
            return redirect(url_for('idp.login', next=request.url))

        if current_user.has_role('admin'):
            return super(MyAdminIndexView, self).index()

# Create customized model view class
class MyModelView(sqla.ModelView):

    def is_accessible(self):
        if not current_user.is_active() or not current_user.is_authenticated():
            return False

        if current_user.has_role('admin'):
            return True

        return False

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated():
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('idp.login', next=request.url))

class UserModelView(MyModelView):
    # Don't display the password on the list of Users
    column_exclude_list = ('password_hash',)
    form_columns = ('email', 'cb_username', 'first_name', 'last_name', 'active', 'roles')

    form_args = dict(
        cb_username = dict(validators=[validators.required()]),
        email = dict(validators=[validators.required()])
    )

    # Automatically display human-readable names for the current and available Roles when creating or editing a User
    column_auto_select_related = True

    # On the form for creating or editing a User, don't display a field corresponding to the model's password field.
    # There are two reasons for this. First, we want to encrypt the password before storing in the database. Second,
    # we want to use a password field (with the input masked) rather than a regular text field.
    def scaffold_form(self):

        # Start with the standard form as provided by Flask-Admin. We've already told Flask-Admin to exclude the
        # password field from this form.

        form_class = super(UserModelView, self).scaffold_form()

        # Add a password field, naming it "password2" and labeling it "New Password".
        form_class.password = PasswordField('Change Password',
                             [validators.optional(),
                              validators.equal_to('confirm_password')])
        form_class.confirm_password = PasswordField()
        form_class.active = BooleanField(default=True)

        return form_class

    # This callback executes when the user saves changes to a newly-created or edited User -- before the changes are
    # committed to the database.
    def on_model_change(self, form, model, is_created):
        # If the password field isn't blank...
#        if len(model.password2):
            # ... then encrypt the new password prior to storing it in the database. If the password field is blank,
            # the existing password in the database will be retained.
#            model.password = encrypt_password(model.password2)

        # now add/modify this user on all the connected Cb servers
        # TODO: this will only track *NEW* users, not changes. I don't believe on_model_change gives you
        # the before and after models, so I'm not sure how you can track the admin changing the cb_username after
        # the user's been created.

        # this will create a random password for each user
        if is_created:
            success_servers = []
            fail_servers = []
            existed_servers = []

            random_password = ''.join(random.SystemRandom().choice(string.digits + string.ascii_letters) for _ in range(30))
            for server in CbServer.query.all():
                c = server.connect_cb()

                try:
                    if len([x for x in c.user_enum() if x['username'] == model.cb_username]) == 1:
                        existed_servers.append(c.server)
                    else:
                        c.user_add_from_data(model.cb_username, model.first_name, model.last_name, random_password,
                                             random_password, False, [1], model.email)
                        success_servers.append(c.server)
                except:
                    import traceback
                    traceback.print_exc()
                    fail_servers.append(c.server)

            message = "User {0:s} ".format(model.cb_username)
            statuses = []
            if len(success_servers):
                statuses.append("added to servers {0:s}".format(", ".join(success_servers)))
            if len(existed_servers):
                statuses.append("already exists on servers {0:s}".format(", ".join(existed_servers)))
            if len(fail_servers):
                statuses.append("failed to add to servers {0:s}".format(", ".join(fail_servers)))

            flash(message + ', '.join(statuses))

    def on_model_delete(self, model):
        for server in CbServer.query.all():
            c = server.connect_cb()
            try:
                c.user_del(model.cb_username)
            except:
                flash("Could not remove user {0:s} from Cb server {1:s}".format(model.cb_username, c.server))

    def validate_form(self, form):
        if not super(UserModelView, self).validate_form(form):
            return False

        return True



class CbModelView(MyModelView):
    column_exclude_list = ('saml_sp_config',)
    form_args = dict(
        url=dict(label='Cb server URL', validators=[validators.required()]),
        admin_key=dict(validators=[validators.required()]),
        saml_sp_config=dict(validators=[validators.required()])
    )

    def on_model_change(self, form, model, is_created):
        if is_created:
            (already_exist, failed_users, success_users) = bulk_synchronize(
                CbApi(model.url, token=model.admin_key, ssl_verify=False)
            )

            statuses = []
            if len(already_exist):
                statuses.append("Users {0:s} already existed".format(", ".join(already_exist)))
            if len(failed_users):
                statuses.append("Failed to add users {0:s}".format(", ".join(failed_users)))

            flash(". ".join(statuses))

        else:
            # all we do here is to update the SAML SP configuration
            load_metadata(model.id, model.saml_sp_config)

    def on_model_delete(self, model):
        pass

    def validate_form(self, form):
        if not super(CbModelView, self).validate_form(form):
            return False

        if not hasattr(form, 'url') or not hasattr(form, 'admin_key'):
            return True

        cb_server = form.url.data
        cb_token = form.admin_key.data

        # validate that we can connect to the cb server using the token provided
        c = CbApi(cb_server, token=cb_token, ssl_verify=False)
        try:
            info = c.info()
            return True
        except:
            import traceback
            traceback.print_exc()
            for field in [form.url, form.admin_key]:
                field.errors.append("Could not contact a Cb server at this URL and token")
            return False


def bulk_synchronize(target_cb):
    user_details = dict([(row.cb_username, row) for row in User.query.all()])
    my_users = set(user_details.keys())
    cb_users = set([u['username'] for u in target_cb.user_enum()])

    already_exist = my_users.intersection(cb_users)
    add_users = my_users - cb_users
    failed_users = []
    success_users = []

    for u in add_users:
        random_password = ''.join(random.SystemRandom().choice(string.digits + string.ascii_letters) for _ in range(30))

        user_record = user_details[u]
        try:
            target_cb.user_add_from_data(u, user_record.first_name, user_record.last_name, random_password,
                                         random_password, False, [1], user_record.email)
            success_users.append(u)
        except:
            failed_users.append(u)

    return already_exist, failed_users, success_users

def setup_admin(app, db):
    admin = Admin(app=app, template_mode='bootstrap3', index_view=MyAdminIndexView())
    admin.add_view(UserModelView(User, db.session))
    admin.add_view(CbModelView(CbServer, db.session))

    return admin
