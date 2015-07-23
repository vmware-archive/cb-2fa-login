from flask.ext.wtf import Form
from wtforms import StringField, PasswordField, validators


class LoginForm(Form):
    email_address = StringField('Email Address', [validators.Length(min=6, max=100), validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])

