from flask.ext.login import UserMixin
from app.shared import db
from werkzeug.security import generate_password_hash, check_password_hash

# Define models
roles_users = db.Table('roles_users',
        db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
        db.Column('role_id', db.Integer(), db.ForeignKey('role.id')))

class Role(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __unicode__(self):
        return self.name

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if type(other) == str or type(other) == unicode:
            return self.name == other
        else:
            return self.name == other.name

    def __ne__(self, other):
        return not self.__eq__(other)

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True)
    first_name = db.Column(db.String(80))
    last_name = db.Column(db.String(80))
    password_hash = db.Column(db.String(255))

    cb_username = db.Column(db.String(255), unique=True)
    active = db.Column(db.Boolean())

    confirmed_at = db.Column(db.DateTime())
    last_login_at = db.Column(db.DateTime())
    current_login_at = db.Column(db.DateTime())
    last_login_ip = db.Column(db.String(45))
    current_login_ip = db.Column(db.String(45))
    login_count = db.Column(db.Integer)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def has_role(self, role_name):
        return role_name in self.roles

    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

    def __unicode__(self):
        return self.email