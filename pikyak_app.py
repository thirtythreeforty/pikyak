#!/usr/bin/python2

from flask import Flask, request, g, jsonify, url_for
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.httpauth import HTTPBasicAuth
from sqlalchemy import exc, exists
from sqlalchemy.orm.exc import NoResultFound
from passlib.hash import sha256_crypt as crypt
import os

app = Flask(__name__)

app.config.update(dict(
    DEBUG=False,
    SECRET_KEY='development key',
    USERNAME='admin',
    PASSWORD='default'
))
app.config.from_envvar('PIKYAK_SETTINGS', silent=True)
app.config["SQLALCHEMY_DATABASE_URI"]="mysql://localhost/pikyak"
db = SQLAlchemy(app)

auth = HTTPBasicAuth()

# Models
maxIDlength = 255

class AsDictMixin(object):
    # Exportables are members that can be safely serialized to a client
    _exportables = []
    def asdict(self):
        result = {}
        for key in self._exportables_:
            result[key] = getattr(self, key)
        return result

class User(db.Model, AsDictMixin):
    __tablename__ = "users"
    _exportables_ = ["username", "email"]
    username = db.Column(db.String(maxIDlength), nullable = False, unique = True, primary_key = True)
    email = db.Column(db.String(maxIDlength))
    hash_password = db.Column(db.String(maxIDlength))
    deleted = db.Column(db.Boolean)
    posts = db.relationship('Post', backref='author', cascade='delete')

    def __init__(self, **args):
        self.username = args.get("username")
        self.email = args.get("email")
        self.deleted = False

    # Authentication
    def hash_new_password(self, password):
        self.hash_password = crypt.encrypt(password)
        return self.hash_password

    def verify_password(self, password):
        return crypt.verify(password, self.hash_password)

class Post(db.Model, AsDictMixin):
    __tablename__ = 'posts'
    _exportables_ = []
    id = db.Column(db.Integer, primary_key = True)
    author_id = db.Column(db.String(maxIDlength), db.ForeignKey("users.username"), nullable = False)

    def __init__(self, **args):
        self.author = args.get("author")


# Authentication
@auth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username = username).first()
    if not user or not user.verify_password(password):
        return False
    g.user = user
    return True

# Views are TODO

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=app.config['DEBUG'])
