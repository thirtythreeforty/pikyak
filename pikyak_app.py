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
    __tablename__ = 'users'
    _exportables_ = []
    username = db.Column(db.String(maxIDlength), primary_key = True)
    hash_password = db.Column(db.String(maxIDlength))
    deleted = db.Column(db.Boolean)
    posts = db.relationship('Post', backref='user', cascade='delete')

    def __init__(self, **args):
        self.username = args.get('username')
        self.deleted = False

    # Authentication
    def hash_new_password(self, password):
        self.hash_password = crypt.encrypt(password)
        return self.hash_password

    def verify_password(self, password):
        return crypt.verify(password, self.hash_password)

class Post(db.Model, AsDictMixin):
    __tablename__ = 'posts'
    _exportables_ = ['user_id', 'conversation_id']
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.String(maxIDlength), db.ForeignKey('users.username'), nullable = False)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversations.id'), nullable = False)

    def __init__(self, **args):
        self.user = args.get('user')
        self.user_id = args.get('user_id')
        self.conversation = args.get('conversation')
        self.conversation_id = args.get('conversation_id')

class Conversation(db.Model, AsDictMixin):
    __tablename__ = 'conversations'
    _exportables_ = ['posts']
    id = db.Column(db.Integer, primary_key = True)
    posts = db.relationship('Post', backref='conversation')

class Vote(db.Model, AsDictMixin):
    __tablename__ = 'votes'
    _exportables = []
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.String(maxIDlength), db.ForeignKey('users.username'), nullable = False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable = False)
    value = db.Column(db.Integer, nullable = False)

    def __init__(self, **args):
        self.user = args.get('user')
        self.user_id = args.get('user_id')
        self.post = args.get('post')
        self.post_id = args.get('post_id')
        self.value = args.get('value')

# Authentication
@auth.verify_password
def verify_password(username, password):
    user = User.query.filter_by(username = username).first()
    if not user or not user.verify_password(password):
        return False
    g.user = user
    return True

# Views

@app.route("/users/<userID>", methods=["PUT"])
def registerPeer(userID):
    j = request.get_json()
    if j is None:
        # Bad request
        return "", 400

    # TODO create User object here
	user = User(username = request.authorization['username'])


    password = request.authorization["password"]
    user.hash_new_password(password)

    db.session.add(user)
    try:
        db.session.commit()
    except exc.IntegrityError:
        # Already registered.
        return "", 409

    # User created!
    return "", 201

@app.route("/users/<userID>", methods=["DELETE"])
def unregisterPeer(userID):
    j = request.get_json()
    if j is None:
        # Bad request
        return "", 400

    user = db.query.filter_by(userID="userID").scalar()
    if (user is not None):
        db.session.delete(user)
        db.session.commit()
        return "", 204
    else:
        return "", 404

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=app.config['DEBUG'])
