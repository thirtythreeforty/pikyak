#!/usr/bin/python2

from flask import Flask, request, g, jsonify, url_for
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.httpauth import HTTPBasicAuth
from sqlalchemy import exc, exists
from sqlalchemy.orm.exc import NoResultFound
from passlib.hash import sha256_crypt as crypt
from uuid import uuid4
import os

app = Flask(__name__)

app.config.update(dict(
    DEBUG=False,
))
app.config.from_envvar('PIKYAK_SETTINGS', silent=True)
app.config["SQLALCHEMY_DATABASE_URI"]="mysql://username:password@localhost/dbname"
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
    gcm_id = db.Column(db.String(maxIDlength))
    deleted = db.Column(db.Boolean)
    posts = db.relationship('Post', backref='user', cascade='delete')

    def __init__(self, **args):
        self.username = args.get('username')
        self.deleted = False
        self.gcm_id = args.get('gcm_id')

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
    image = db.Column(db.String(maxIDlength))
    user_id = db.Column(db.String(maxIDlength), db.ForeignKey('users.username'), nullable = False)
    conversation_id = db.Column(db.Integer, db.ForeignKey('conversations.id'), nullable = False)
    block = db.Column(db.Boolean)

    def __init__(self, **args):
        # Can pass either User object or user_id string
        self.user = args.get('user')
        self.user_id = args.get('user_id')
        
        # same as user above
        self.conversation = args.get('conversation')
        self.conversation_id = args.get('conversation_id')
        
        self.block = False

class Conversation(db.Model, AsDictMixin):
    __tablename__ = 'conversations'
    _exportables_ = ['posts']
    id = db.Column(db.Integer, primary_key = True)
    block = db.Column(db.Boolean)
    posts = db.relationship('Post', backref='conversation')
    
    def __init__(self, **args):
        self.block = False

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
def registerUser(userID):
    j = request.get_json()
    if j is None \
      or request.authorization is None \
      or request.authorization['username'] != userID:
        # Bad request
        return "", 400

    user = User(username = j.get("email"), gcm_id = j.get("gcm_id"))

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
@auth.login_required
def unregisterUser(userID):
    if userID != request.authorization['username']:
        # prevent anyone from deleting users except their own
        return "",403
        
    user = User.query.filter_by(username = userID).scalar()
    if (user is not None):
        db.session.delete(user)
        db.session.commit()
        return "", 204
    else:
        return "", 404

@app.route("/conversations", methods=["POST"])
@app.route("/conversations/<int:conversation_id>", methods = ["POST"])
@auth.login_required
def postImage(conversation_id = None):
    if request.files["image"] is None:
        # Bad request
        return "", 400
    
    # Ceate new conversation object for first post
    if conversation_id is None:
        post = Post(user_id = request.authorization["username"], conversation = Conversation())
    else:
        
        conID = db.query(conversation_id = conversation_id).scalar()
        if conID is None:
            return "Conversation is not in database", 400
            
        post = Post(username = request.authorization["username"], conversation = conID)
    
    # Decode image from json
    image = request.files["image"]
    
    # Save locally to random filename
    filename = "images/"
    filename += uuid4().hex
    filename += ".jpg"
    
    image.save(filename)    
    # store reference to the image in the db
    # TODO: The image URL will be of the form "/image/{}" so you need a new GET /image/{} view.
    post.image = filename
    
    db.session.add(post)
    db.session.commit()
    response = {
        "id":post.id,
        "conversation_id":conversation_id
    }
    # post successful!
    return jsonify(response), 201

# Functions should be combined but unsure how to manage the app.routes
@app.route("/posts/<int:post_id>/block", methods=["PUT"])
# TODO: Must be a moderator
@auth.login_required
def deletePost(post_id):
    if Post.query(post_id) is None:
        # Post not in database
        return "", 400
    post = Post.query.get(post_id)
    post.block =  True
    
    db.session.add(post)
    db.session.commit()
    # Post deleted
    return "", 204

@app.route("/conversations/<int:conversation_id>/block", methods = ["PUT"])
# TODO: Must be a moderator
@auth.login_required
def deleteConversation(conversation_id):
    if Conversation.query(conversation_id) is None:
        # Conversation not in database
        return "", 400
    conversation = Conversation.query.get(conversation_id)
    conversation.block = True
    
    db.session.add(conversation)
    db.session.commit()
    # Conversation deleted
    return "",204
    
# Should also be combined
@app.route("/posts/<int:post_id>/block", methods=["DELETE"])
# TODO: Must be a moderator
@auth.login_required
def deletePost(post_id):
    if Post.query(post_id) is None:
        # Post not in database
        return "", 400
    post = Post.query.get(post_id)
    post.block =  False
    
    db.session.add(post)
    db.session.commit()
    # Post undeleted
    return "", 201

@app.route("/conversations/<int:conversation_id>/block", methods = ["DELETE"])
# TODO: Must be a moderator
@auth.login_required
def deleteConversation(conversation_id):
    if Conversation.query(conversation_id) is None:
        # Conversation not in database
        return "", 400
    conversation = Conversation.query.get(conversation_id)
    conversation.block = False
    
    db.session.add(conversation)
    db.session.commit()
    # Conversation undeleted
    return "",201
    

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=app.config['DEBUG'])
