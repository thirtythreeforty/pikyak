#!/usr/bin/python2

from flask import Flask, request, g, jsonify, url_for, safe_join, send_from_directory
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.httpauth import HTTPBasicAuth
from flask.ext.uploads import UploadSet, IMAGES, configure_uploads
from sqlalchemy import exc, exists
from sqlalchemy.orm.exc import NoResultFound
from passlib.hash import sha256_crypt as crypt
from uuid import uuid4
import os
import random

app = Flask(__name__)

app.config.update(dict(
    DEBUG=False,
    ALLOWED_EXTENSIONS=set(['jpg', 'gif', 'png']),
    MAX_CONTENT_LENGTH = 1024 * 1024 * 16,

    UPLOADED_IMAGES_DEST = "images",
))
app.config.from_envvar('PIKYAK_SETTINGS', silent=True)
app.config["SQLALCHEMY_DATABASE_URI"]="mysql://username:password@localhost/dbname"
db = SQLAlchemy(app)

auth = HTTPBasicAuth()

images = UploadSet('images', IMAGES, default_dest = lambda app: app.instance_root)
configure_uploads(app, (images,))

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
    is_moderator = db.Column(db.Boolean)
    posts = db.relationship('Post', backref='user', cascade='delete')
    votes = db.relationship('Vote', backref='user', cascade='delete')

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
    votes = db.relationship('Vote', backref='post')

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
        
@app.route("/users/<int:user_id>", methods=["GET"])
@auth.login_required
def getUser(user_id):
    user = g.user
    if user.user_id != user_id: 
        # Bad request
        return "", 400
    
    response = {
        "user_id" : user.user_id,
        "is_moderator" : user.is_moderator
    }
    return jsonify(response), 200
    
@app.route("/posts/<int:post_id>/user_score", methods=["PUT"])
@auth.login_required
def createVote(post_id):
    j = request.get_json()
    if j is None:
        # Bad request
        return "", 400
    
    if abs(j.get("value")) != 1:
        # Bad request
        return "",400
    
    vote = Vote.query.filter_by(post_id = post_id, user_id = g.user.username).scalar()
    if vote is None:
        vote = Vote( user = g.user, post_id = post_id)
    vote.value = int(j.get("value"))
    
    db.session.add(vote)
    db.session.commit()
    # Request succeeded  
    return "", 201
    
@app.route("/posts/<int:post_id>/user_score", methods=["DELETE"])
@auth.login_required
def removeVote(post_id):
    vote = Vote.query.filter_by(post_id = post_id, user_id = g.user.username).scalar()
    if vote is None:
        # Bad request: Post does not exist
        return "", 400
    
    vote.value = None
    db.session.add(vote)
    db.session.commit()
    # Success: No Content
    return "", 204
    

@app.route("/conversations", methods=["GET"])
def listConversations():
    conversations = Conversation.query.order_by(Conversation.id.desc()).paginate(int(request.args.get('first')) + 1, per_page=10).items
    
    response = {
        "conversations" : [
            {
                "id" : c.id,
                "url" : url_for('listConversations', id = c.id),
                "image" : images.url(c.posts[0].image),
                "score" : sum([
                    v.value for v in c.posts[0].votes
                ])
            } for c in conversations
        ]
    }
    return jsonify(response), 200

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

        conversation = db.query(conversation_id = conversation_id).scalar()
        if conversation is None:
            return "Conversation is not in database", 400

        post = Post(username = request.authorization["username"], conversation = conversation)

    # Save locally to random filename
    filename = uuid4().hex + "." # flask-uploads will append the correct extension if the filename ends in '.'
    filename = images.save(request.files["image"], name = filename)

    # store reference to the image in the db
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
@auth.login_required
def deletePost(post_id):
    if not g.user.is_moderator:
        # Forbidden, must be a moderator
        return "", 403
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
@auth.login_required
def deleteConversation(conversation_id):
    if not g.user.is_moderator:
        # Forbidden, must be a moderator
        return "", 403
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
@auth.login_required
def restorePost(post_id):
    if not g.user.is_moderator:
        # Forbidden, must be a moderator
        return "", 403
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
@auth.login_required
def restoreConversation(conversation_id):
    if not g.user.is_moderator:
        # Forbidden, must be a moderator
        return "", 403
    if Conversation.query(conversation_id) is None:
        # Conversation not in database
        return "", 400
    conversation = Conversation.query.get(conversation_id)
    conversation.block = False

    db.session.add(conversation)
    db.session.commit()
    # Conversation undeleted
    return "",201

@app.route("/images/<path:filename>", methods = ["GET"])
def getImage(filename):
    # TODO: ensure the client gets a 404 if they pass something nasty like ../../../../etc/passwd.
    return send_from_directory("images", filename)

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=app.config['DEBUG'])
