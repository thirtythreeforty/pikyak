#!/usr/bin/python2

from flask import Flask, request, g, jsonify, url_for, safe_join, send_from_directory, redirect
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
    block = db.Column(db.Boolean, nullable = False)
    score = db.Column(db.Integer, nullable = False)
    num_flags = db.Column(db.Integer, nullable = False)
    votes = db.relationship('Vote', backref='post', cascade='delete')
    flags = db.relationship('Flag', backref='post', cascade='delete')
    

    def __init__(self, **args):
        # Can pass either User object or user_id string
        self.user = args.get('user')
        self.user_id = args.get('user_id')

        # same as user above
        self.conversation = args.get('conversation')
        self.conversation_id = args.get('conversation_id')

        self.block = False
        self.score = 0
        self.num_flags = 0

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
        
class Flag(db.Model, AsDictMixin):
    __tablename__ = 'flags'
    _exportables = []
    id = db.Column(db.Integer, primary_key = True)
    user_id = db.Column(db.String(maxIDlength), db.ForeignKey('users.username'), nullable = False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable = False)
    value = db.Column(db.Boolean, nullable = False)

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
        vote = Vote( user = g.user, post_id = post_id, value = j.get("value"))
        post = Post.query.get(post_id)
    else:
        post = vote.post
        post.score -= vote.value
        vote.value = j.get("value")

    post.score += vote.value

    db.session.add(vote)
    db.session.add(post)
    db.session.commit()
    # Request succeeded  
    return "", 201
    
@app.route("/posts/<int:post_id>/user_score", methods=["DELETE"])
@auth.login_required
def removeVote(post_id):
    vote = Vote.query.filter_by(post_id = post_id, user = g.user).scalar()
    if vote is None:
        # Bad request: Post does not exist
        return "", 404

    post = Post.query.get(post_id)
        
    post.score -= vote.value
    db.session.add(post)
    db.session.delete(vote)
    db.session.commit()
    # Success: No Content
    return "", 204
    
@app.route("/conversations/<int:conversation_id>/user_score", methods=["PUT","DELETE"])
@auth.login_required
def voteConversation(conversation_id):
    conversation = Conversation.query.get(conversation_id)
    if conversation is None:
        return "", 404

    if request.method == "PUT":
        return createVote(post_id = conversation.posts[0].id)
    else:
        return removeVote(post_id = conversation.posts[0].id)
    

@app.route("/conversations", methods=["GET"])
def listConversations():
    conversations = Conversation.query.order_by(Conversation.id.desc()).paginate(int(request.args.get('first')) + 1, per_page=10).items
    
    response = {"conversations":[]}
    for c in conversations:
        if c.posts[0].score <= -5:
            continue
        user_score = 0
        if request.authorization is not None:
            vote = Vote.query.filter_by(user_id = request.authorization["username"], post = c.posts[0]).scalar()
            if vote is not None:
                user_score = vote.value
        response["conversations"].append(
            {
                "id" : c.id,
                "url" : url_for('listConversations', id = c.id),
                "image" : images.url(c.posts[0].image),
                "score" : c.posts[0].score,
                "user_score" : user_score
            }
        )

    return jsonify(response), 200

@app.route("/conversations/<int:conversation_id>", methods=["GET"])
def listPosts(conversation_id):
    posts = Post.query.filter_by(conversation_id = conversation_id).order_by(Post.id.asc()).paginate(int(request.args.get('first')) + 1, per_page=10).items

    response = {"posts":[]}
    for p in posts:
        if p.score <= -5:
            continue
        user_score = 0
        if request.authorization is not None:
            vote = Vote.query.filter_by(user_id = request.authorization["username"], post = p).scalar()
            if vote is not None:
                user_score = vote.value
        response["posts"].append(
            {
                "id" : p.id,
                "image" : images.url(p.image),
                "score" : p.score,
                "user_score" : user_score
            }
        )
        
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
        conversation = Conversation.query.get(conversation_id)
        if conversation is None:
            return "Conversation is not in database", 400

        post = Post(user_id = request.authorization["username"], conversation = conversation)

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

@app.route("/posts/<int:post_id>/block", methods=["PUT","DELETE"])
@auth.login_required
def deletePost(post_id):
    if not g.user.is_moderator:
        # Forbidden, must be a moderator
        return "", 403
    post = Post.query.get(post_id)
    if post is None:
        # Post not in database
        return "", 400
        
    if request.method == "PUT":
       post.block =  True
       db.session.add(post)
       db.session.commit()
       # Post deleted
       return "", 204 
    else:
        post.block = False
        db.session.add(post)
        db.session.commit()
        # Post restored
        return "", 201

@app.route("/conversations/<int:conversation_id>/block", methods = ["PUT","DELETE"])
@auth.login_required
def deleteConversation(conversation_id):
    if not g.user.is_moderator:
        # Forbidden, must be a moderator
        return "", 403
    conversation = Conversation.query.get(conversation_id)
    if conversation is None:
        # Conversation not in database
        return "", 400
    if request.method == "PUT":  
        conversation.block = True
        db.session.add(conversation)
        db.session.commit()
        # Conversation deleted
        return "",204
    else:
        conversation.block = True
        db.session.add(conversation)
        db.session.commit()
        # Conversation undeleted
        return "",201

@app.route("/posts/<int:post_id>/flag", methods = ["DELETE"])
@auth.login_required
def clearPostFlags(post_id):
    post = Post.query.get(post_id)
    if post is None:
        # Post not in database
        return "", 400
    
    post.num_flags = 0
    # Request successful
    return "",201
        
@app.route("/conversations/<int:conversation_id>/flag", methods = ["PUT"])
@auth.login_required
def clearConFlags(conversation_id):
    conversation = Conversation.query.get(conversation_id)
    if conversation is None:
        # Conversation not in database
        return "", 400
    # Redirect to handle the post
    return clearPostFlags(post_id = conversation.posts[0].id)
    
@app.route("/posts/{int:post_id}/flag", methods = ["PUT"])
@auth.login_required
def flagPost(post_id):
    post = Post.query.get(post_id)
    if post is None:
        # Post not in database
        return "",400
    
    flag = Flag.query.filter_by(post_id = post_id, user_id = g.user.username).scalar(),
    if flag is None:
        flag = Flag(user = g.user, post_id = post_id, value = 1)
        post = Post.query.get(post_id)
    else:
        post = flag.post
        post.num_flags -= flag.value
        flag.value = 1

    post.num_flags += flag.value

    db.session.add(flag)
    db.session.add(post)
    db.session.commit()
    # Request succeeded  
    return "", 201
    
@app.route("/conversations/{int:conversation_id}/flag", methods = ["PUT"])
@auth.login_required
def flagConversation(conversation_id):
    conversation = Conversation.query.get(conversation_id)
    if conversation is None:
        # conversation not in database
        return "",400
        
    # Redirect to flag first post in conversation
    return flagPost(post_id = conversation.posts[0].id)
        
@app.route("/images/<path:filename>", methods = ["GET"])
def getImage(filename):
    return send_from_directory("images", filename)

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=app.config['DEBUG'])
