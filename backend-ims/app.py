# Initialize app
import os
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask import Flask, request, jsonify, Response
from flask_cors import CORS

app = Flask(__name__)
CORS(app)
cors = CORS(app, resource={
    r"/*":{
        "origins":"*"
    }
})
basedir = os.path.abspath(os.path.dirname(__file__))

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'db.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize db
db = SQLAlchemy(app)

# Initialize ma
ma = Marshmallow(app)


# Product Model
class User(db.Model):
  email = db.Column(db.String(100), primary_key=True)
  emailQ = db.Column(db.String(256))
  name = db.Column(db.String(100))
  nameQ = db.Column(db.String(256))
  age = db.Column(db.Integer)
  ageQ = db.Column(db.String(256))
  gender = db.Column(db.String(100))
  genderQ = db.Column(db.String(256))
  phnum = db.Column(db.Integer)
  phnumQ = db.Column(db.String(256))
  password = db.Column(db.String(100))

  def __init__(self, email, name, age, gender, phnum, emailQ, nameQ, ageQ, genderQ, phnumQ, password):
    self.email = email
    self.name = name
    self.age = age
    self.gender = gender
    self.phnum = phnum
    self.emailQ = emailQ
    self.nameQ = nameQ
    self.ageQ = ageQ
    self.genderQ = genderQ
    self.phnumQ = phnumQ
    self.password = password


# Product Schema
class UserSchema(ma.Schema):
  class Meta:
    fields = ('email', 'emailQ', 'name', 'nameQ', 'age', 'ageQ', 'gender', 'genderQ', 'phnum', 'phnumQ', 'password')

# Init schema
user_schema = UserSchema()
users_schema = UserSchema(many=True)

# Create a user
@app.route('/user', methods=['POST'])
def add_user():
  email = request.json['email']
  emailQ = request.json['emailQ']
  name = request.json['name']
  nameQ = request.json['nameQ']
  age = request.json['age']
  ageQ = request.json['ageQ']
  gender = request.json['gender']
  genderQ = request.json['genderQ']
  phnum = request.json['phnum']
  phnumQ = request.json['phnumQ']
  password = request.json['password']

  new_user = User(email, name, age, gender, phnum, emailQ, nameQ, ageQ, genderQ, phnumQ, password)

  db.session.add(new_user)
  db.session.commit()
  return user_schema.jsonify(new_user)

@app.route('/login', methods=['POST'])
def login():
  email = request.json['email']
  password = request.json['password']
  user = User.query.get(email)
  if(user.password == password):
    return user_schema.jsonify(user)
  else:
    return Flask.Response("Wrong password or email", 400)

# Get All users
@app.route('/user', methods=['GET'])
def get_users():
  all_users = User.query.all()
  result = users_schema.dump(all_users)
  return users_schema.jsonify(result)

# Get Single User
@app.route('/user/<id>', methods=['GET'])
def get_user(id):
  product = User.query.get(id)
  return user_schema.jsonify(product)

#Update a User
@app.route('/user/<id>', methods=['PUT'])
def update_user(id):
  user = User.query.get(id)

  email = request.json['email']
  emailQ = request.json['emailQ']
  name = request.json['name']
  nameQ = request.json['nameQ']
  age = request.json['age']
  ageQ = request.json['ageQ']
  gender = request.json['gender']
  genderQ = request.json['genderQ']
  phnum = request.json['phnum']
  phnumQ = request.json['phnumQ']

  user.email = email
  user.emailQ = emailQ
  user.name = name
  user.nameQ = nameQ
  user.age = age
  user.ageQ = ageQ
  user.gender = gender
  user.genderQ = genderQ
  user.phnum = phnum
  user.phnumQ = phnumQ


  db.session.commit()

  return user_schema.jsonify(user)

# Delete User
@app.route('/user/<id>', methods=['DELETE'])
def delete_user(id):
  user = User.query.get(id)
  db.session.delete(user)
  db.session.commit()

  return user_schema.jsonify(user)
