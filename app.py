from flask import Flask,render_template,url_for, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
import psycopg2
import re
from flask_bcrypt import Bcrypt
# app = Flask(__name__)
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Sr080601@localhost/DATA'
# app.config['SECRET_KEY'] = 'thisisasecretkey'
# db = SQLAlchemy(app)
# bcrypt = Bcrypt(app)


# class User(db.Model, UserMixin):
#     id= db.Column(db.Integer,primary_key= True)
#     username= db.Column(db.String(20), nullable= False, unique= True)
#     password= db.Column(db.String(80), nullable= False)

# with app.app_context():
#     db.create_all()



# @app.route('/')
# def home():
#     return render_template('home.html')

# @app.route('/login',methods=['GET','POST'])
# def login():
   
#     username= request.json['username']
#     password= request.json['password']

#     if not username or not password:
#         return jsonify({"message": "enter username and password"})
    
#     existing_user_username= User.query.filter_by(username= username).first()

#     if not existing_user_username or not bcrypt.check_password_hash(existing_user_username.password, password):
#         return jsonify({"message": "Invalid username or password"})
    
#     return jsonify({"message": "Login Successful"})

# @app.route('/register',methods=['GET','POST'])
# def register():

#     username= request.json['username']
#     password= request.json['password']

#     if len(username)>10:
#         return jsonify({"message": "username too long"})
    

#     password_regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$"
#     if not re.match(password_regex, password):
#         return jsonify({"message": "Password should be minimum eight characters, at least one uppercase letter, one lowercase letter and one number"})

#     existing_username= User.query.filter_by(username= username).first()

#     if existing_username:
#         return jsonify({"message": "Already exists"})

#     hashed_password= bcrypt.generate_password_hash(password).decode("utf-8")
#     new_user = User(username= username,password= hashed_password)
#     db.session.add(new_user)
#     db.session.commit()

#     return jsonify({"message": "register successful"})


# if __name__ == "__main__":
#     app.run(debug=True)


from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Sr080601@localhost/DATA'
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['JWT_SECRET_KEY'] = 'super-secret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

@app.route('/')
def home():
    return jsonify({'message': 'Hello, World!'})

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username or not password:
        return jsonify({"message": "enter username and password"}), 401

    user = User.query.filter_by(username=username).first()

    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"message": "Invalid username or password"}), 401

    access_token = create_access_token(identity=user.id)
    return jsonify(access_token=access_token), 200

@app.route('/display/<int:user_id>', methods=['GET'])
def display(user_id):
    user = User.query.filter_by(id = user_id).first()
    return jsonify({"username": user.username, "password": user.password})

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if len(username) > 10:
        return jsonify({"message": "username too long"}), 400

    password_regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$"
    if not re.match(password_regex, password):
        return jsonify({"message": "Password should be minimum eight characters, at least one uppercase letter, one lowercase letter and one number"}), 400

    existing_username = User.query.filter_by(username=username).first()

    if existing_username:
        return jsonify({"message": "Already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "register successful"}), 201

@app.route('/users/<int:user_id>', methods=['PATCH', 'DELETE'])
@jwt_required()
def update_user(user_id):
    user = User.query.get(user_id)

    if not user:
        return jsonify({"message": "User not found"}), 404

    if request.method == 'PATCH':
        username = request.json.get('username', None)
        password = request.json.get('password', None)

        if username:
            user.username = username

        if password:
            hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
            user.password = hashed_password

        db.session.commit()
        return jsonify({"message": "User updated successfully"}), 200

    elif request.method == 'DELETE':
        db.session.delete(user)
        db.session.commit()


@app.route('/protected' ,methods = ['GET'])
@jwt_required()
def protected():
    return jsonify({'message': 'You are authorized to access this resource.'}), 200

if __name__ == '__main__':
    app.run(debug=True)
