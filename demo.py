from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/test', methods= ['GET', 'POST'])

def test():
    if request.method == "GET":
        return jsonify({"response":  "Get Request Called"})
    elif request.method == "POST":
        name = request.json['name']
        return jsonify({"response": "Hi "+ name})

if __name__ == "__main__":
    app.run(debug= True, port= 9090)



# from flask import Flask,render_template,url_for, jsonify, request
# from flask_sqlalchemy import SQLAlchemy
# from flask_login import UserMixin
# from flask_wtf import FlaskForm
# from wtforms import StringField, PasswordField, SubmitField
# from wtforms.validators import InputRequired, Length, ValidationError
# import psycopg2
# import re
# from flask_bcrypt import Bcrypt
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

