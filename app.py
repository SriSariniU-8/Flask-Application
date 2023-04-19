from flask import Flask,render_template,url_for, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, ValidationError
import psycopg2
import re
from flask_bcrypt import Bcrypt
from datetime import timedelta

from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.orm import sessionmaker

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
    manager_id = db.Column(db.Integer)
class admin(db.Model):
    id= db.Column(db.Integer, primary_key=True)
    admin_name = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

class manager(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    manager_name = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

with app.app_context():
    # db.init_app(app)
    db.create_all()


@app.route('/')
def home():
    return jsonify({'message': 'Hello, World!'})

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username or not password:
        return jsonify({"message": "enter username and password"}), 401

    user = (User.query.filter_by(username=username).first() or admin.query.filter_by(admin_name=username).first() or manager.query.filter_by(manager_name=username).first())

    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"message": "Invalid username or password"}), 401

    access_token = create_access_token(identity=user.id,expires_delta=timedelta(hours=1))
    return jsonify(access_token=access_token), 200
    return jsonify({"message":"LOgin successful"})
    # admin.get(email)

@app.route('/display', methods=['GET'])
def display():
    user_id= request.json.get('id', None)
    role= request.json.get('role', None)
    if(role == 'user'):
        user = User.query.filter_by(id = user_id).first()
        return jsonify({"username": user.username, "password": user.password})

    if(role == 'admin'):
        Admin = admin.query.filter_by(id = user_id).first()
        return jsonify({"username": Admin.admin_name, "password": Admin.password})

    if(role == 'manager'):
        Manager = manager.query.filter_by(id = user_id).first()
        return jsonify({"username": Manager.manager_name, "password": Manager.password})

@app.route('/search', methods=['GET'])
def search():
    search_by= request.json.get('search_by')
    name= request.json.get('name', None)
    role= request.json.get('role', None)
    # user_id= request.json.get('userid', None)
    # user = User.query.get(user_id)
    if(search_by== 'name'):
        person= []
        users = User.query.filter_by(username=name).all()
        for user in users:
            person.append({'id': user.id, 'username': user.username, 'password': user.password})
        admins = admin.query.filter_by(admin_name=name).all()
        for Admin in admins:
            person.append({'id': Admin.id, 'admin_name': Admin.admin_name, 'password': Admin.password})
        managers = manager.query.filter_by(manager_name=name).all()
        for Manager in managers:
            person.append({'id': Manager.id, 'manager_name': Manager.manager_name, 'password': Manager.password})

        return jsonify(person)
    
    elif search_by == 'role':
        persons = []
        if role == 'employee':
            users = User.query.all()
            for user in users:
                persons.append({'id': user.id, 'username': user.username, 'password': user.password})

        elif role == 'admin':
            admins = admin.query.all()
            for Admin in admins:
                persons.append({'id': Admin.id, 'admin_name': Admin.admin_name, 'password': Admin.password})

        elif role == 'manager':
            managers = manager.query.all()
            for Manager in managers:
                persons.append({'id': Manager.id, 'manager_name': Manager.manager_name, 'password': Manager.password})

        return jsonify(persons)

        # return jsonify([p.serialize() for p in person])

    return jsonify({'message': 'Invalid search_by parameter'}), 400


    #     return jsonify({"id": person[0], "name": person[1], "password": person[2]})
    # print(user)


    # elif search_by == 'role':


    # return jsonify({"username": user.username, "password": user.password})

@app.route('/register', methods=['POST'])
def register():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    role= request.json.get('role', None)

    if len(username) > 10:
        return jsonify({"message": "username too long"}), 400

    password_regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$"
    if not re.match(password_regex, password):
        return jsonify({"message": "Password should be minimum eight characters, at least one uppercase letter, one lowercase letter and one number"}), 400

    # existing_username = (User.query.filter_by(username=username).first() or admin.query.filter_by(admin_name=username).first() or manager.query.filter_by(manager_name=username).first())

    # if existing_username:
    #     return jsonify({"message": "Already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    if role== 'admin':
        new_user= admin(admin_name= username, password= hashed_password)

    if role== 'user':
        new_user = User(username=username, password=hashed_password)
    
    if role== 'manager':
        new_user = manager(manager_name=username, password=hashed_password)

    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "register successful"}), 201

# @app.route('/register', methods=['POST'])
# @jwt_required()
# def register():
#     current_user_id = get_jwt_identity()
#     adminx = admin.query.filter_by(id=current_user_id).first()
#     if adminx:
#         username = request.json.get('username', None)
#         password = request.json.get('password', None)
#         role= request.json.get('role', None)

#         if len(username) > 10:
#             return jsonify({"message": "username too long"}), 400

#         password_regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$"
#         if not re.match(password_regex, password):
#             return jsonify({"message": "Password should be minimum eight characters, at least one uppercase letter, one lowercase letter and one number"}), 400

#         existing_username = (User.query.filter_by(username=username).first() or admin.query.filter_by(admin_name=username).first() or manager.query.filter_by(manager_name=username).first())

#         if existing_username:
#             return jsonify({"message": "Already exists"}), 400

#         hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
#         if role== 'admin':
#             new_user= admin(admin_name= username, password= hashed_password)

#         if role== 'user':
#             new_user = User(username=username, password=hashed_password)
        
#         if role== 'manager':
#             new_user = manager(manager_name=username, password=hashed_password)

#         db.session.add(new_user)
#         db.session.commit()

#         return jsonify({"message": "register successful"}), 201
    
#     else:
#         return jsonify({'msg': 'You do not have permission to access this route'}), 403

@app.route('/view', methods=['GET'])
def view():
    role= request.json.get('role')
    id = request.json.get('id')
    person= []
    if role == 'manager':
        users = User.query.filter_by(manager_id=id).all()
        for user in users:
            person.append({'id': user.id, 'username': user.username, 'password': user.password})
    
        return jsonify(person)
    
    # if role == 'employee':
    #     record = db.session.query(User).join(manager, User.manager_id == manager.id)
    #     return jsonify({"employee_username": record.username, "manager_id": record.manager_id, "manager_name": record.manager_name})
    if role == 'employee':
        record = db.session.query(User.username, User.manager_id, admin.admin_name.label('manager_name')) \
                .join(admin, User.manager_id == admin.id) \
                .filter(User.id == id).first()
        if record:
            result = {"employee_username": record.username, "manager_id": record.manager_id, "manager_name": record.manager_name}
            return jsonify(result)
        else:
            return jsonify({"message": "User not found"})


@app.route('/admin-only/<int:user_id>', methods=['PATCH', 'DELETE'])
@jwt_required()
def admin_only(user_id):
    current_user_id = get_jwt_identity()
    # adminx = admin.get(current_user)
    adminx = admin.query.filter_by(id=current_user_id).first()
    if adminx:
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
            return jsonify({"message": "deleted successfully"})

    else:
        return jsonify({'msg': 'You do not have permission to access this route'}), 403

@app.route('/adminaccess-only', methods=['PATCH'])
@jwt_required()
def adminaccess_only():
    current_user_id = get_jwt_identity()
    # adminx = admin.get(current_user)
    adminx = admin.query.filter_by(id=current_user_id).first()
    if adminx:
        user_id= request.json.get("emp_id", None)
        manager_id= request.json.get("mentor_id", None)
    
        # user = User.query.get(user_id)
        # managerr = manager.query.get(manager_id)
        user = User.query.filter_by(id=user_id).first()
        managerr= manager.query.filter_by(id=manager_id).first()

        if (not user or not managerr):
            return jsonify({"message": "User or manager not found"}), 404
    
        if managerr:
            user.manager_id= manager_id
            db.session.commit()
            return jsonify({"message": "User updated successfully"}), 200
        
        else :
            return jsonify({"message": "enter valid manager_id"})

    else:
        return jsonify({'msg': 'You do not have permission to access this route'}), 403

@app.route('/admin_change_role', methods=['PATCH'])
@jwt_required()
def admin_change_role():
    current_user_id = get_jwt_identity()
    # adminx = admin.get(current_user)
    adminx = admin.query.filter_by(id=current_user_id).first()
    if adminx:
        user_id= request.json.get("user_id", None)
        current_role= request.json.get("current_role", None)
        role_change= request.json.get("role_change", None)

    
        # user = User.query.get(user_id)
        # managerr = manager.query.get(manager_id)
        if(current_role== 'employee'):
            user = User.query.filter_by(id=user_id).first()
            if user is not None:
                user_copy = User(username=user.username, password=user.password)
                db.session.delete(user)
                if role_change== 'admin':
                    changed_user = admin(admin_name = user_copy.username , password= user_copy.password)
                    db.session.add(changed_user)
                    db.session.commit()
                    return jsonify({"message": "role changed to admin"})
                
                else:
                    changed_user = manager(manager_name = user_copy.username , password= user_copy.password)
                    db.session.add(changed_user)
                    db.session.commit()
                    return jsonify({"message": "role changed to manager"})
                
                        
        return jsonify({"message": "admin-rights"})
        
    else:
        return jsonify({'msg': 'You do not have permission to access this route'}), 403




@app.route('/protected' ,methods = ['GET'])
@jwt_required()
def protected():
    return jsonify({'message': 'You are authorized to access this resource.'}), 200

if __name__ == '__main__':
    app.run(debug=True)
