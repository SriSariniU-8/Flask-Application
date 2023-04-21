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
from sqlalchemy.orm import aliased

from flask import Flask, jsonify, request
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy.orm import sessionmaker

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Sr080601@localhost/Database'
app.config['SECRET_KEY'] = 'thisisasecretkey'
app.config['JWT_SECRET_KEY'] = 'super-secret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    email = db.Column(db.String(20), nullable= False, unique= True)
    password = db.Column(db.String(80), nullable=False)
    manager_id = db.Column(db.Integer)
    role_id = db.Column(db.Integer, db.ForeignKey('role.role_id'))

class Role(db.Model):
    role_id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(20), nullable=False, unique=True)

with app.app_context():
    # db.init_app(app)
    db.create_all()
    Session = sessionmaker(bind=db.engine)


@app.route('/')
def home():
    return jsonify({'message': 'Hello, World!'})

@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username or not password:
        return jsonify({"message": "enter username and password"}), 401

    user = (User.query.filter_by(username=username).first())

    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"message": "Invalid username or password"}), 401

    access_token = create_access_token(identity=user.id,expires_delta=timedelta(hours=1))
    return jsonify(access_token=access_token), 200
    return jsonify({"message":"Login successful"})

@app.route('/display_manager', methods = ['GET'])
def display_manager():
    id = request.json.get('id', None)
    user = User.query.filter_by(id=id).first()
    if user:
        session = Session()
        employee = aliased(User)
        manager = aliased(User)
        result = session.query(
        employee.id,
        employee.username,
        employee.manager_id,
        manager.username.label('ManagerName')
    ).join(
        manager,
        employee.manager_id == manager.id
    ).filter(
        employee.id == id
    ).all()
        session.close()
        data = []
        for row in result:
            d = {'id': row[0], 'username': row[1], 'manager_id': row[2], 'manager_name': row[3]}
            data.append(d)
        
        return jsonify(data)

    else:
        return jsonify({"message": "enter valid userid"})



@app.route('/search', methods=['GET'])
def search():
    search_by= request.json.get('search_by')
    name= request.json.get('name', None)
    role= request.json.get('role', None)
    if(search_by== 'name'):
        person = []
        users = User.query.filter_by(username=name).all()
        for user in users:
            person.append({'id': user.id, 'username': user.username, 'email': user.email, 'role_id': user.role_id, 'manager_id': user.manager_id})
        return person

    elif search_by == 'role':
        persons = []
        if role == 'employee':
            users = User.query.all()
            for user in users:
                if (user.role_id== 0):
                    persons.append({'id': user.id, 'username': user.username, 'password': user.password})

        elif role == 'admin':
            users = User.query.all()
            for Admin in users:
                if (Admin.role_id == 2):
                    persons.append({'id': Admin.id, 'admin_name': Admin.username, 'email': Admin.email})

        elif role == 'manager':
            users = User.query.all()
            for Manager in users:
                if Manager.role_id == 1:
                    persons.append({'id': Manager.id, 'manager_name': Manager.username, 'email': Manager.email})

        return jsonify(persons)

    return jsonify({'message': 'Invalid search_by parameter'}), 400


    #     return jsonify({"id": person[0], "name": person[1], "password": person[2]})
    # print(user)


    # elif search_by == 'role':


    # return jsonify({"username": user.username, "password": user.password})

@app.route('/register', methods=['POST'])
@jwt_required()
def register():
    current_user_id = get_jwt_identity()
    user = User.query.filter_by(id=current_user_id).first()
    if(user.role_id == 2):

        username = request.json.get('username', None)
        password = request.json.get('password', None)
        role= request.json.get('role', None)
        email = request.json.get('email', None)

        if len(username) > 10:
            return jsonify({"message": "username too long"}), 400

        password_regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[a-zA-Z\d]{8,}$"
        if not re.match(password_regex, password):
            return jsonify({"message": "Password should be minimum eight characters, at least one uppercase letter, one lowercase letter and one number"}), 400

        # existing_username = User.query.filter_by(username=username).first() 
        # if existing_username:
        #     return jsonify({"message": "Already exists"}), 400

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        if(role <4 ):
            new_user= User(username= username, password= hashed_password, role_id = role, email= email)
            db.session.add(new_user)
            db.session.commit()
            return jsonify({"message": "register successful"}), 201
        
        else:
            return jsonify({"message": "Enter valid role"})

    else:
        return jsonify({'msg': 'You do not have permission to access this route'}), 403

@app.route('/view', methods=['GET'])
def view():
    id = request.json.get('id')
    user = User.query.filter_by(id=id).first()

    if (user):
        return jsonify({"id": user.id, "username": user.username, "email": user.email})
    else:
        return jsonify({"message": "User not found"})

@app.route('/display', methods=['GET'])
def display():
    persons = []
    id = request.json.get('id')
    person = User.query.filter_by(id=id).first()
    if (person.role_id == 1):
        # manager = Manager.query.filter_by(manager_name= user.username).first()
        users = User.query.filter_by(manager_id=person.id).all()
        for user in users:
            if (user.manager_id == person.id):
                persons.append({"manager_name": person.username,"id":user.id, "username": user.username, "email": user.email})
                
        return jsonify(persons)

    if person.role_id == 0:
        result = {"employee_username": person.username,"email": person.email, "manager_id": person.manager_id}
        return jsonify(result)
    else:
        return jsonify({"message": "User not found"})


@app.route('/admin-only/<int:user_id>', methods=['PATCH', 'DELETE'])
@jwt_required()
def admin_only(user_id):
    current_user_id = get_jwt_identity()
    user = User.query.filter_by(id=current_user_id).first()
    if (user.role_id == 2):
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
    user = User.query.filter_by(id=current_user_id).first()
    if (user.role_id == 2):
        user_id= request.json.get("emp_id", None)
        manager_id= request.json.get("mentor_id", None)
    
        user = User.query.filter_by(id=user_id).first()
        manager= User.query.filter_by(id=manager_id).first()

        
        if (not user or not manager):
            return jsonify({"message": "User or manager not found"}), 404
    
        if manager.role_id== 1 :
            user.manager_id= manager.id
            db.session.commit()
            return jsonify({"message": "Manager assigned to User successfully"}), 200
        
        else :
            return jsonify({"message": "enter valid manager_id"})

    else:
        return jsonify({'msg': 'You do not have permission to access this route'}), 403

@app.route('/admin_change_role', methods=['PATCH'])
@jwt_required()
def admin_change_role():
    current_user_id = get_jwt_identity()
    admin = User.query.filter_by(id=current_user_id).first()
    if (admin.role_id == 2):
        user_id= request.json.get("user_id", None)
        current_role= request.json.get("current_role", None)
        role_change= request.json.get("role_change", None)
        if(current_role== 'Employee'):
            user = User.query.filter_by(id=user_id).first()
            if user is not None:
                if role_change== 'Manager':
                    user.role_id = 1
                    db.session.commit()
                    return jsonify({"message": "role changed to Manager"})
                
        return jsonify({"message": "admin-rights"})
        
    else:
        return jsonify({'msg': 'You do not have permission to access this route'}), 403

@app.route('/protected' ,methods = ['GET'])
@jwt_required()
def protected():
    return jsonify({'message': 'You are authorized to access this resource.'}), 200

if __name__ == '__main__':
    app.run(debug=True)
