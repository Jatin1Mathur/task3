from flask import Flask, request, jsonify
from model import db, User
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_ngrok import run_with_ngrok
from flask_bcrypt import Bcrypt

app = Flask(__name__)
run_with_ngrok(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///User.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
db.init_app(app)
jwt = JWTManager(app)
bcrypt = Bcrypt(app)

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    access_token = create_access_token(identity={'username': new_user.username, 'email': new_user.email})
    return jsonify({'access_token': access_token})

@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
    user = User.query.filter_by(username=auth['username']).first()
    if not user:
        return jsonify({'message': 'User not found'})
    if bcrypt.check_password_hash(user.password, auth['password']):
        access_token = create_access_token(identity={'username': user.username, 'email': user.email})
        return jsonify({'access_token': access_token})
    else:
        return jsonify({'message': 'Invalid credentials'})

@app.route('/delete', methods=['DELETE'])
@jwt_required() 
def delete_user():
    current_username = get_jwt_identity()
    data = request.get_json()
    username = data.get('username')
    if not username:
        return jsonify({'error': 'Username is required'})
    user = User.query.filter_by(username=username).first()
    if user:
        if user.username != current_username: 
            return jsonify({'error': 'Unauthorized'})
        db.session.delete(user)    
        db.session.commit()
        return jsonify({'message': 'User deleted successfully'})
    else:
        return jsonify({'error': 'User not found'})


@app.route('/retrieve', methods=['GET'])
@jwt_required()
def get_user():
    current_user = get_jwt_identity()
    user = User.query.filter_by(username=current_user['username']).first()
    if user:
        return jsonify({'username': user.username, 'email': user.email})
    else:
        return jsonify({'message': 'User not found'})
    

@app.route('/update/<int:id>', methods=['PUT'])
@jwt_required()  
def update_user(id):
    try:
        current_username = get_jwt_identity()
        user = User.query.get(id)
        if user:
            if user.username != current_username:  
                return jsonify({'error': 'Unauthorized'})
            data = request.get_json()
            if 'username' in data:
                user.username = data['username']
            if 'email' in data:
                user.email = data['email']
            db.session.commit()
            return jsonify({'message': 'User updated successfully'})
        return jsonify({'message': 'User not found'}), 404
    except Exception as e:
        return jsonify({'message': 'Error updating user: {str(e)}'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()


