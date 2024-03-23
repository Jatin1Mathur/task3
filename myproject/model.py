from flask_sqlalchemy import SQLAlchemy
import sqlalchemy 
db = SQLAlchemy()
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100),  nullable=False)
    password = db.Column(db.String(100), nullable=False)