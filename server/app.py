#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User

from werkzeug.security import generate_password_hash, check_password_hash

class ClearSession(Resource):

    def delete(self):
    
        session['page_views'] = None
        session['user_id'] = None

        return {}, 204

class Signup(Resource):
    
    def post(self):
        json = request.get_json()
        hashed_password = generate_password_hash(json['password'], method='sha256')
        user = User(
            username=json['username'],
            password_hash=hashed_password
        )
        db.session.add(user)
        db.session.commit()
        
        
        session['user_id'] = user.id

        return user.to_dict(), 201

class CheckSession(Resource):

    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.filter_by(id=user_id).first()
            if user:
                return user.to_dict(), 200
        return {}, 204

class Login(Resource):

    def post(self):
        json = request.get_json()
        user = User.query.filter_by(username=json['username']).first()
        if user and check_password_hash(user.password_hash, json['password']):
            session['user_id'] = user.id
            return user.to_dict(), 200
        return {"message": "Invalid credentials"}, 401

class Logout(Resource):

    def delete(self):
        session.pop('user_id', None)
        return {}, 20

api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
if __name__ == '__main__':
    app.run(port=5555, debug=True)
