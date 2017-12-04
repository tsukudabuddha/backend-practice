from flask import Flask, request, jsonify, make_response
import json
import pdb
from bson import Binary, Code
from bson.json_util import dumps
from util import JSONEncoder
from pymongo import MongoClient
from flask_restful import Api, Resource
import bcrypt
import loginInfo


app = Flask(__name__)
api = Api(app)

# https://github.com/mongolab/mongodb-driver-examples/blob/master/python/pymongo_simple_example.py
mongo = MongoClient('mongodb://travel-pro-server:tiger5000@ds129796.mlab.com:29796/travel_pro')
app.bcrypt_rounds = 12
app.db = mongo.travel_pro
auth_info = loginInfo.loginInfo()
auth_user = auth_info[0]
auth_password = auth_info[1]
app.db.authenticate(auth_user, auth_password)


def validate_auth(username, password):
    """Validate user authentication."""
    user_collection = app.db.users
    user = user_collection.find_one({'username': username})

    if user is None:
        return False
    else:
        # check if the hash we generate based on auth matches stored hash
        encodedPW = password.encode('utf-8')  # PW = Password
        return bcrypt.checkpw(encodedPW, user['password'])


def authenticated_request(func):
    """Wrap or something."""
    def wrapper(*args, **kwargs):
        auth = request.authorization

        if not auth or not validate_auth(auth.username, auth.password):
            return ({'error': 'Basic Auth Required.'}, 401, None)

        return func(*args, **kwargs)

    return wrapper


class User(Resource):
    """User routing w/ flask_restful."""

    def post(self):
        """Add user to database."""
        new_user = request.json
        users_collection = app.db.users

        # Check for duplicate user
        username = new_user['username']
        duplicate = users_collection.find_one({'username': username})
        if not duplicate:
            password = new_user['password']

            # Convert password to utf-8 string
            encodedPassword = password.encode('utf-8')

            hashed = bcrypt.hashpw(
                encodedPassword, bcrypt.gensalt(app.bcrypt_rounds)
            )

            new_user['password'] = hashed
            users_collection.insert_one(new_user)

            return new_user

        return("That username is already taken", 409, None)

    @authenticated_request
    def get(self):
        """Get user(s)."""
        username = request.authorization.username
        users_collection = app.db.users
        user = users_collection.find_one({'username': username})
        return user

    @authenticated_request
    def patch(self):
        """Update user."""
        username = request.authorization.username
        new_user = request.json["new_username"]
        users_collection = app.db.users
        user = users_collection.find_one_and_update(
            {"user": username},
            {"$set": {"user": new_user}},
            # return_document=ReturnDocument.AFTER
        )

        return user

    @authenticated_request
    def delete(self):
        """Delete user from db."""
        username = request.authorization.username
        self.users_collection.remove({'user': username})
        return ('user has been deleted', 200, None)


api.add_resource(User, '/users')


class Trip(Resource):
    """Trip routing w/ flask_restful."""

    @authenticated_request
    def post(self):
        """Add trip to database."""
        new_trip = request.json
        new_trip['travelers'] = [request.authorization.username]
        trips_collection = app.db.trips

        result = trips_collection.insert_one(new_trip)

        return result

    @authenticated_request
    def get(self):
        """Get trip(s) for authorized user."""
        trips_collection = app.db.trips
        username = request.authorization.username
        trips = trips_collection.find({"travelers": username})
        all_trips = []
        if trips:
            for trip in trips:
                all_trips.append(trip)
            return (all_trips, 200, None)
        else:
            return("user not found", 404, None)

    @authenticated_request
    def delete(self):
        """Delete trip from db."""
        trip_id = request.json['trip_id']
        self.trips_collection.remove({'trip': trip_id})
        return ('user has been deleted', 200, None)

    @authenticated_request
    def patch(self):
        """Update trip."""
        username = request.authorization.username
        updated_trip = request.json
        trips_collection = app.db.trips
        trip = trips_collection.find_one_and_update(
            {"id": username},
            {"$set": updated_trip},
            # return_document=ReturnDocument.AFTER
        )

        return trip


api.add_resource(Trip, '/trips')


@api.representation('application/json')  # custom JSON serializer
def output_json(data, code, headers=None):
    """Serialize output JSON Data."""
    if type(data) is dict:
        if data['password']:
            data['password'] = data['password'].decode('utf-8')
    resp = make_response(JSONEncoder().encode(data), code)
    resp.headers.extend(headers or {})
    return resp


if __name__ == '__main__':
    # Turn this on in debug mode to get detailled information about request
    # related exceptions: http://flask.pocoo.org/docs/0.10/config/
    app.config['TRAP_BAD_REQUEST_ERRORS'] = True
    app.run(debug=True)
