from flask import Flask, request
import json
import pdb
from bson import Binary, Code
from bson.json_util import dumps
from util import JSONEncoder

# 1
from pymongo import MongoClient

app = Flask(__name__)

# 2
mongo = MongoClient('localhost', 27017)

# 3
app.db = mongo.test

@app.route('/users')
def get_users():
    # Our users collection
    user_collection = app.db.users

    # Get URL params
    if request.args.get('name'):
        name = request.args.get('name')
        result = user_collection.find_one(
            {"name": name}
        )
        json_result = JSONEncoder().encode(result)
    else:
        result = user_collection.find()
        json_result = dumps(result)

    return (json_result, 200, None)


@app.route('/courses', methods=['POST'])
def add_course():
    if request.args.get('name') and request.args.get('instructor'):
        course_collection = app.db.courses
        cursor = course_collection.find()
        count = 0
        for item in cursor:
            count += 1
        name = request.args.get('name')
        instructor = request.args.get('instructor')
        entry = {'name': name, 'instructor': instructor,
                 'id': count}
        course_collection.insert_one(entry)
        entry["status"] = "added to database"
        return (entry, 121, None)
    else:
        return (None, 400, None)


@app.route('/courses', methods=['GET'])
def get_course():
    if request.args.get('id'):
        course_collection = app.db.courses
        course_number = request.args.get('id')
        result = course_collection.find_one(
            {'id': str(course_number)}
        )
        print("course num: " + str(course_number))
        json_result = JSONEncoder().encode(result)
        return(json_result, 200, None)
    else:
        return(None, 400, None)


@app.route('/pets')
def get_pets():
    doggo = {"name": "Gigi", "color": "white"}
    pupper = {"name": "Madison", "color": "brown"}
    pets = [doggo, pupper]
    json_pets = json.dumps(pets)
    return json_pets


if __name__ == '__main__':
    app.config["TRAP_BAD_REQUEST_ERRORS"] = True
    app.run(debug=True)  # Makes it so that you don't need to close server
