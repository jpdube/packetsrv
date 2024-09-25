import datetime
import logging
from datetime import timedelta
from functools import wraps

import jwt
from config.config import Config
from config.config_db import ConfigDB, User
from dbase.dbengine import DBEngine
from flask import Flask, jsonify, request, session
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_bcrypt import bcrypt
import datetime

log = logging.getLogger("packetdb")

app = Flask(__name__)
app.config["SECRET_KEY"] = "01234567890abcdefgh"
# app.secret_key = "aaabbbcccddd"
app.config["JWT_SECRET_KEY"] = "Jq@QA^9xA&yo%YG@J&DW38$GoWiw+z*&"
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(minutes=480)

jwt = JWTManager(app)


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(seconds=20)
    session.modified = True


@app.route("/login", methods=["POST"])
def login():
    if request.json is None:
        log.info("Error login user")
        return jsonify({"error": "Unable to login"})

    username = request.json.get("username", "")
    password = request.json.get("password", "")
    user = User()
    user.get(username)
    print(user)

    if username == "jpdube" and bcrypt.checkpw(password.encode("utf-8"), user.password.encode('utf-8')):
        token = create_access_token(identity=username)
        return jsonify({"token": token})
    else:
        return jsonify({"error": "Bad username or password"})


@app.route('/pql', methods=['POST'])
@jwt_required()
def query():
    pql = request.get_json()
    if pql is not None:
        log.debug(f"Got PQL <----- {pql}")
        try:
            db = DBEngine()
            result = db.run(pql["query"])
            return jsonify(result)
            # return jsonify({"result": result})
        except (SyntaxError):
            return jsonify({"error": "Synatx error in pql"})


@app.route('/node', methods=['GET'])
def node():
    try:
        configdb = ConfigDB()
        return jsonify({"result": configdb.node_info})
    except (SyntaxError):
        return jsonify({"error": "Node config not found"})


def start():
    app.run(host="0.0.0.0", port=8443, debug=False, ssl_context=(
        "./dev_certs/cert.pem", "./dev_certs/key.pem"))
