import datetime
import functools
import logging
from datetime import timedelta

# import jwt
from config.config import Config
from config.config_db import ConfigDB, User
from dbase.dbengine import DBEngine
from flask import Flask, jsonify, request, session
from flask_bcrypt import bcrypt
from flask_cors import CORS
from flask_jwt_extended import (JWTManager, create_access_token,
                                get_jwt_identity, jwt_required)

# from functools import wraps


Config.load()
log = logging.getLogger("packetdb")

app = Flask(__name__)
app.config["SECRET_KEY"] = Config.api_secret_key()
app.config["JWT_SECRET_KEY"] = Config.api_jwt_secrete_key()
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(
    minutes=Config.api_jwt_token_expires())

cors = CORS(app)
jwt = JWTManager(app)


def is_valid(api_key: str) -> bool:
    print(f"API key is: {api_key}")
    return api_key == "X-RjqgnPkdM%xQjxLi-Yk8%u"


def api_required(func):
    @functools.wraps(func)
    def decorator(*args, **kwargs):
        api_key = request.headers.get("ApiKey")
        if api_key is None:
            return {"massage": "Please provide an API key"}
        if is_valid(api_key):
            return func(*args, **kwargs)
        else:
            return {"message": "The provided API key is not valid"}, 403
    return decorator


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(seconds=20)
    session.modified = True


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"msg": "Online"})


@app.route("/login", methods=["POST"])
def login():
    if request.json is None:
        log.info("Error login user")
        return jsonify({"error": "Unable to login"})

    username = request.json.get("username", "")
    password = request.json.get("password", "")

    user = User()
    if user.get(username) and bcrypt.checkpw(password.encode("utf-8"), user.password.encode('utf-8')):
        token = create_access_token(identity=username)
        return jsonify({"token": token})
    else:
        return jsonify({"error": "Bad username or password"})


@app.route('/query', methods=['POST'])
@api_required
# @jwt_required()
def query():
    pql = request.get_json()
    if pql is not None:
        log.debug(f"Got PQL <----- {pql}")
        try:
            db = DBEngine()
            result = db.exec(pql["query"])
            return jsonify(result)
            # return jsonify({"result": result})
        except (SyntaxError):
            return jsonify({"error": "Synatx error in pql"})


@app.route('/node', methods=['GET'])
@jwt_required()
def node():
    try:
        configdb = ConfigDB()
        return jsonify({"result": configdb.node_info})
    except (SyntaxError):
        return jsonify({"error": "Node config not found"})


def start():
    app.run(host="0.0.0.0", port=8443, debug=False)
    # , ssl_context=(
    #     "./dev_certs/cert.pem", "./dev_certs/key.pem"))
