import logging
from datetime import timedelta

from config.config import Config
from config.config_db import ConfigDB
from dbase.dbengine import DBEngine
from flask import Flask, g, jsonify, request, session

log = logging.getLogger("packetdb")

app = Flask(__name__)
app.secret_key = "aaabbbcccddd"


@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(seconds=20)
    session.modified = True


@app.route('/pql', methods=['POST'])
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
