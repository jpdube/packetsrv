from dbase.dbengine import DBEngine
from flask import Flask, jsonify, request
from config.config_db import ConfigDB
from config.config import Config

app = Flask(__name__)


@app.route('/pql', methods=['POST'])
def query():
    pql = request.get_json()
    if pql is not None:
        print(f"Got PQL <----- {pql}")
        try:
            db = DBEngine()
            result = db.run(pql["query"])
            return jsonify({"result": result})
        except (SyntaxError):
            return jsonify({"error": "Synatx error in pql"})


@app.route('/node', methods=['GET'])
def node():
    try:
        configdb = ConfigDB()
        # configdb.load()
        return jsonify({"result": configdb.node_info})
    except (SyntaxError):
        return jsonify({"error": "Node config not found"})


def start():
    app.run(host="0.0.0.0", port=8080, debug=False)
