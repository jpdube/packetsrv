from flask import Flask, jsonify, request

from dbase.dbengine import DBEngine

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
        except(SyntaxError):
            return jsonify({"error": "Synatx error in pql"})


def start():
    app.run(host="0.0.0.0", port=8080)
