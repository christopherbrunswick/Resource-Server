from flask import Flask, jsonify, request
from flask_cors import flask_cors

app = Flask(__name__)
CORS(app)

# load the trained model

@app.route('/predict', methods=['POST'])
def process_data():
    if request.is_json:
        cleansed_data = request.get_json()
        print(f"Received data from Express: {cleansed_data}")
        # pass data from js to python function
        return jsonify({ "message": "Data received successfully", "process_data": cleansed_data}), 200
    else:
        return jsonify({"error": "Not a json request"}), 400

def entity_resolution(data=cleansed_data):



if __name__ == '__main__':
    app.run(port=5000)