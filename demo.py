from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/test', methods= ['GET', 'POST'])

def test():
    if request.method == "GET":
        return jsonify({"response":  "Get Request Called"})
    elif request.method == "POST":
        name = request.json['name']
        return jsonify({"response": "Hi "+ name})

if __name__ == "__main__":
    app.run(debug= True, port= 9090)