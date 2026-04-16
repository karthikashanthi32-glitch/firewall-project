from flask import Flask, jsonify, render_template
import json
import os

app = Flask(__name__)

LOG_FILE = "alerts.json"

# Route for dashboard UI
@app.route("/")
def index():
    return """
    <html>
    <head>
        <title>Firewall Dashboard</title>
        <script>
            async function loadData() {
                let res = await fetch('/data');
                let data = await res.json();

                let table = document.getElementById("table");
                table.innerHTML = "";

                data.forEach(item => {
                    let row = `<tr>
                        <td>${item.ip}</td>
                        <td>${item.attack}</td>
                        <td>${item.score}</td>
                    </tr>`;
                    table.innerHTML += row;
                });
            }

            setInterval(loadData, 3000);
            window.onload = loadData;
        </script>
    </head>

    <body>
        <h2>🔥 Adaptive Firewall Dashboard</h2>
        <table border="1">
            <thead>
                <tr>
                    <th>IP</th>
                    <th>Attack</th>
                    <th>Score</th>
                </tr>
            </thead>
            <tbody id="table"></tbody>
        </table>
    </body>
    </html>
    """

# API to send JSON data
@app.route("/data")
def data():
    if not os.path.exists(LOG_FILE):
        return jsonify([])

    with open(LOG_FILE, "r") as f:
        try:
            data = json.load(f)
        except:
            data = []

    return jsonify(data)


if __name__ == "__main__":
    app.run(host="0.0.0.0",port=5000,debug=True)