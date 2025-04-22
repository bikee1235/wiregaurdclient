from flask import Flask
from routes.health import health_check

app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health():
    return health_check()

if __name__ == '__main__':
    app.run(debug=True)