import json
from flask import Flask, abort, request
from flask_cors import CORS

from util import (
    authorize,
    authorize_exch,
    validate_access_token,
    get_token_from_header,
    check_auth_user,
    exchange_token
)

app = Flask(__name__)
CORS(app)

# Case #1
@app.route('/api/v2/rcs/rdo/unlock', methods=['POST'])
@authorize()
def unlock(claims={}):
    data = json.loads(request.data)
    token = get_token_from_header()
    try:
        validate_access_token(token, [], data['userName'])
    except:
        abort(401)
    return json.dumps({
        'vin': data['vin'],
        'status': 'unlocked'
    })

# Case #2
@app.route('/ha/exchangeToken', methods=['POST'])
def get_token(claims={}):
    req = json.loads(request.data)
    token = exchange_token(req)
    data = {
        'access_token': token,
        'token_type': 'Bearer',
        'Expires_in': 300,
    }
    return json.dumps(data)


@app.route('/m/remote/accounts/<vin>/remote-start', methods=['POST'])
@authorize_exch()
def start(vin, claims={}):
    data = {
        'status': 'SUCCESS',
        'command': 'START',
        'vin': vin,
        'serviceType': 'REMOTE_START_CAR',
        'timeStamp': '',
        'location': {
            'lat': '',
            'lng': '',
        }
	}
    return json.dumps(data)


# Case #3
@app.route('/api/v1/auth', methods=['POST'])
def auth(claims={}):
    data = json.loads(request.data)
    user = check_auth_user(data['username'], data['password'])
    if not user:
        abort(401)
    return json.dumps({'status': 'SUCCESS'})


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 8080)))
