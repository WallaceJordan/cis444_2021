from flask import request, g
import jwt
from flask_json import FlaskJSON, JsonError, json_response, as_json
from tools.token_tools import create_token
from db_con import get_db_instance, get_db

from tools.logging import logger
import datetime
import bcrypt
global_db_con = get_db()

def handle_request():
    logger.debug("Buy Book Handle Request")
    cur = global_db_con.cursor()
    print(data_to_send)
    #print(request.form['booklist'])
    #decodedJWT = jwt.decode(request.form["jwt"], g.secrets['JWT'],  algorithm="HS256")
    #print(decodedJWT)
    return json_response(data={"message":"Book purchased successfully!"}, status=200)
