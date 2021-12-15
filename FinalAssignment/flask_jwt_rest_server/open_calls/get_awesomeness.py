from flask import request, g
from flask_json import FlaskJSON, JsonError, json_response, as_json
from tools.token_tools import create_token
from db_con import get_db_instance, get_db

from tools.logging import logger
global_db_con = get_db()

def handle_request():
    logger.debug("Get Awesomeness Handle Request")
    cur = global_db_con.cursor()
    hunklist = {}
    try:
        cur.execute("select first_name, last_name, gender, date_of_birth, height, hair_color, eye_color from dylan;")
        print('executed cur.execute')
    except:
        return json_response(data={"message": "Error occured while reading from database."}, status=500)
    count = 0
    while 1:
        row = cur.fetchone()
        if row is None:
            break
        else:
            if count > 0:
                print("")
            hunklist[count] = row[0], row[1], row[2], row[3], row[4], row[5], row[6]
            count += 1
    print(hunklist)
    user = {
            "sub" : 'girl'
            }
    print("Valid user. Sending list of awesomeness.")

    return json_response( token = create_token( user ) , awesomeness = hunklist )
