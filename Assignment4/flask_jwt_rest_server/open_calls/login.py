from flask import request, g
from flask_json import FlaskJSON, JsonError, json_response, as_json
from tools.token_tools import create_token
import bcrypt
from tools.logging import logger
from db_con import get_db_instance, get_db

global_db_con = get_db()

def handle_request():
    cur = global_db_con.cursor()
    print("made it to open_calls/login")
    logger.debug("Login Handle Request")
    #use data here to auth the user

    password_from_user_form = request.form['password']
    user = {
            "sub" : request.form['firstname'] #sub is used by pyJwt as the owner of the token
            }
    try: cur.execute("select username, password from users where username = '" + user["sub"] + "';")
    except:
        return json_response(data={"message":"Error while reading from database."}, status=500)
    row = cur.fetchone()
    if row is None:
        print("Username '" + request.form["username"] + "' does not exist.")
        return json_response(data={"message":("Username '" + request.form["username"] + "' does not exist.")}, status=404)
    else:
        # print("made it to bcrypt")
        salted = bcrypt.hashpw(bytes(request.form["password"],  'utf-8' ) , bcrypt.gensalt(12))
        if bcrypt.checkpw(bytes(row[1], "utf-8"), salted):
            print(f"'{row[0]}' has logged in.")
            #global JWT_Token
            #JWT_Token = jwt.encode(
             #       {"username": row[0]}, JWT_SECRET, algorithm="HS256")
            #return json_response(data={"jwt": JWT_Token})
        else:
            print("Incorrect password.")
            return json_response(data={"message":"Incorrect password."}, status=404)

    print(user)
    if not user:
        return json_response(status_=401, message = 'Invalid credentials', authenticated =  False )

    print("exiting open_calls/login")
    return json_response( token = create_token(user) , authenticated = True)

