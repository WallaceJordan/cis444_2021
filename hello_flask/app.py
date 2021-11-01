from flask import Flask,render_template,request
from flask_json import FlaskJSON, JsonError, json_response, as_json, jsonify
import jwt
import json

import datetime
import bcrypt

from db_con import get_db_instance, get_db

app = Flask(__name__)
FlaskJSON(app)

JWT_SECRET = None
JTW_Token = None
global_db_con = get_db()

with open("secret", "r") as f:
    JWT_SECRET = f.read()

def ValidateToken(token):
    # If the token is still None, it hasn't been set. Don't attempt to
    # validate.
    if JWT_Token is None:
        print("No token stored in server.")
        return False
    else:
        fromServer = jwt.decode(JWT_Token, JWT_SECRET, algorithms=["HS256"])
        fromRequest = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])

        if fromServer == fromRequest:
            print("Valid token.")
            return True
        else:
            print("Tokens do not match.")
            return False

@app.route('/') #endpoint
def assignment3():
    return render_template("assignment3.html")

@app.route('/login', methods=["POST"]) #endpoint
def login():
    cur = global_db_con.cursor()
    try:
        cur.execute("select username, password from users where username = '" + request.form["username"] + "';")
    except:
        return json_response(data={"message":"Error while reading from database."}, status=500)

    row =cur.fetchone()
    # print(row)

    if row is None:
        print("Username '" + request.form["username"] + "' does not exist.")
        return json_response(data={"message":("Username '" + request.form["username"] + "' does not exist.")}, status=404)
    else:
        # print("made it to bcrypt")
        salted = bcrypt.hashpw(bytes(request.form["password"],  'utf-8' ) , bcrypt.gensalt(12))
        # print(salted)
        # print(bcrypt.checkpw(bytes(row[1], "utf-8"), salted))
        if bcrypt.checkpw(bytes(row[1], "utf-8"), salted):
            print(f"'{row[0]}' has logged in.")
            global JWT_Token
            JWT_Token = jwt.encode(
                    {"username": row[0]}, JWT_SECRET, algorithm="HS256")
            return json_response(data={"jwt": JWT_Token})
        else:
            print("Incorrect password.")
            return json_response(data={"message":"Incorrect password."}, status=404)

@app.route('/bookList', methods=["POST"]) #endpoint
def bookList():
    if ValidateToken(request.form["jwt"]):
        cur = global_db_con.cursor()
        try:
            cur.execute("select bookname, price from books;")
        except:
            return json_response(data={"message": "Error occured while reading from database."}, status=500)

        count = 0
        message = '{"books":['
        while 1:
            row = cur.fetchone()
            if row is None:
                break
            else:
                if count > 0:
                    message += ","
                message += '{"bookname":"' + row[0] + '","price":"' + str(row[1]) + "\"}"
                count += 1
        message += "]}"

        print("Valid user. Sending list of books.")
        return json_response(data=json.loads(message))
    else:
        print("Invalid token. Sending error message.")
        return json_response(data={"message": "User is not logged in."}, status=404)

@app.route("/purchaseBook", methods=["POST"])
def purchaseBook():
    decodedJWT = jwt.decode( request.form["jwt"], JWT_SECRET, algorithms=["HS256"])
    print(decodedJWT["username"])
    print(str(request.form["book_id"]))
    print(str(datetime.datetime.now()))
    cur = global_db_con.cursor()
    try:
        print("insert into purchases (username, purchase, created_on) values ('" +     str(decodedJWT["username"]) + "','" + str(request.form["book_id"]) + "','" + str(datetime    .datetime.now()) + "'); commit;")
        cur.execute("insert into purchases (username, purchase, created_on) values ('" + str(decodedJWT["username"]) + "','" + str(request.form["book_id"]) + "','" + str(datetime.datetime.now()) + "'); commit;")
        #global_db_con.commit()
        print("Purchase successful!")
        return json_response(data={"message":"Book purchased successfully!"}, status=200)
    except:
        return json_response(data={"message":"Error occured while writing to purchases."}, status=500)

@app.route('/auth',  methods=['POST']) #endpoint
def auth():
        print(request.form)
        return json_response(data=request.form)

#Assigment 2
@app.route('/ss1') #endpoint
def ss1():
    return render_template('server_time.html', server_time= str(datetime.datetime.now()) )

@app.route('/getTime') #endpoint
def get_time():
    return json_response(data={"password" : request.args.get('password'),
                                "class" : "cis44",
                                "serverTime":str(datetime.datetime.now())
                            }
                )

@app.route('/auth2') #endpoint
def auth2():
    jwt_str = jwt.encode({"username" : "cary",
                            "age" : "so young",
                            "books_ordered" : ['f', 'e'] } 
                            , JWT_SECRET, algorithm="HS256")
    #print(request.form['username'])
    return json_response(jwt=jwt_str)

@app.route('/exposejwt') #endpoint
def exposejwt():
    jwt_token = request.args.get('jwt')
    print(jwt_token)
    return json_response(output=jwt.decode(jwt_token, JWT_SECRET, algorithms=["HS256"]))


@app.route('/hellodb') #endpoint
def hellodb():
    cur = global_db_con.cursor()
    cur.execute("select * from users;")
    for r in cur.fetchall():
        print(r)
    return json_response(status="good")


app.run(host='0.0.0.0', port=80)

