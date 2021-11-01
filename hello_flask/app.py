from flask import Flask,render_template,request
from flask_json import FlaskJSON, JsonError, json_response, as_json, jsonify
import jwt

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
    print("hi")
    cur = global_db_con.cursor()
    try:
        cur.execute("select username, password from users where username = '" + request.form["username"] + "';")
    except:
        return json_response(data={"message":"Error while reading from database."}, status=500)

    row =cur.fetchone()
    print(row)

    if row is None:
        print("Username '" + request.form["username"] + "' does not exist.")
        return json_response(data={"message":("Username '" + request.form["username"] + "' does not exist.")}, status=404)
    else:
        print("made it to bcrypt")
        salted = bcrypt.hashpw(bytes(request.form["password"],  'utf-8' ) , bcrypt.gensalt(12))
        print(salted)
        print(bcrypt.checkpw(bytes(row[1], "utf-8"), salted))
        if bcrypt.checkpw(bytes(row[1], "utf-8"), salted):
            print(f"'{row[0]}' has logged in.")
            global JWT_Token
            JWT_Token = jwt.encode(
                    {"username": row[0]}, JWT_SECRET, algorithm="HS256")
            return json_response(data={"jwt": JWT_Token})
        else:
            print("Incorrect password.")
            return json_response(data={"message":"Incorrect password."}, status=404)


#@app.route('/login', methods=['POST']) #endpoint
#def login():
#    user_name = request.form['username']
#    print(f"username: {user_name}")
#    password = request.form['password']
#    print(f"password: {password}")
#    cur = global_db_con.cursor()
#    cur.execute(f"select * from users where username = '{user_name}';")
#    namecheck = cur.fetchall()
#    print(namecheck)
#    dbpw = namecheck[0][2]
#    salted = bcrypt.hashpw( bytes(password,  'utf-8' ) , bcrypt.gensalt(12))
#    print(bcrypt.checkpw(bytes(dbpw,'utf-8'), salted ))
    #print(salted)
    #print(namecheck)
#    JWT_Token = jwt.encode({"username" : user_name, "password" : password} , JWT_SECRET, algorithm="HS256")
#    print(jwt.decode(JWT_Token, JWT_SECRET, algorithms=["HS256"]))
#    return json_response(jwt=JWT_Token)
    #return json_response(data=request.form)
@app.route("/logout") #endpoint
def logout():
    global JWT_Token
    JWT_Token = None
    print("Logged out.")
    return json_response(data={"message": "Logged out."})

@app.route('/buy') #endpoint
def buy():
    return 'Buy'

@app.route('/hello') #endpoint
def hello():
    return render_template('hello.html',img_url=IMGS_URL[CUR_ENV] ) 

@app.route('/back',  methods=['GET']) #endpoint
def back():
    return render_template('backatu.html',input_from_browser=request.args.get('usay', default = "nothing", type = str) )

@app.route('/backp',  methods=['POST']) #endpoint
def backp():
    print(request.form)
    salted = bcrypt.hashpw( bytes(request.form['fname'],  'utf-8' ) , bcrypt.gensalt(10))
    print(salted)

    print(  bcrypt.checkpw(  bytes(request.form['fname'],  'utf-8' )  , salted ))

    return render_template('backatu.html',input_from_browser= str(request.form) )

@app.route('/auth',  methods=['POST']) #endpoint
def auth():
        print(request.form)
        return json_response(data=request.form)

@app.route('/signup', methods=['POST']) #endpoint
def signup():
    user_name = request.form['username']
    password = request.form['password']
    cur = global_db_con.cursor()
    cur.execute(f"select * from users where userID = '{user_name}';")
    namecheck = cur.fetchone()
    if nameCheck == None:
        salted = bcrypt.hashpw(bytes(request.form['password'], 'utf-8'), bcrypt.gensalt(12))
        decryptSalt = salted.decode('utf-8')
        print(decryptSalt)
        cut.execute(f"insert into users (username, password) values ('{user_name}', '{decryptSalt}');")
        global_db_con.commit()
        token = JWT_Token(user_name)
        return jsonify(token)
    else:
        print("username already exists")
        return make_response(
                'Username already exists',
                401,
                {'WWW-Authenticate' : 'Basic realm ="User does not exist!"'})


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

