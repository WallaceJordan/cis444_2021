from flask import Flask,render_template,request
from flask_json import FlaskJSON, JsonError, json_response, as_json
import jwt

import datetime
import bcrypt


from db_con import get_db_instance, get_db

app = Flask(__name__)
FlaskJSON(app)

USER_PASSWORDS = { "cjardin": "strong password"}

IMGS_URL = {
            "DEV" : "/static",
            "INT" : "https://cis-444-fall-2021.s3.us-west-2.amazonaws.com/images",
            "PRD" : "http://d2cbuxq67vowa3.cloudfront.net/images"
            }

CUR_ENV = "PRD"
JWT_SECRET = None

global_db_con = get_db()


with open("secret", "r") as f:
    JWT_SECRET = f.read()

@app.route('/') #endpoint
def index():
    return 'Web App with Python Caprice!' + USER_PASSWORDS['cjardin']

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
    namecheck = cut.fetchone()
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
    global_db_con.commit()
    return json_response(status="good")


app.run(host='0.0.0.0', port=80)

