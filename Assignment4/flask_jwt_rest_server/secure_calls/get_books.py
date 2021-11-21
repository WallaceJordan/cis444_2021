from flask import request, g
from flask_json import FlaskJSON, JsonError, json_response, as_json
from tools.token_tools import create_token
from db_con import get_db_instance, get_db

from tools.logging import logger
global_db_con = get_db()

def handle_request():
    logger.debug("Get Books Handle Request")
    cur = global_db_con.cursor()
    booklist = {}
    try:
        cur.execute("select bookname, price from books;")
        print('executed cur.execute')
    except:
        return json_response(data={"message": "Error occured while reading from database."}, status=500)
    count = 0
    #message = '{"books":['
    while 1:
        row = cur.fetchone()
        if row is None:
            break
        else:
            if count > 0:
                print("")
            booklist[count] = row[0], str(row[1])
            count += 1
                #message += ","
            #message += '{"bookname":"' + row[0] + '","price":"' + str(row[1]) + "\"}"
    #message += "]}"
    print(booklist)
    #print("List of books: " + message)
    print("Valid user. Sending list of books.")

    return json_response( token = create_token(  g.jwt_data ) , books = booklist )

