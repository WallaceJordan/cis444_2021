import bcrypt

nonsalt = input()
password_to_salt = nonsalt
salted = bcrypt.hashpw( bytes(password_to_salt,  'utf-8' ) , bcrypt.gensalt(10))
decoded = salted.decode('utf-8')
print(salted)
print(decoded)

