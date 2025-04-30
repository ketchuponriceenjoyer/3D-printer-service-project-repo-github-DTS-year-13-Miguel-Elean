from flask import Flask, render_template, request, redirect, send_file, session
import sqlite3, io
from sqlite3 import Error
from flask_bcrypt import Bcrypt
from flask import Response

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "testingkey"
#connects database to python into a variable
DATABASE = 'database'

def connect_database(db_file):
    """
    Connects to the database and sends error message if database cannot be connected for some reason
    :param db_file:
    :return:
    """
    try:
        connection = sqlite3.connect(db_file)
        return connection
    except Error as e:
        print(e)
        print(f'an error when connecting to database')
    return
@app.route('/')
def render_homepage():
    return render_template('Home.html')

@app.route('/Session', methods=['POST', 'GET'])
def render_Sessionpage():
    if request.method == 'POST':
        #grabs submitted information from the html

        Filament = request.form.get('Filament')
        Size = request.form.get('Size')
        Model = request.files.get('Model_File')
        user_id = session.get("user_id")

        if user_id is None:
            print("user id is None")

        print(session)

        #converts model for the code to read the 3D data information
        file_data = Model.read()

        #inserts all information submitted to database while database is called out. Model.filename
        # only grabs the name of the file and puts it in the database as a seperate colomun for file names
        con = connect_database(DATABASE)
        cur = con.cursor()
        query_insert = "INSERT INTO session (filament, size, file_data, file_name, fk_user_id) VALUES (?, ?, ?, ?, ?)"
        cur.execute(query_insert, (Filament, Size, file_data, Model.filename, user_id))
        con.commit()
        con.close()

    return render_template('Session.html')



@app.route('/images')
def render_imagespage():
    #image gallery coming soon
    return render_template('images.html')
@app.route('/Login', methods=['POST', 'GET'])
def render_loginpage():
    if request.method == 'POST':
        #grabs information submitted
        Name = request.form.get('Name')
        email = request.form.get('Email')
        password = request.form.get('password')

        #selects the user id username and password from the specific email to only grab one user

        check_query = "SELECT user_id, username, password FROM users WHERE email = ?"
        con = connect_database(DATABASE)
        cur = con.cursor()
        cur.execute(check_query, (email,))
        user_info = cur.fetchone() 
        cur.close()
        # code that does the security check
        print(user_info)
        try:
            #gets the user information from the check query
            user_id = user_info[0]
            username = user_info[1]
            user_password = user_info[2]

        except IndexError:
            #if check doesnt work print this out
            print("index error")
            return redirect("/Login?error=email+or+password+invalid")
        if not bcrypt.check_password_hash(user_password, password):
            #checks password submitted and password in the database matches
            print("passwords do not match")
            return redirect("/Login?error=email+or+password+invalid")

        # holds the user information in the website while user is logged in
        session['email'] = email
        session['user_id'] = user_id
        session['username'] = username
        print(session)
        print("log in successful")
        print("logged in as ", session['username'])

        return redirect("/")

    return render_template('Login.html')

@app.route('/Signin', methods=['POST', 'GET'])
def render_signinpage():
    if request.method == 'POST':
        #gets information submitted
        Name = request.form.get('Name')
        Address = request.form.get('Address')
        Email = request.form.get('Email')
        password = request.form.get('Password')
        re_Password = request.form.get('Re_Password')

        #converts password submitted into bcrypt layout for better security purposes
        hashed_password = bcrypt.generate_password_hash(password)
        #checks if password is 8 digits long and re password matches password
        if password != re_Password:
            return redirect("/Signin?error=password+invalid")
        if len(password) < 8:
            return redirect("/Signin?error=password+invalid")
        #grabs submitted information and place it into the database
        con = connect_database(DATABASE)
        cur = con.cursor()
        query_insert = "INSERT INTO users (username, address, email, password) VALUES (?, ?, ?, ?)"
        cur.execute(query_insert, (Name, Address, Email, hashed_password))
        con.commit()
        con.close()
        return redirect("/Login")
    return render_template('signin.html')



if __name__ == '__main__':
    app.run()