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

def user_profile_display():
    username = session.get("username")
    email = session.get("email")
    admin = session.get("admin")
    return (username, email, admin)

@app.route('/logout')
def logout():
    session.clear()
    print(session)
    return redirect("/")

@app.route('/Session', methods=['POST', 'GET'])
def render_Sessionpage():
    user, email, admin = user_profile_display()
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

    return render_template('Session.html', user = user, email = email, admin = admin)


def check_admin(email):
    check_query = "SELECT Admin FROM users WHERE email = ?"
    con = connect_database(DATABASE)
    cur = con.cursor()
    cur.execute(check_query, (email,))
    admin_info = cur.fetchone()
    cur.close()
    admin_ = admin_info[0]
    return admin_


def find_account(email):
    check_query = "SELECT user_id, username, password , email FROM users WHERE email = ?"
    con = connect_database(DATABASE)
    cur = con.cursor()
    cur.execute(check_query, (email,))
    user_info = cur.fetchone()
    cur.close()
    return user_info

@app.route('/Login', methods=['POST', 'GET'])
def render_loginpage():
    user, email, is_admin = user_profile_display()
    if request.method == 'POST':
        #grabs information submitted
        Name = request.form.get('Name')
        email = request.form.get('Email')
        password = request.form.get('password')

        #selects the user id username and password from the specific email to only grab one user

        user_info = find_account(email)
        # code that does the security check
        try:
            #gets the user information from the check query and puts them in separate variables
            user_id = user_info[0]
            username = user_info[1]
            user_password = user_info[2]

            #error activates if try cannot get information from user id indicating the gmail wasn't found
        except TypeError:
            return render_template('signin.html', error="account doesnt exist")

            # checks if username and passwords match if not prints out error message
        if not user_info[1] == Name and not bcrypt.check_password_hash(user_password, password):
            return render_template('Login.html', error="passwords and username do not match")

            # checks if username match if not prints out error message
        if not user_info[1] == Name:
            return render_template('Login.html', error="username do not match")

            # checks if passwords match if not prints out error message
        if not bcrypt.check_password_hash(user_password, password):
            return render_template('Login.html', error="passwords do not match")
        # holds the user information in the website while user is logged in
        session['email'] = email
        session['user_id'] = user_id
        session['username'] = username

        print("log in successful")
        print("logged in as ", session['username'])
        admin_var = check_admin(email)
        if admin_var == True:
            session['admin'] = True
        else:
            session['admin'] = False
        print(session)
        return redirect("/")

    return render_template('Login.html', user = user, email = email, admin=is_admin)

@app.route('/Signin', methods=['POST', 'GET'])
def render_signinpage():
    user, email_display, is_admin = user_profile_display()
    if request.method == 'POST':
        #gets information submitted
        Name = request.form.get('Name')
        Address = request.form.get('Address')
        Email = request.form.get('Email')
        password = request.form.get('Password')
        re_Password = request.form.get('Re_Password')
        check_query = "SELECT username FROM users"
        con = connect_database(DATABASE)
        cur = con.cursor()
        cur.execute(check_query)
        user_name_account = cur.fetchall()
        cur.close()
        print(user_name_account)
        username_list = []
        for x in user_name_account:
            username_list.append(x[0])

        if Name in username_list:
            return render_template('signin.html', error="username already in use")

        user_info = find_account(Email)
        try:
            if user_info[3] == Email:
                return render_template('Login.html', error="Email address already in use", link="/signin")
        except TypeError:
            pass



        #converts password submitted into bcrypt layout for better security purposes
        hashed_password = bcrypt.generate_password_hash(password)
        #checks if password is 8 digits long and re password matches password
        if password != re_Password:
            return render_template('signin.html', error="passwords do not match")
        if len(password) < 8:
            return render_template('signin.html', error="passwords to short")
        #grabs submitted information and place it into the database
        con = connect_database(DATABASE)
        cur = con.cursor()
        query_insert = "INSERT INTO users (username, address, email, password) VALUES (?, ?, ?, ?)"
        cur.execute(query_insert, (Name, Address, Email, hashed_password))
        con.commit()
        con.close()
        return redirect("/Login")
    return render_template('signin.html', user = user, email = email_display, admin=is_admin)

@app.route('/Admin', methods=['POST', 'GET'])
def render_Adminpage():

    con = connect_database(DATABASE)
    cur = con.cursor()
    query = "SELECT session.session_id, users.username, users.address, users.email, session.filament, session.size, session.file_name FROM session JOIN users ON session.fk_user_id = users.user_id"
    cur.execute(query)
    sessions = cur.fetchall()
    cur.close()
    if request.method == 'POST':
        session_id = request.form['session_id']
        con = connect_database(DATABASE)
        cur = con.cursor()
        cur.execute("DELETE FROM session WHERE session_id = ?", (session_id,))
        con.commit()
        cur.close()

    return render_template('Admin.html', sessions=sessions)

if __name__ == '__main__':
    app.run()