from flask import Flask, render_template, request, redirect, send_file
import sqlite3, io
from sqlite3 import Error
from flask import Response

app = Flask(__name__)

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
        Filament = request.form.get('Filament')
        Size = request.form.get('Size')
        Model = request.files.get('Model_File')

        file_data = Model.read()

        con = connect_database(DATABASE)
        cur = con.cursor()
        query_insert = "INSERT INTO session (Filament, size, model, filename) VALUES (?, ?, ?, ?)"
        cur.execute(query_insert, (Filament, Size, file_data, Model.filename))
        con.commit()
        con.close()

    return render_template('Session.html')

@app.route('/images')
def render_imagespage():
    return render_template('images.html')
@app.route('/Login', methods=['POST', 'GET'])
def render_loginpage():
    return render_template('Login.html')

@app.route('/Signin', methods=['POST', 'GET'])
def render_signinpage():
    if request.method == 'POST':
        Name = request.form.get('Name')
        Address = request.form.get('Address')
        Email = request.form.get('Email')
        password = request.form.get('Password')

        con = connect_database(DATABASE)
        cur = con.cursor()
        query_insert = "INSERT INTO users (username, address, email, password) VALUES (?, ?, ?, ?)"
        cur.execute(query_insert, (Name, Address, Email, password))
        con.commit()
        con.close()

    return render_template('signin.html')



if __name__ == '__main__':
    app.run()