from flask import Flask, render_template, request, redirect, url_for
from validator import validate_password_security
from DB_MANAGMENT import Establish_DB_Connection, CloseDBConnection, CheckIfUserExists, AddUserToDB

app = Flask(__name__)

@app.route('/') 
def login():
    return render_template('login.html')

@app.route('/change_password')
def change_password():
    return render_template('change_password.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        print("--- Register Start ---") 
        
        current_connection = Establish_DB_Connection()
        
        if not current_connection:
            return render_template('register.html', error_msg="Connection Error")

        fname = request.form['first_name']
        lname = request.form['last_name']
        email = request.form['email']
        pwd = request.form['password']
        dob = request.form['date_of_birth']

        try:
            error = validate_password_security(pwd)
            if error:
                print(f"!!! STOPPING HERE: Password Validation Failed: {error}") 
                CloseDBConnection(current_connection)
                return render_template('register.html', error_msg=error)
        except NameError:
             print("Error: Function name mismatch in validator")

        if CheckIfUserExists(current_connection, email):
            CloseDBConnection(current_connection)
            return render_template('register.html', error_msg='User already exists')
        
        else:
            print("--- Attempting to add user ---")
            success = AddUserToDB(current_connection, fname, lname, email, pwd, dob)
            CloseDBConnection(current_connection) 

            if success:
                print("--- Success! Redirecting ---")
                return redirect(url_for('login'))
            else:
                print("--- DB Error (result was False/None) ---")
                return render_template('register.html', error_msg="Error with DB")

    return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=False)