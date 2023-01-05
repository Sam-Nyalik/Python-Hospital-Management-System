from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
import bcrypt
import re

app = Flask(__name__)

app.secret_key = 'your secret key'
# Database Connection
app.config['MYSQL_DATABASE'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Your mysql database password'
app.config['MYSQL_DB'] = 'hospitalSystem'

db = MySQL(app)


# Home route
@app.route('/hospitalSystem/')
def home():
    return render_template('index.html')


# User registration route
@app.route('/hospitalSystem/user_register', methods=['GET', 'POST'])
def user_register():  
    # Define variables and assign them empty values 
    message = ''
    fullName = ''
    emailAddress = ''
    gender = ''
    age = ''
    password = ''
    confirmPassword = ''
    fullName_error = ''
    email_error = ''
    gender_error = ''
    age_error = ''
    password_error = ''
    confirmPassword_error = ''
    
    # Validate the request method and the user input when the form is submitted
    if request.method == 'POST':
        # Store user input inside variables
        # fullName = request.form['fullName']
        # emailAddress = request.form['emailAddress']
        # gender = request.form['gender']
        # password = request.form['password']
        # confirmPassword = request.form['confirmPassword']
        
        # Validating fullName
        if request.form['fullName'] == "":
            fullName_error = "Field is required"
        else:
            fullName = request.form['fullName']    
            
        # Validate emailAddress
        if request.form['emailAddress'] == "":
            email_error = "Field is required"
        else:
            emailAddress = request.form['emailAddress']    
            
        # Validate gender
        if request.form['gender'] == "":
            gender_error = "Field is required"
        else:
            gender = request.form['gender']   
            
            
        # Validate age
        if request.form['age'] == "":
            age_error = "Field is required"
        elif not re.match (r'[0-9]+',request.form['age']):
            age_error = "Only numbers are allowed"
        else:
            age = request.form['age']    
            
        # Validate password
        if request.form['password'] == "":
            password_error = "Field is required"
        elif len(request.form['password']) < 8:
            password_error = "Passwords must have at least 8 characters"
        else:
            password = request.form['password']    
        
        # Validate confirm password
        if request.form['confirmPassword'] == "":
            confirmPassword_error = "Field is required"
        else:
            confirmPassword = request.form['confirmPassword']    
            
            if password_error == "" and password != confirmPassword:
                confirmPassword_error = "Passwords do not match!"
                
        if fullName_error == "" and email_error == "" and gender_error == "" and password_error == "" and confirmPassword_error == "":
            # Check if the account already exists
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("SELECT * FROM users WHERE emailAddress = %s", (emailAddress,))
            account = cursor.fetchone()
        
            # If account exists display an error
            if account:
                message = "User with this email address already exists!"
            else:
                # Account doesn't exist, prepare an INSERT statement
                # Hash the password
                # Convert the password to an array of bytes
                bytes = password.encode('utf-8')
                # Generate the salt
                salt = bcrypt.gensalt()
                # Hash password
                password_hash = bcrypt.hashpw(bytes,salt)
                cursor.execute("INSERT INTO users(fullName, emailAddress, gender, age, password) VALUES(%s, %s, %s, %s, %s)", (fullName, emailAddress, gender, age, password))
                db.connection.commit()
            
                return redirect(url_for('user_login'))
        
    return render_template('User/register.html', message=message, fullName_error=fullName_error, email_error=email_error, gender_error=gender_error, age_error=age_error, password_error=password_error, confirmPassword_error=confirmPassword_error)

# User Login route
@app.route('/hospitalSystem/user_login', methods=['GET', 'POST'])
def user_login():
    # Define variables and assign them empty values
    emailAddress = ''
    password = ''
    emailAddress_error = ''
    password_error = ''
    message = ''
    if request.method == 'POST':
        # Validate emailAddress
        if request.form['emailAddress'] == "":
            emailAddress_error = 'Field is required'
        else:
            emailAddress = request.form['emailAddress']    
            
        # Validate password
        if request.form['password'] == "":
            password_error = "Field is required"
        else:
            password = request.form['password']    
            
        if emailAddress_error == "" and password_error == "":
            # Check if the account exists
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("SELECT user_id, fullName, emailAddress, password FROM users WHERE emailAddress = %s", (emailAddress,))
            # Fetch the record
            account = cursor.fetchone()
            
            # User doen't exist, generate an error
            if not account:
                message = "User with these details doesn't exist"
                
            # User exists, proceed
            else:
                # Store database data in variables
                user_id = account['user_id']
                fullName = account['fullName']
                user_emailAddress = account['emailAddress']
                db_password = account['password']
                
                # Verify the passwords
                if password == db_password:
                    # store data in sessions
                    session['loggedIn'] = True
                    session['user_id'] = user_id
                    session['fullName'] = fullName
                    session['emailAddress'] = user_emailAddress
                    
                    return redirect(url_for('user_dashboard'))
                
                else:
                    password_error = "Wrong password"
                
                
    return render_template('User/login.html', message=message, emailAddress_error=emailAddress_error, password_error=password_error)

# User Logout route
@app.route('/hospitalSystem/user_logout')
def user_logout():
    # Unset the sessions
    session.pop('loggedIn', None)
    session.pop('user_id', None)
    session.pop('fullName', None)
    session.pop('emailAddress', None)
    
    # Redirect the user to the login page
    return redirect(url_for('user_login'))


# User dashboard route
@app.route('/hospitalSystem/user_dashboard')
def user_dashboard():
    # Check if the user is loggedIn
    if 'loggedIn' in session:
        # User is logged in, redirect to the dashboard page
        return render_template('User/dashboard.html', user_id=session['user_id'], full_name=session['fullName'])
    # User isn't logged in
    return redirect(url_for('user_login'))

#Admin Login route
@app.route('/hospitalSystem/admin_login', methods=['GET', 'POST'])
def admin_login():
    # Define variables and assign them empty values
    emailAddress = ''
    password = ''
    # Error variables
    emailAddress_error = ''
    password_error = ''
    message = ''
    
    if request.method == 'POST':
        # validate emailAddress
        if not request.form['emailAddress']:
            emailAddress_error = "Field is required"
        else:
            emailAddress = request.form['emailAddress']
            
        # Validate password
        if not request.form['password']:
            password_error = "Field is required"
        else:
            password = request.form['password']    
            
        # Check for errors before dealing with the database
        if not emailAddress_error and not password_error:
            # Prepare a SELECT statement
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("SELECT * FROM admin WHERE emailAddress=%s", (emailAddress,))
            account = cursor.fetchone()
            
            # Check if the user exists
            if not account:
                message = "User with this email address does not exist"
            else:
                #  User exists, Validate passwords
                if password != account['password']:
                    password_error = "Wrong password"
                else:
                     # Password is correct, store data in session variables
                    admin_id = account['id']
                    admin_fullName = account['fullName']
                    admin_emailAddress = account['emailAddress']
                    session['loggedIn'] = True
                    session['id'] = admin_id
                    session['fullName'] = admin_fullName
                    session['emailAddress'] = admin_emailAddress
                    
                    # Redirect to the dashboard page
                    return redirect(url_for('admin_dashboard'))
                     
    return render_template('Administrator/login.html', message=message, emailAddress=emailAddress, password=password, emailAddress_error=emailAddress_error, password_error=password_error)

# Admin Register route
@app.route('/hospitalSystem/admin_register', methods=['GET', 'POST'])
def admin_register():
    # Define variables and assign them empty values
    fullName = ''
    emailAddress = ''
    gender = ''
    password = ''
    confirmPassword = ''
    # Error variables
    fullName_error = ''
    emailAddress_error = ''
    gender_error = ''
    password_error = ''
    confirmPassword_error = ''
    message = ''
    if request.method == 'POST':
        # Validate fullName
        if not request.form['fullName']:
            fullName_error = "Field is required"
        else:
            fullName = request.form['fullName']    
       
        # Validate emailAddress
        if not request.form['emailAddress']:
            emailAddress_error = 'Field is required'
        else:
            emailAddress = request.form['emailAddress']    
            
        # Validate gender
        if not request.form['gender']:
            gender_error = "Field is required"
        else:
            gender = request.form['gender']    
            
        # Validate password
        if not request.form['password']:
            password_error = "Field is required"
        elif len(request.form['password']) < 8:
            password_error = "Passwords must have more than 8 characters"
        else:
            password = request.form['password']
            
        # Validate confirmPassword
        if not request.form['confirmPassword']:
            confirmPassword_error = "Field is required"
        else: 
            confirmPassword = request.form['confirmPassword']   
            
        # Validate password and confirm password
        if password_error == '' and password != confirmPassword:
            confirmPassword_error = "Passwords do not match"      
            
        # Check for errors before dealing with the database
        if not fullName_error and not emailAddress_error and not gender_error and not password_error and not confirmPassword_error:
            cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
            cursor.execute("SELECT * FROM admin WHERE emailAddress = %s", (emailAddress,))
            account = cursor.fetchone()
            # Check if account exists
            if account:
                message = "Email Address already exists. Use a different one"
            # User with the emailAddress doesn't exist, proceed to the INSERT statement
            else:
                cursor.execute('INSERT INTO admin(fullName, emailAddress, gender, password) VALUES(%s,%s,%s,%s)', (fullName, emailAddress, gender, password))
                db.connection.commit()
                # Redirect the admin to the login page
                return redirect(url_for('admin_login'))
                
    return render_template('Administrator/register.html', message= message, fullName=fullName, emailAddress=emailAddress, gender=gender, password=password, confirmPassword=confirmPassword, fullName_error=fullName_error, emailAddress_error=emailAddress_error, gender_error=gender_error, password_error=password_error, confirmPassword_error=confirmPassword_error)

# Admin Logout route
@app.route('/hospitalSystem/admin_logout')
def admin_logout():
    # Kill sessions
    session.pop('loggedIn', None)
    session.pop('fullName', None)
    session.pop('emailAddress', None)
    session.pop('id', None)
    
    # Redirect to the login page
    return redirect(url_for('admin_login'))

# Admin dashboard route
@app.route('/hospitalSystem/admin_dashboard')
def admin_dashboard():
    # Check if admin is loggedIn
    if 'loggedIn' in session:
        db_fullName = session['fullName']
        return render_template('Administrator/dashboard.html', db_fullName=db_fullName)
    # Admin is not logged in, redirect to the login page
    return redirect(url_for('admin_login'))

# Admin profile route
@app.route('/hospitalSystem/admin_profile', methods=['GET', 'POST'])
def admin_profile():
    # Define variables and assign them empty values
    fullName = ''
    emailAddress = ''
    fullName_error = ''
    message = ''
    # Check if the admin is logged in
    if 'loggedIn' in session:
        db_fullName = session['fullName']
        db_emailAddress = session['emailAddress']
        
        # Process form data when the form is submitted
        if request.method == 'POST':
            #Validate form data
            # Validate full name
            if request.form['fullName'] == '':
                fullName_error = "Field is required!"
            else:
                fullName = request.form['fullName']
            
            # Check for errors before dealing with the database 
            if fullName_error == '':
                #Prepare an update statement
                cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
                cursor.execute("UPDATE admin SET fullName = %s WHERE emailAddress = %s", (fullName, db_emailAddress))
                db.connection.commit()
                
                message = "Profile has been updated successfully!"
        return render_template('Administrator/profile.html', message=message, db_fullName=db_fullName, db_emailAddress=db_emailAddress, fullName=fullName, emailAddress=emailAddress, fullName_error=fullName_error)
    # Admin is not logged in, redirect to the login page
    return redirect(url_for('admin_login'))

# Admin Password reset
@app.route('/hospitalSystem/admin_password_reset', methods=['GET', 'POST'])
def admin_password_reset():
    # Initialize variables and assign them empty values
    currentPassword = ''
    newPassword = ''
    confirmNewPassword = ''
    currentPassword_error = ''
    newPassword_error = ''
    confirmNewPassword_error = ''
    # Check if the admin is logged in
    if 'loggedIn' in session:
        # Process form data when the form is submitted
       if request.method == 'POST':
            # Validate user input  
            # Validate currentPassword
            if request.form['currentPassword'] == '':
                currentPassword_error = "Field is required"
            else:
                currentPassword = request.form['currentPassword']    
            # Validate new password
            if request.form['newPassword'] == '':
                newPassword_error = "Field is required"
            elif len(request.form['newPassword']) < 8:
                newPassword_error = "Passwords must have more than 8 characters"
            else:
                newPassword = request.form['newPassword']    
            # Validate confirmNewPassword
            if request.form['confirmNewPassword'] == '':
                confirmNewPassword_error = "Field is required"
            else:
                confirmNewPassword = request.form['confirmNewPassword']    
                
            if newPassword_error == '' and newPassword != confirmNewPassword:
                # Passwords do not match
                confirmNewPassword_error = "New Passwords do not match"
                
    return render_template('Administrator/admin_password_reset.html', currentPassword_error=currentPassword_error, newPassword_error=newPassword_error, confirmNewPassword_error=confirmNewPassword_error)
    
    # Admin isn't logged in, redirect to the login page
    return redirect(url_for('admin_login'))

# Admin User Management route
@app.route('/hospitalSystem/manage_users')
def manage_users():
    # Check if the admin is logged in
    if 'loggedIn' in session:
        # Fetch user data from the database
        cursor = db.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute("SELECT * FROM users ORDER BY registration_date")
        account = cursor.fetchall()
        count = 1
    return render_template('Administrator/users/manage_users.html', account=account, count=count)

    # Redirect to the login page
    return redirect(url_for('admin_login'))

# Admin Add doctor route
@app.route('/hospitalSystem/add_doctor')
def add_doctor():
    
    # Return the add_doctor.html template
    return render_template('Administrator/doctors/add_doctor.html')