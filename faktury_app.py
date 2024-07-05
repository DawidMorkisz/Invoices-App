from flask import Flask, render_template, request, redirect, url_for, session, g
from dotenv import load_dotenv
from datetime import datetime
import pyodbc, hashlib
import os

load_dotenv() 

app = Flask(__name__)
app.secret_key = os.urandom(24)
print(app.secret_key)

db_config = {  
    'server': 'localhost\\SQLEXPRESS',
    'database': 'invoices',
    'trusted_connection': 'yes',
    'driver': '{SQL Server}'
}

def passwordhash(password):
    hash_algorithm = os.getenv('HASH_ALGORITHM')

    hash = hashlib.new(hash_algorithm)
    hash.update(password.encode())
    password = hash.hexdigest()
    return password

def Logs (log_content):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S ")
    with open('Logs.txt','a') as file:
        file.write('\n'+current_time + log_content)

@app.before_request
def before_request():
    g.user = None
    g.role = None
    if 'username' in session:
        g.user = session['username']
        g.role = session['role']


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['login']
        password = request.form['password']

        conn = pyodbc.connect(';'.join([f'{key}={value}' for key, value in db_config.items()]))
        cursor = conn.cursor()

        query = "SELECT login, password, role FROM users WHERE login = ?"
        cursor.execute(query, (username,))
        user_record = cursor.fetchone()

        if user_record and user_record[1] == passwordhash(password):
            session['username'] = user_record[0]
            session['role'] = user_record[2]
            Logs(f"User {username} has logged in")
            return redirect(url_for('application'))
        else:
            Logs(f"User {username} failed login attempt")
            return render_template('login.html', error=True) 

        cursor.close()
        conn.close()

    return render_template('login.html')

@app.route('/')
def application():
    if 'username' in session:
        return render_template('application.html')
    else:
        return redirect(url_for('login'))
    
@app.route('/logout')
def logout():
    Logs(f"User {g.user} logged out")
    session.clear()
    return redirect(url_for('login'))
    
# ---------------------------- Invoice section---------------------------- 

@app.route('/invoice_layout')
def invoices():
    if 'username' in session:
        return render_template('invoice_layout.html')
    else:
        return redirect(url_for('login'))

@app.route('/add_invoice', methods=['POST'])
def add_invoice():
    invoice_no = request.form.get('invoice_no')
    add_date = request.form.get('add_date')
    client_name = request.form.get('client_name')
    amount = request.form.get('amount')

    if invoice_no == '' or add_date == '' or client_name == '' or amount == '':
        return render_template('invoice_layout.html', error=True)
    else:
        conn = pyodbc.connect(';'.join([f'{key}={value}' for key, value in db_config.items()]))
        cursor = conn.cursor()
        query = ("INSERT INTO invoices (invoice_no, add_date, client_name, amount) "
         "VALUES (?, ?, ?, ?)")
        cursor.execute(query, (invoice_no, add_date, client_name, amount,))
        conn.commit()

        cursor.close()
        conn.close()

        Logs(f"New invoice has been added successfully by {g.user}")
        return render_template('invoice_layout.html')

@app.route('/search_invoices', methods=['GET'])
def search_invoices():
    search_param = request.args.get('search_param')
    value = request.args.get('value')

    conn = pyodbc.connect(';'.join([f'{key}={value}' for key, value in db_config.items()]))
    cursor = conn.cursor()

    if search_param == 'all':
        query = "SELECT * FROM invoices"
        cursor.execute(query)
    elif search_param in ['search_by_date', 'search_by_client_name']:
        query = f"SELECT * FROM invoices WHERE {search_param} = ?"
        cursor.execute(query, (value,))

    invoices = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('searched_invoices.html', invoices=invoices)

# ----------------------------Payment Section ---------------------------- 

@app.route('/payment_status_main')
def payment_status():
    if 'username' in session:
        return render_template('payment_status_main.html')
    else:
        return redirect(url_for('login'))

@app.route('/add_payment_status', methods=['POST'])
def add_payment_status():
    invoice_no = request.form.get('invoice_no')
    payment_date = request.form.get('payment_date')
    status = request.form.get('status')

    conn = pyodbc.connect(';'.join([f'{key}={value}' for key, value in db_config.items()]))
    cursor = conn.cursor()

    query = ("INSERT INTO payment_status (invoice_no, payment_date, status) "
             "VALUES (?, ?, ?)")
    cursor.execute(query, (invoice_no, payment_date, status,))
    conn.commit()

    cursor.close()
    conn.close()
    Logs(f'Payment status for invoice no.{invoice_no} was added by {g.user}')
    return 'Status płatności dodany'

@app.route('/search_payment_status', methods=['GET'])
def search_payment_status():
    status = request.args.get('status')

    conn = pyodbc.connect(';'.join([f'{key}={value}' for key, value in db_config.items()]))
    cursor = conn.cursor()

    if status == 'all':
        query = "SELECT * FROM payment_status"
        cursor.execute(query)
    else:
        query = "SELECT * FROM payment_status WHERE status = ?"
        cursor.execute(query, (status,))

    statusy = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('payment_status.html', statusy=statusy)

# ---------------------------- User section---------------------------- 

@app.route('/users')
def users():
    if 'username' in session and g.role == "admin":
        return render_template('users.html')
    else:
        return redirect(url_for('login'))

@app.route('/add_user', methods=['POST'])
def add_user():
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    role = request.form.get('role')
    login = request.form.get('login')
    password = request.form.get('password')  

    if first_name == '' or last_name == '' or role == '' or login == '' or password == '':
        return render_template('users.html', EmptyFieldError=True)
    elif user_exists(login):
        return render_template('users.html', UserExistError=True)
    else:
        conn = pyodbc.connect(';'.join([f'{key}={value}' for key, value in db_config.items()]))
        cursor = conn.cursor()

        query = ("INSERT INTO users (first_name, last_name, role, login, password) "
             "VALUES (?, ?, ?, ?, ?)")
        cursor.execute(query, (first_name, last_name, role, login, passwordhash(password),))
        conn.commit()

        cursor.close()
        conn.close()

        Logs(f"User {login} has been added successfully by {g.user}")
        return render_template('users.html', UserAddedSuccess = True)

@app.route('/search_users', methods=['GET'])
def search_users():
    role = request.args.get('role')

    conn = pyodbc.connect(';'.join([f'{key}={value}' for key, value in db_config.items()]))
    cursor = conn.cursor()

    if role == 'all':
        query = "SELECT * FROM users"
        cursor.execute(query)
    else:
        query = "SELECT * FROM users WHERE role = ?"
        cursor.execute(query, (role,))

    users = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template('searched_users.html', users=users)

def user_exists(login):
    conn = pyodbc.connect(';'.join([f'{key}={value}' for key, value in db_config.items()]))
    cursor = conn.cursor()

    query = "SELECT COUNT(*) FROM users WHERE login = ?"
    cursor.execute(query, (login,))
    result = cursor.fetchone()

    cursor.close()
    conn.close()

    return result[0] > 0

if __name__ == '__main__':
    app.run(debug=True)
