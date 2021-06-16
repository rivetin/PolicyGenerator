import os
import json
import pickle
import json2zip
import sqlite3
import hashlib
from dotenv import load_dotenv
from datetime import datetime
from flask import Flask, render_template, sessions, url_for, flash, redirect, request, session, send_from_directory, g
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from forms import BuildForm, RegistrationForm, LoginForm
from werkzeug.utils import secure_filename


dirname = os.path.dirname(__file__)


# used by log object to set logs listed in the home page

# returns date as string


def lloogg(s, x):
    if s == "b":
        print('--------------------------------------------')
        print(f'{x}')
        print('--------------------------------------------')
    if s == "s":
        print(f'{x}')


def date_string(x):
    lloogg("s", "Date returned")
    if x == 'stamp':
        return datetime. now(). strftime("_%d_%m_%Y_%I:%M:%S_%p")
    if x == 'homelog':
        return datetime. now(). strftime("%I:%M, %B %d, %Y")

# returns a dict with all files in the docx dir without extention


def file_dict():
    lloogg("s", "Traversing dir folder : - Retrived")
    path = os.path.join(dirname, 'docx')
    dir_list = os.listdir(path)
    dict_dir = {}
    x = 1
    for item in dir_list:
        item = item.split(".")[0]
        dict_dir["{0}".format(x)] = item
        x += 1
    lloogg("b", "Traversing dir folder : - Retrived")
    return dict_dir


dotenv_path = os.path.join(dirname, '.env')
load_dotenv(dotenv_path)


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY')  # should use env --> done


login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "danger"
login_manager.session_protection = "strong"


class User(UserMixin):
    def __init__(self, id, email, password):
        self.id = id
        self.email = email
        self.password = password
        self.authenticated = False

    def is_active(self):
        return self.is_active()

    def is_anonymous(self):
        return False

    def is_authenticated(self):
        return self.authenticated

    def is_active(self):
        return True

    def get_id(self):
        return self.id


@login_manager.user_loader
def load_user(user_id):
    conn = sqlite3.connect(os.path.join(dirname, "db", "login.db"))
    curs = conn.cursor()
    curs.execute("SELECT * from login where user_id = (?)", [user_id])
    lu = curs.fetchone()
    if lu is None:
        return None
    else:
        return User(int(lu[0]), lu[1], lu[2])


# please dont try to open the pkl file it might corrept the file.
log_file_path = os.path.join(dirname, 'static', 'logs', 'logs.pkl')
if(os.path.isfile(log_file_path)):
    print('Log file fetched')
    open_file = open(log_file_path, "rb")
    logs = pickle.load(open_file)
    open_file.close()
else:
    print('no logfile')
    open_file = open(log_file_path, "wb")
    logs = pickle.load(open_file)
    log = {
        'author': '',
        'title': 'Log file was not found',
        'content': 'none',
        'date_posted': date_string('homelog'),
        'json': 'none'}
    logs.append(log)
    pickle.dump(logs, open_file)
    open_file.close()


uploads_dir = os.path.join(app.instance_path, 'uploads')
os.makedirs(uploads_dir, exist_ok=True)


@app.route("/home")
@login_required
def home():
    lloogg("b", "Someone is Home")
    return render_template('home.html', title='Home', posts=logs)


@app.route("/", methods=['GET', 'POST'])
@app.route("/login", methods=['GET', 'POST'])
def login():
    lloogg("b", "Someone accessed login")
    form = LoginForm()
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if form.validate_on_submit():
        conn = sqlite3.connect(os.path.join(dirname, "db", "login.db"))
        curs = conn.cursor()
        curs.execute("SELECT * FROM login where email = (?)",
                     [form.email.data])
        try:
            user = list(curs.fetchone())
            Us = load_user(user[0])
        except:
            flash(f'Incorrect email ', 'danger')
            return redirect(url_for('login'))

        if form.email.data == Us.email and form.password.data == Us.password:
            login_user(Us, remember=form.remember.data)
            Umail = list({form.email.data})[0].split('@')[0]
            session['user'] = form.email.data
            flash(f'You have been logged in 💟', 'success')
            return redirect(url_for('home'))
        else:
            flash('Email or password incorrect', 'danger')
    return render_template('login.html', title='Login', form=form)


@app.route("/build", methods=['GET', 'POST'])
@login_required
def build():
    lloogg("b", "Someone is trying to build")
    dict_items = file_dict()
    form = BuildForm()
    if form.validate_on_submit():
        f = form.logo.data
        f.filename = f.filename.split(
            '.')[0]+date_string('stamp')+'.'+f.filename.split('.')[1]
        filename = secure_filename(f.filename)
        f.save(os.path.join(
            uploads_dir, filename
        ))

        project_name = form.project_name.data
        company_full_name = form.company_full_name.data
        company_short_name = form.company_short_name.data
        ciso_name = form.ciso_name.data
        hrman_name = form.hrman_name.data
        itsec_name = form.itsec_name.data
        ithelp_name = form.ithelp_name.data
        doc_ref = form.doc_ref.data
        data_author = form.data_author.data
        data_classification = form.data_classification.data
        data_date = form.data_date.data
        data_owner = form.data_owner.data

        if session.get('user'):
            g_user = session.get('user')
        else:
            g_user = 'Web Admin'

        json_dict = {
            'project_name': project_name,
            'common_fields': {
                'filename': filename,
                'company_full_name': company_full_name,
                'company_short_name': company_short_name,
                'ciso_name': ciso_name,
                'hrman_name': hrman_name,
                'itsec_name': itsec_name,
                'ithelp_name': ithelp_name,
                'doc_ref': doc_ref,
                'data_author': data_author,
                'data_classification': data_author,
                'data_date': data_author,
                'data_owner': data_author
            },
            'specific_fields': {

            }
        }

        x = {}
        x = 1
        for key, value in dict_items.items():
            check = request.form.get(value)
            if check:
                data_author = (request.form.get('author-of-'+value))
                data_classification = (
                    request.form.get('classification-of-'+value))
                data_date = (request.form.get('Date-of-'+value+'-creation'))
                data_owner = (request.form.get('Owner-of-'+value))

                x = {
                    'data_author': data_author,
                    'data_classification': data_classification,
                    'data_date': data_date,
                    'data_owner': data_owner
                }

                json_dict['specific_fields'][value+'.docx'] = x

        out_file_name = project_name+date_string('stamp')+".json"
        out_file_name = secure_filename(out_file_name)
        out_file_path = os.path.join(dirname, 'static', 'json', out_file_name)
        out_file = open(out_file_path, 'w')
        json.dump(json_dict, out_file, indent=5)
        out_file.close()

        log = {
            'author': g_user,
            'title': project_name,
            'content': company_full_name,
            'date_posted': date_string('homelog'),
            'json': out_file_name}

        logs.append(log)
        open_file = open(log_file_path, "wb")
        pickle.dump(logs, open_file)
        open_file.close()

        flash(f'Json create success 💔', 'success')
        lloogg("b", "Built done")
        return redirect(url_for('home'))
    return render_template('build.html', title='Build', form=form, dict_item=dict_items)


@app.route('/download/<path:filename>', methods=['GET', 'POST'])
@login_required
def download(filename):
    lloogg("b", "Download Initiated")
    # Appending app path to upload folder path within app root folder
    json_file = os.path.join(dirname, 'static/json', filename)
    # Returning file from appended path
    print(json_file)
    zip_path, filename = json2zip.generate_zip(json_file)
    if zip_path == False:
        flash(f'File was deleted 😿', 'danger')
        return redirect(url_for('home'))

    lloogg("b", "download done")
    return send_from_directory(directory=zip_path, path=filename, as_attachment=True)


@app.route('/deleteLog/<path:log>', methods=['GET', 'POST'])
@login_required
def deleteLog(log):
    for i in range(len(logs)):
        if logs[i]['title'] == log:
            del logs[i]
            print(f'log with title -- {log} was deleted')
            flash(
                f'Log with title -- {log} was deleted this cannot be reversed 🥴', 'danger')
            break

    return redirect(url_for('home'))


@app.route("/register", methods=['GET', 'POST'])
@login_required
def register():
    lloogg("b", "Register initiated")
    form = RegistrationForm()
    if form.validate_on_submit():
        flash(f'Account created for {form.username.data}!', 'success')
        return redirect(url_for('home'))
    return render_template('register.html', title='Register', form=form)


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash(f'Sad to see you go 😪', 'danger')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)
