import os
import json
import json2zip
import sqlite3
import requests
import msal
import shutil
import flaskcode
from functions import lloogg, date_string, file_dict, template_dict
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from pprint import pprint
from dotenv import load_dotenv
from flask_session import Session
from flask import Flask, render_template, sessions, url_for, flash, redirect, request, session, send_from_directory, g
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user
from forms import BuildForm, RegistrationForm, LoginForm, template
from werkzeug.utils import secure_filename
import auth.app_config as app_config


dirname = os.path.dirname(__file__)


# used by log object to set logs listed in the home page

# returns date as string


dotenv_path = os.path.join(dirname, '.env')
load_dotenv(dotenv_path)


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY')  # should use env --> done
app.config.from_object(app_config)
Session(app)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.config.from_object(flaskcode.default_config)
app.config['FLASKCODE_RESOURCE_BASEPATH'] = os.path.join(
    dirname, 'static/json')
app.register_blueprint(flaskcode.blueprint, url_prefix='/flaskcode')


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
log_file_path = os.path.join(dirname, 'static', 'logs', 'logs.json')
if(os.path.isfile(log_file_path)):
    print('Log file fetched')
    open_file = open(log_file_path, "r")
    logs = json.load(open_file)
    open_file.close()
else:
    print('no logfile')
    log_bkup = os.path.join(dirname, 'static', 'logs_bkup', 'logs.json')
    log_file_path = os.path.join(dirname, 'static', 'logs', 'logs.json')
    shutil.copyfile(log_bkup, log_file_path)


uploads_dir = os.path.join(app.instance_path, 'uploads')
os.makedirs(uploads_dir, exist_ok=True)


def logs_up(logs):
    pprint(logs)
    log_file = open(os.path.join(dirname, 'static', 'logs', 'logs.json'), 'w')
    json.dump(logs, log_file, indent=5)
    log_file.close()


@ app.route("/")
@app.route("/home")
def home():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    lloogg("b", "Someone is Home")
    return render_template('home.html', title='Home', posts=logs, user=session["user"], version=msal.__version__)


@app.route("/temp_view", methods=['GET', 'POST'])
@login_required
def temp_view():
    form = template()
    if form.validate_on_submit():
        f = form.template.data
        group_name = request.form.get('group')
        # f.filename = f.filename.split(
        #     '.')[0]+date_string('stamp')+'.'+f.filename.split('.')[1]
        filename = secure_filename(f.filename)
        f.save(os.path.join(dirname, 'docx', group_name, filename))
    dict_temp_list = template_dict()
    lloogg("b", "Someone is temp_view")
    return render_template('temp_view.html', title='temp_view', posts=dict_temp_list, form=form)


@app.route("/register", methods=['GET', 'POST'])
def register():
    lloogg("b", "Register initiated")
    form = RegistrationForm()
    if form.validate_on_submit():
        conn = sqlite3.connect(os.path.join(dirname, "db", "login.db"))
        curs = conn.cursor()
        email = form.email.data
        username = form.username.data
        password = generate_password_hash(form.password.data)
        curs.execute(
            "INSERT INTO login('email', 'password', 'username') VALUES(?,?,?)", (email, password, username))
        conn.commit()
        flash(f'Account created for {form.username.data}! 💚', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@ app.route("/", methods=['GET', 'POST'])
@ app.route("/login", methods=['GET', 'POST'])
def login():
    lloogg("b", "Someone accessed login")
    form = LoginForm()

    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if not session.get('set'):
        graph_data = graphcall()
    else:
        graph_data = None
    if type(graph_data) is dict:
        graph_user = graph_data['value'][0]['userPrincipalName']
        conn = sqlite3.connect(os.path.join(dirname, "db", "login.db"))
        curs = conn.cursor()
        print(graph_user)
        curs.execute("SELECT * FROM login where email = (?)",
                     [graph_user])
        try:
            user = list(curs.fetchone())
            Us = load_user(user[0])
            login_user(Us)
            flash(f'You have been logged in  👌', 'success')
            return redirect(url_for('home'))
        except:
            flash(f'You are not authendicated 😐', 'danger')
            session['set'] = 'set'
            return redirect(url_for('login'))

    if form.validate_on_submit():
        conn = sqlite3.connect(os.path.join(dirname, "db", "login.db"))
        curs = conn.cursor()
        curs.execute("SELECT * FROM login where email = (?)",
                     [form.email.data])
        try:
            user = list(curs.fetchone())
            Us = load_user(user[0])
        except:
            flash(f'Email or password incorrect 😐', 'danger')
            return redirect(url_for('login'))

        if form.email.data == Us.email and check_password_hash(Us.password, form.password.data):
            login_user(Us)
            session['user'] = {'name': form.email.data}
            session['g_user'] = form.email.data
            flash(f'You have been logged in 💟', 'success')
            return redirect(url_for('home'))
        else:
            flash('Email or password incorrect 😶', 'danger')
    session["flow"] = _build_auth_code_flow(scopes=app_config.SCOPE)
    return render_template('login.html', title='Login', form=form, auth_url=session["flow"]["auth_uri"], version=msal.__version__)


@ app.route("/build", methods=['GET', 'POST'])
@ login_required
def build():

    lloogg("b", "Someone is trying to build")

    dict_items = template_dict()

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
        data_date = form.data_date.data.strftime('%Y-%m-%d')
        data_owner = form.data_owner.data

        if session.get('user'):
            try:
                g_user = session.get('user').name
            except:
                g_user = session.get('g_user')

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
                'data_classification': data_classification,
                'data_date': data_date,
                'data_owner': data_owner
            },
            'specific_fields': {

            }
        }

        for keys in dict_items:
            y = {}
            y[keys] = {}
            for value in dict_items[keys]:
                check = request.form.get(value)
                if check:
                    x = {}
                    docname = value+'.docx'
                    value = value.replace(' ', '')
                    data_author = request.form.get('author-of-'+value)
                    data_classification = request.form.get(
                        'classification-of-'+value)
                    data_date = request.form.get('Date-of-'+value+'-creation')
                    data_owner = request.form.get('Owner-of-'+value)
                    print('author-of-'+value)
                    print('classification-of-'+value)
                    print('Date-of-'+value+'-creation')

                    x[docname] = {
                        'data_author': data_author,
                        'data_classification': data_classification,
                        'data_date': data_date,
                        'data_owner': data_owner
                    }

                    y[keys].update(x)

            json_dict['specific_fields'].update(y)

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
        pprint(log)
        logs.append(log)

        logs_up(logs)

        flash(f'Json create success 💔', 'success')
        lloogg("b", "Built done")
        return redirect(url_for('home'))
    return render_template('build.html', title='Build', form=form, dict_item=dict_items)


@ app.route('/download/<path:filename>', methods=['GET', 'POST'])
@ login_required
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


@app.route("/delete")
def delete():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    lloogg("b", "Someone is deleting")
    return render_template('delete.html', title='Home', logs=logs, user=session["user"], version=msal.__version__)


@ app.route('/temp2del/<path:filename>', methods=['GET', 'POST'])
@ login_required
def temp2del(filename):
    group_name = request.args.get('key')
    lloogg("b", "Delete temp initiated")
    temp_path = os.path.join(dirname, 'docx', group_name, filename+'.docx')
    os.remove(temp_path)
    flash(f'File removed 😦', 'danger')

    lloogg("b", "Delete temp done")
    return redirect(url_for('temp_view'))


@ app.route('/deleteAll/<path:type>', methods=['GET', 'POST'])
@ login_required
def deleteAll(type):
    if type == "zips":
        lloogg("b", "Delete All Zips initiated")
        file_path = os.path.join(dirname, 'zips')
        for file in os.scandir(file_path):
            if file.name.endswith(".zip"):
                os.unlink(file.path)

        lloogg("b", "All zips deleted")
        flash(f'All Zip files where deleted 🙃', 'danger')
        return redirect(url_for('delete'))

    if type == "logs":
        logs = []
        logs_up(logs)

        lloogg("b", "All Logs deleted")
        flash(f'All Logs files where deleted 🙃', 'danger')
        return redirect(url_for('delete'))

    if type == "json":
        lloogg("b", "Delete All Json Configs initiated")
        file_path = os.path.join(dirname, 'static/json')
        for file in os.scandir(file_path):
            if file.name.endswith(".json"):
                os.unlink(file.path)
        flash(f'All Json Config files where deleted 🙃', 'danger')
        lloogg("b", "All Json Configs deleted")
        return redirect(url_for('delete'))

    if type == "All":
        # jsonnn
        lloogg("b", "Delete All Json Configs initiated")
        file_path = os.path.join(dirname, 'static/json')
        for file in os.scandir(file_path):
            if file.name.endswith(".json"):
                os.unlink(file.path)

        lloogg("b", "All Json Configs deleted")

        # logsss
        logs = []
        logs_up(logs)

        lloogg("b", "All Logs deleted")

        # Zipss
        lloogg("b", "Delete All Zips initiated")
        file_path = os.path.join(dirname, 'zips')
        for file in os.scandir(file_path):
            if file.name.endswith(".zip"):
                os.unlink(file.path)

        lloogg("b", "All zips deleted")
        flash(f'Everything Deleted 🙃', 'danger')
        return redirect(url_for('delete'))


@ app.route('/deleteLog/<path:log>', methods=['GET', 'POST'])
@ login_required
def deleteLog(log):
    for i in range(len(logs)):
        if logs[i]['title'] == log:
            del logs[i]
            print(f'log with title -- {log} was deleted')
            pprint(logs)
            logs_up(logs)
            flash(
                f'Log with title -- {log} was deleted this cannot be reversed 🥴', 'danger')
            print('file deleted')
            break
    return redirect(url_for('home'))


# @ app.route("/logout")
# @ login_required
# def logout():
#     session.clear()
#     flash(f'Sad to see you go 😪', 'danger')
#     return redirect(url_for('login'))


@app.route("/logout")
def logout():

    session.clear()
    # Wipe out user and its token cache from session
    redirect(url_for('login'))
    flash(f'Sad to see you go 😪', 'danger')
    return redirect(  # Also logout from your tenant's web session
        app_config.AUTHORITY + "/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + url_for("login", _external=True))


@app.route(app_config.REDIRECT_PATH)
def authorized():
    try:
        cache = _load_cache()
        result = _build_msal_app(cache=cache).acquire_token_by_auth_code_flow(
            session.get("flow", {}), request.args)
        if "error" in result:
            return render_template("auth_error.html", result=result)
        session["user"] = result.get("id_token_claims")
        _save_cache(cache)
    except ValueError:  # Usually caused by CSRF
        pass  # Simply ignore them
    return redirect(url_for("home"))


@app.route("/graphcall")
def graphcall():
    token = _get_token_from_cache(app_config.SCOPE)
    if not token:
        return redirect(url_for("login"))
    graph_data = requests.get(  # Use token to call downstream service
        app_config.ENDPOINT,
        headers={'Authorization': 'Bearer ' + token['access_token']}).json()
    return graph_data


def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache


def _save_cache(cache):
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()


def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        app_config.CLIENT_ID, authority=authority or app_config.AUTHORITY,
        client_credential=app_config.CLIENT_SECRET, token_cache=cache)


def _build_auth_code_flow(authority=None, scopes=None):
    return _build_msal_app(authority=authority).initiate_auth_code_flow(
        scopes or [],
        redirect_uri=url_for("authorized", _external=True))


def _get_token_from_cache(scope=None):
    cache = _load_cache()  # This web app maintains one cache per session
    cca = _build_msal_app(cache=cache)
    accounts = cca.get_accounts()
    if accounts:  # So all account(s) belong to the current signed-in user
        result = cca.acquire_token_silent(scope, account=accounts[0])
        _save_cache(cache)
        return result


app.jinja_env.globals.update(
    _build_auth_code_flow=_build_auth_code_flow)  # Used in template


if __name__ == '__main__':
    app.run(debug=True)
