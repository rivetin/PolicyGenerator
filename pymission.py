import os
import json
import pickle
import json2zip
from dotenv import load_dotenv
from datetime import datetime
from flask import Flask, render_template, sessions, url_for, flash, redirect, request, session, send_from_directory
from forms import BuildForm, RegistrationForm, LoginForm
from werkzeug.utils import secure_filename


dirname = os.path.dirname(__file__)

# used by log object to set logs listed in the home page

# returns date as string


def date_string(x):
    if x == 'stamp':
        return datetime. now(). strftime("_%d_%m_%Y_%I:%M:%S_%p")
    if x == 'homelog':
        return datetime. now(). strftime("%I:%M, %B %d, %Y")

# returns a dict with all files in the docx dir without extention


def file_dict():
    path = os.path.join(dirname, 'docx')
    dir_list = os.listdir(path)
    dict_dir = {}
    x = 1
    for item in dir_list:
        item = item.split(".")[0]
        dict_dir["{0}".format(x)] = item
        x += 1
    return dict_dir


dotenv_path = os.path.join(dirname, '.env')
load_dotenv(dotenv_path)


app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get(
    'SECRET_KEY')  # should use env --> done


# please dont open the pkl file it might corrept the file.
log_file_path = os.path.join(dirname, 'static', 'logs', 'logs.pkl')
open_file = open(log_file_path, "rb")
logs = pickle.load(open_file)

open_file.close()


uploads_dir = os.path.join(app.instance_path, 'uploads')
os.makedirs(uploads_dir, exist_ok=True)


@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html', posts=logs)


@app.route("/build", methods=['GET', 'POST'])
def build():
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
                'doc_ref': doc_ref
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
        return redirect(url_for('home'))
    return render_template('build.html', title='Build', form=form, dict_item=dict_items)


@app.route('/download/<path:filename>', methods=['GET', 'POST'])
def download(filename):
    # Appending app path to upload folder path within app root folder
    json_file = os.path.join(dirname, './static/json', filename)
    # Returning file from appended path
    print(json_file)
    zip_path, filename = json2zip.generate_zip(json_file)
    return send_from_directory(directory=zip_path, path=filename, as_attachment=True)


@app.route("/logout")
def logout():
    session.clear()
    flash(f'Sad to see you go 😪', 'danger')
    return redirect(url_for('login'))


@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        flash(f'Account created for {form.username.data}!', 'success')
        return redirect(url_for('home'))
    return render_template('register.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        if form.email.data == 'athul@com.com' and form.password.data == 'password':
            session['user'] = form.email.data
            flash(
                f'You have been logged in as { form.email.data } !', 'success')
            return redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)


if __name__ == '__main__':
    app.run(debug=False)
