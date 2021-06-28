from flask_wtf import FlaskForm
from wtforms.fields.html5 import DateField
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_wtf.file import FileField, FileRequired, FileAllowed
import os


class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')


class LoginForm(FlaskForm):
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class template(FlaskForm):
    submit = SubmitField('Add')
    template = FileField('Choose template', validators=[FileRequired(),
                                                        FileAllowed(['docx'], 'Docx files only!')])


class BuildForm(FlaskForm):
    project_name = StringField(
        '', validators=[DataRequired(), Length(min=4, max=100)], render_kw={"placeholder": "Project Name"})
    logo = FileField('', validators=[FileRequired(),
                     FileAllowed(['jpg', 'png'], 'Images only!')], render_kw={"title": "Logo"})
    company_full_name = StringField(
        '', validators=[DataRequired(), Length(min=4, max=100)], render_kw={"placeholder": "Company Full Name"})
    company_short_name = StringField(
        '', validators=[DataRequired(), Length(min=4, max=100)], render_kw={"placeholder": "Company Short Name"})
    ciso_name = StringField('', validators=[
                            DataRequired(), Length(min=4, max=100)], render_kw={"placeholder": "Name of the CISO / IT Security Manager"})
    hrman_name = StringField('', validators=[
        DataRequired(), Length(min=4, max=100)], render_kw={"placeholder": "Name of Hr Manager"})
    itsec_name = StringField('', validators=[
                             DataRequired(), Length(min=2, max=100)], render_kw={"placeholder": "Name of IT Security Department"})
    ithelp_name = StringField('', validators=[
                              DataRequired(), Length(min=2, max=100)], render_kw={"placeholder": "Name of IT Helpdesk Department"})
    doc_ref = StringField('', validators=[
                          DataRequired(), Length(min=2, max=100)], render_kw={"placeholder": "Doc ref prefix"})
    data_author = StringField('', validators=[
        DataRequired(), Length(min=2, max=100)], render_kw={"placeholder": "Data Author"})
    data_classification = StringField('', validators=[
        DataRequired(), Length(min=2, max=100)], render_kw={"placeholder": "Data Classification"})
    data_date = DateField('', format='%Y-%m-%d')
    data_owner = StringField('', validators=[
        DataRequired(), Length(min=2, max=100)], render_kw={"placeholder": "Data Owner"})
    submit = SubmitField('Build!')
