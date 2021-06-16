from flask_wtf import FlaskForm
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


class BuildForm(FlaskForm):
    project_name = StringField(
        'Project Name', validators=[DataRequired(), Length(min=5, max=100)])
    logo = FileField('Logo', validators=[FileRequired(),
                     FileAllowed(['jpg', 'png'], 'Images only!')])
    company_full_name = StringField(
        'Company Full Name', validators=[DataRequired(), Length(min=5, max=100)])
    company_short_name = StringField(
        'Company Short Name', validators=[DataRequired(), Length(min=5, max=100)])
    ciso_name = StringField('Name of the CISO / IT Security Manager', validators=[
                            DataRequired(), Length(min=5, max=100)])
    hrman_name = StringField('Name of Hr Manager', validators=[
        DataRequired(), Length(min=5, max=100)])
    itsec_name = StringField('Name of IT Security Department', validators=[
                             DataRequired(), Length(min=2, max=100)])
    ithelp_name = StringField('Name of IT Helpdesk Department', validators=[
                              DataRequired(), Length(min=2, max=100)])
    doc_ref = StringField('Doc ref prefix', validators=[
                          DataRequired(), Length(min=2, max=100)])
    data_author = StringField('Data Author', validators=[
        DataRequired(), Length(min=2, max=100)])
    data_classification = StringField('Data Classification', validators=[
        DataRequired(), Length(min=2, max=100)])
    data_date = StringField('Data Date', validators=[
        DataRequired(), Length(min=2, max=100)])
    data_owner = StringField('Data Owner', validators=[
        DataRequired(), Length(min=2, max=100)])
    submit = SubmitField('Build!')
