from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError, Optional
from user_model import User

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_email(self, email):
        user = User.get_by_email(email.data)
        if user:
            raise ValidationError('Email already registered.')

class ProfileForm(FlaskForm):
    abuseipdb_api_key = StringField('ABUSEIPDB_API_KEY', validators=[Optional(), Length(max=200)])
    virustotal_api_key = StringField('VIRUSTOTAL_API_KEY', validators=[Optional(), Length(max=200)])
    shodan_api_key = StringField('SHODAN_API_KEY', validators=[Optional(), Length(max=200)])
    ipqualityscore_api_key = StringField('IPQUALITYSCORE_API_KEY', validators=[Optional(), Length(max=200)])
    save_api_keys = SubmitField('Enregistrer les clés API')
    regenerate_api_key = SubmitField('Regénérer la clé API')
