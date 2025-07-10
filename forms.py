from flask_wtf import FlaskForm
from wtforms import PasswordField, validators, SubmitField


class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('Current Password', validators=[
        validators.DataRequired(),
        validators.Length(min=6)
    ])
    new_password = PasswordField('New Password', validators=[
        validators.DataRequired(),
        validators.Length(min=8),
        validators.EqualTo('confirm_password', message='Passwords must match')
    ])
    confirm_password = PasswordField('Confirm New Password')
    submit = SubmitField('Change Password')