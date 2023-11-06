from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.forms import AuthenticationForm, User
from captcha.fields import ReCaptchaField




class CustomLoginForm(AuthenticationForm):
    captcha = ReCaptchaField()
    class Meta:
        model = User
        fields = ('username', 'password','captcha')