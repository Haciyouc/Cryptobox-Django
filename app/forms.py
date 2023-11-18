from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.forms import AuthenticationForm, User
from .models import *




class CustomLoginForm(AuthenticationForm):
    class Meta:
        model = User
        fields = ('username', 'password')



class MessageForm(forms.ModelForm):
    ENCRYPTION_CHOICES = (
            ('', 'Select an encryption method '),
            ('cesar', 'Ceasar'),
            ('mirror', 'Mirror'),
            ('affine', 'Affine'),
            ('shift', 'Shift Right/Left'),
    )

    encryption_method = forms.ChoiceField(
        label="Encryption method :",
        choices=ENCRYPTION_CHOICES,
    )
    encryption_key = forms.IntegerField(label="Key a ",required=False)
    encryptionb_key= forms.IntegerField(label="Key b ",required=False)
    encryption_direction = forms.ChoiceField(
        choices=[('left', 'Left'), ('right', 'Right')],
        required=False
    )
    content=forms.CharField(widget=forms.Textarea(attrs={'class': 'custom-class-5'}))  # Exemple pour le champ 'content'

    class Meta:
        model = Message
        fields = ['receiver', 'encryption_method', 'encryption_key','encryptionb_key' ,'encryption_direction','content']
