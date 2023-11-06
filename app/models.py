from django.db import models
from django.contrib.auth.models import User


class TodoUserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    password1 = models.CharField(max_length=100, blank=True)
   
       


class Message(models.Model):
    content = models.TextField()
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    receiver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.receiver.username

