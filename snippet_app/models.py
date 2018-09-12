from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone

import base64
import os
# Create your models here.


class User(AbstractUser):
    user_id = models.AutoField(primary_key=True)
    username = models.CharField(blank=True, max_length=30)
    email = models.EmailField(blank=True, unique=True)
    password = models.CharField(blank=True, max_length=100)
    join_date = models.DateTimeField(default=timezone.now)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ('username', 'password')

    def __str__(self):
        return str(self.user_id)

class Snippet(models.Model):
    user_id = models.ForeignKey(User, to_field='user_id', on_delete=models.CASCADE)
    snippet_id = models.AutoField(primary_key=True)
    text_snippet = models.TextField(blank=True)
    key = models.CharField(null=True, max_length=100)

    def save(self, *args, **kwargs):
        if self.key:
            enc = []
            for i in range(len(self.text_snippet)):
                key_c = self.key[i % len(self.key)]
                enc_c = chr((ord(self.text_snippet[i]) + ord(key_c)) % 256)
                enc.append(enc_c)
            encoded = base64.urlsafe_b64encode("".join(enc).encode()).decode()
            self.text_snippet = encoded
        super(Snippet, self).save(*args, **kwargs)

    def __str__(self):
        return self.text_snippet
