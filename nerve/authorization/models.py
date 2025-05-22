from django.db import models
from django.contrib.auth.models import User 
# Create your models here.

class UserDetails(models.Model):
    username=models.ForeignKey(User,on_delete=models.CASCADE)
    email=models.EmailField(max_length=200)
    created_on=models.DateTimeField(auto_now_add=True)
    updated_on=models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.username  