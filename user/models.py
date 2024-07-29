from django.contrib.auth.models import AbstractUser
from django.db import models


class CustomUser(AbstractUser):
    DoesNotExist = None
    email = models.EmailField(unique=True)

    def __str__(self):
        return self.username