import binascii
import os
import random

from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
from rest_framework_simplejwt.tokens import RefreshToken

EMAIL_EXPIRE = 5

class UserConfirmation(models.Model):
    code = models.CharField(max_length=6)
    user = models.ForeignKey('users.User', models.CASCADE, 'verify_codes')
    expiration_time = models.DateTimeField(null=True)
    is_confirmed = models.BooleanField(default=False)
    def __str__(self):
        return str(self.user.__str__())

    def save(self, *args, **kwargs):
        self.expiration_time = timezone.now() + timezone.timedelta(minutes=EMAIL_EXPIRE)
        super(UserConfirmation, self).save(*args, **kwargs)
        
class PasswordResetConfirmation(models.Model):
    code = models.CharField(max_length=6)
    user = models.ForeignKey('users.User', models.CASCADE, 'password_reset_codes')
    key = models.CharField(max_length=40,null=True,blank=True)
    expiration_time = models.DateTimeField(null=True)
    is_confirmed = models.BooleanField(default=False)
    
    def __str__(self):
        return str(self.user.__str__())

    def save(self, *args, **kwargs):
        self.expiration_time = timezone.now() + timezone.timedelta(minutes=EMAIL_EXPIRE)
        self.key = self.generate_key()
        super(PasswordResetConfirmation, self).save(*args, **kwargs)
        
    @classmethod
    def generate_key(cls):
        return binascii.hexlify(os.urandom(20)).decode()
               
class User(AbstractUser):
    avatar = models.ImageField(null=True,blank=True)
    bio = models.CharField(max_length=127,null=True,blank=True)
    country = models.CharField(max_length=127,null=True,blank=True)
    email_verified = models.BooleanField(default=False)
    email = models.EmailField(("email address"),unique=True)
    
    def __str__(self) -> str:
        return self.username
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    
    def create_code(self):
        code = "".join(str(random.randint(0,100)%10) for _ in range(6))
        UserConfirmation.objects.create(
            user=self,
            code=code
        )    
        return code
    
    def create_reset_code(self):
        code = "".join(str(random.randint(0,100)%10) for _ in range(6))
        codes = PasswordResetConfirmation.objects.filter(user=self)
        if codes.exists():
            codes.delete()
        PasswordResetConfirmation.objects.create(
            user=self,
            code=code
        )    
        return code
    
    def delete_reset_codes(self):
        self.password_reset_codes.all().delete()
    def get_tokens(self):
        refresh = RefreshToken.for_user(self)

        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }