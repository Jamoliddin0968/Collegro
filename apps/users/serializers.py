from django.utils import timezone
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from django.contrib.auth import authenticate
from utils.tools import send_mail
from rest_framework_simplejwt.serializers import TokenObtainSerializer
from .models import User


class PasswordResetSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    def validate(self, attrs):
        super(PasswordResetSerializer, self).validate(attrs)
        email  = attrs.get("email")
        users = User.objects.filter(email=email)
        if not users.exists():
            raise ValidationError({
                "succes": False,
                "message": "Email not found"
            })
        return attrs

class SignUpSerializer(serializers.ModelSerializer):
    
    class Meta:
        fields = ("first_name","last_name","email","username","password")
        model = User
          
    def create(self, validated_data):
        obj=super(SignUpSerializer,self).create(validated_data)
        password = validated_data.get("password")
        email = validated_data.get("email")
        obj.set_password(password)
        code = obj.create_code()
        send_mail(email=email,code=code)
        return obj
    
    def to_representation(self, instance):
        data = super(SignUpSerializer, self).to_representation(instance)
        data.pop("password")
        data.update(instance.get_tokens())
        return data
      
class PasswordResetVerifySerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)
    code = serializers.CharField(required=True)
    
    def validate(self, attrs):
        super(PasswordResetVerifySerializer, self).validate(attrs)
        email, code = attrs.get("email"), attrs.get("code")
        users = User.objects.filter(email=email)
        if not users.exists():
            raise ValidationError({
                "succes": False,
                "message": "Email not found"
            })

        user = users.first()
        verifies = user.password_reset_codes.filter(
            expiration_time__gte=timezone.now(), user=user, code=code, is_confirmed=False)
        if not verifies.exists():
            data = {
                "success": False,
                'message': "Code is incorrect or expired"
            }
            raise ValidationError(data)
        verifies.update(is_confirmed=True)
        key = user.password_reset_codes.filter(
            expiration_time__gte=timezone.now(), user=user, code=code).first().key

        attrs["key"]=key
        return attrs
    
class PasswordChangeSerializer(serializers.Serializer):
    key = serializers.CharField(max_length = 40,required=True)    
    email = serializers.EmailField(required=True)
    password = serializers.CharField(required=True)
        
    def validate(self, attrs):
        super(PasswordChangeSerializer, self).validate(attrs)
        key,email = attrs.get("key"),attrs.get("email")
        user = User.objects.filter(email=email)
        if not user.exists():
            raise ValidationError({
                "success":False,
                "message":"Email not found"
            })
        user = user.first()
        verifies = user.password_reset_codes.filter(user=user,key=key, is_confirmed=True)
        if not verifies.exists():
             raise ValidationError({
                "success":False,
                "message":"Email or secret key not valid"
            })    
        return attrs
    
    
class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()
   
    
