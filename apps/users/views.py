from django.utils import timezone
from rest_framework import status
from rest_framework.exceptions import ValidationError
from rest_framework.generics import CreateAPIView, UpdateAPIView,GenericAPIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken

from utils.tools import send_mail

from .models import User
from .serializers import (LogoutSerializer, PasswordChangeSerializer,
                          PasswordResetSerializer,
                          PasswordResetVerifySerializer, SignUpSerializer)


class LogoutView(GenericAPIView):
    serializer_class = LogoutSerializer
    permission_classes = (IsAuthenticated, )

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=self.request.data)
        serializer.is_valid(raise_exception=True)
        try:
            refresh_token = self.request.data['refresh']
            token = RefreshToken(refresh_token)
            token.blacklist()
            data = {
                'success': True,
                "message": "You are logged out"
            }
            return Response(data=data, status=status.HTTP_205_RESET_CONTENT)
        except TokenError:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class SignUpApiView(CreateAPIView):
    queryset = User.objects.all()
    serializer_class = SignUpSerializer


class VerifyAPIView(GenericAPIView):
    permission_classes = (IsAuthenticated, )

    def post(self, request, *args, **kwargs):
        user, code = self.request.user, self.request.data.get("code", None)
        self.check_verify(user, code)
        return Response(
            data={
                "success": True,
                "email": user.email,
                "access": user.get_tokens()["access"],
                "refresh": user.get_tokens()["refresh"]
            }, status=200)

    def check_verify(self, user, code):
        if not code:
            raise ValidationError(
                {
                    "success": False,
                    'message': "code kiritilmagan",
                }
            )
        verifies = user.verify_codes.filter(
            expiration_time__gte=timezone.now(), code=code, is_confirmed=False)
        if not verifies.exists():
            data = {
                'message': "Code is incorrect or expired"
            }
            raise ValidationError(data)
        verifies.update(is_confirmed=True)
        user.email_verified = True
        user.save()
        return True


class NewVerifyCode(GenericAPIView):
    permission_classes = (IsAuthenticated,)

    def get(self, request, *args, **kwargs):
        user = self.request.user

        if user.email_verified:
            raise ValidationError({
                "success": False,
                "message": "Email already verified"
            })
        codes = user.verify_codes.filter(user=user)
        if codes:
            codes.delete()
        code = user.create_code()
        email = user.email
        send_mail(email, code)
        return Response(
            {
                "success": True
            }
        )


# password reset qismi
class PasswordResetApiView(GenericAPIView):
    serializer_class = PasswordResetSerializer

    def post(self, request, *args, **kwargs):
        serializer = PasswordResetSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data.get("email")
        user = User.objects.get(email=email)
        code = user.create_reset_code()
        send_mail(email, code)
        return Response(
            {
                "success": True
            }
        )

# codeni tekshirish


class PasswordResetCodeVerifyAPIView(GenericAPIView):
    serializer_class = PasswordResetVerifySerializer

    def post(self, request, *args, **kwargs):
        serializer = PasswordResetVerifySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        key = serializer.validated_data["key"]
        return Response(
            data={
                "success": True,
                "message": "Code verified",
                'key': key
            }, status=200)

# yangi parol o'rnatish


class PasswordChangeAPIView(GenericAPIView):
    serializer_class = PasswordChangeSerializer

    def post(self, request, *args, **kwargs):
        serializer = PasswordChangeSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email, key = serializer.validated_data.get(
            "email"), serializer.validated_data.get("key")
        new_password = serializer.validated_data.get("password")

        user = User.objects.get(email=email)
        user.set_password(new_password)
        user.save()
        user.delete_reset_codes()
        return Response(
            data={
                "success": True,
                "message": "Password succesfully changed",
            }, status=200)
