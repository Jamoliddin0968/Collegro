from django.urls import path

from .views import (NewVerifyCode, PasswordResetApiView,
                    PasswordResetCodeVerifyAPIView, SignUpApiView,
                    VerifyAPIView,PasswordChangeAPIView,LogoutView)


from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)


urlpatterns = [
    path("sign_up/", SignUpApiView.as_view()),
    path("sign_up/verify_code/", VerifyAPIView.as_view()),
    path("sign_up/new_code/", NewVerifyCode.as_view()),
    path('password_reset/', PasswordResetApiView.as_view()),
    path('password_reset/verify_code/', PasswordResetCodeVerifyAPIView.as_view()),
    path('password_reset/new_password/',PasswordChangeAPIView.as_view()),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('login/',TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('logout/',LogoutView.as_view())
]
