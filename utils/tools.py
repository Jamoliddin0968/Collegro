from django.core.mail import EmailMessage
from threading import Thread
from rest_framework.exceptions import ValidationError
def send_mail(email,code):
    try:
        email = EmailMessage('Collegro.uz', f'Your code is - {code}',
                            to=[email,])
        email.send()
    except:
        print(code)
        raise ValidationError({
            "success": False,
            "message": "Error has occured send email"
        })
        
