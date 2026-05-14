__author__ = "Ben"
import random
import smtplib
import ssl
import uuid
from email.message import EmailMessage
email_sender = "Benbrafman2009@gmail.com"
email_password = 'tsng glhj zkfz ccoa'
subject = 'password for Wordle server By Ben Brafman'
body = 'Hi, your password is: '
security_code = str(uuid.uuid4())
half_length = len(security_code) //2
security_code = security_code[:half_length]
def email_send(email_receiver):
    em = EmailMessage()
    em['from'] = email_sender
    em['To'] = email_receiver
    em['subject'] = subject
    password = gen_password()
    em.set_content(body + str(password))
    contex = ssl.create_default_context()
    with smtplib.SMTP_SSL('smtp.gmail.com',465,context=contex) as smtp:
        smtp.login(email_sender,email_password)
        smtp.sendmail(email_sender,email_receiver,em.as_string())
    return password
def gen_password():
    return random.randint(1000,10000)