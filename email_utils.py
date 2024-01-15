import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from . import SMTP_FROM, SMTP_LOGIN, SMTP_PASSWORD

def sendValidationEmail(email, auth_key, url_root):
    msg = MIMEMultipart()
    msg['Subject'] = 'Xancomserver Account Verification'
    msg['From'] = SMTP_FROM
    text = 'Please validate your account by clicking the following link: http://'+ url_root +'/verification?auth_key='+ auth_key
    msg.attach(MIMEText(text,'plain'))
    smtp = smtplib.SMTP('smtp.gmail.com:587')
    smtp.ehlo()
    smtp.starttls()
    smtp.ehlo()
    smtp.login(SMTP_LOGIN,SMTP_PASSWORD)
    smtp.sendmail(SMTP_FROM,email,msg.as_string())
    smtp.quit()

def sendPasswordResetEmail(email, auth_key, url_root):
    msg = MIMEMultipart()
    msg['Subject'] = 'Xancomserver Account Password Reset'
    msg['From'] = SMTP_FROM
    text = 'If you did not request for a new password, you can ignore this email. You can reset your password by following this link: http://'+ url_root +'/reset_password?auth_key='+ auth_key
    msg.attach(MIMEText(text,'plain'))
    smtp = smtplib.SMTP('smtp.gmail.com:587')
    smtp.ehlo()
    smtp.starttls()
    smtp.ehlo()
    smtp.login(SMTP_LOGIN,SMTP_PASSWORD)
    smtp.sendmail(SMTP_FROM,email,msg.as_string())
    smtp.quit()

def sendPrivateKey(email, private_key):
    msg = MIMEMultipart()
    msg['Subject'] = 'Xancomserver Account Password Reset'
    msg['From'] = SMTP_FROM
    text = "You can find attached the private key in OpenSSH format to be used for ssh/sftp connection. <b>Note that the key will be valid for 3 days</b> - after that period you'll need to generate a new key."
    msg.attach(MIMEText(text,'plain'))
    attachment = MIMEText(private_key)
    attachment.add_header('Content-Disposition', 'attachment', filename="rsakey")
    msg.attach(attachment)
    smtp = smtplib.SMTP('smtp.gmail.com:587')
    smtp.ehlo()
    smtp.starttls()
    smtp.ehlo()
    smtp.login(SMTP_LOGIN,SMTP_PASSWORD)
    smtp.sendmail(SMTP_FROM,email,msg.as_string())
    smtp.quit()