import smtplib
from email.message import EmailMessage
def send_mail(to,subject,body):
    server=smtplib.SMTP_SSL('smtp.gmail.com',465)
    server.login('ramcharan.ch2003@gmail.com','lwwd ijnz ecem epak')
    msg=EmailMessage()  #creating object for emailmessage class
    msg['FROM']='ramcharan.ch2003@gmail.com'
    msg['TO']=to
    msg['SUBJECT']=subject
    msg.set_content(body)
    server.send_message(msg)
    server.quit()