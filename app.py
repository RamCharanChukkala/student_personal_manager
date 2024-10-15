from flask import Flask,redirect,url_for,render_template,request,flash,session,send_file
from flask_session import Session
from otp import genotp
import mysql.connector
import bcrypt 
import re
from stoken import token,dtoken
from send_mail import send_mail
from io import BytesIO
import flask_excel as excel
app=Flask(__name__)
app.config['SESSION_TYPE']='filesystem'
excel.init_excel(app)
app.secret_key=b'\xb5\x05\xc0\xddZ'
mydb=mysql.connector.connect(host='localhost',user='root',password='1234',db='spm')
Session(app)
@app.route('/')
def home():
        return render_template('welcome.html')
@app.route('/register',methods=['GET','POST'])
def register():
        if request.method=='POST':
                stu_fname=request.form['s_fname']
                stu_lname=request.form['s_lname']
                email=request.form['email']
                password=request.form['password']
                cursor=mydb.cursor(buffered=True)
                cursor.execute('select count(*) from user where email=%s',[email])
                count=cursor.fetchone()
                print(count)
                if count[0]==0:
                        otp=genotp()
                        data={'otp':otp,'stu_fname':stu_fname,'stu_lname':stu_lname,'email':email,'password':password}
                        subject='Verification for SPM Application'
                        body=f'otp for your spm application. {otp}'
                        send_mail(to=email,subject=subject,body=body)
                        flash('OTP has sent to Your Mail')
                        return redirect(url_for('userverify',userdata=token(data=data)))
                elif count[0]==1:
                        flash(f'Email already existed')
                        return redirect(url_for('home'))
                else:
                        return 'something went wrong'
        return render_template('register.html')
@app.route('/userverify/<userdata>',methods=['GET','POST'])
def userverify(userdata):
        try:
               data=dtoken(data=userdata)
        except Exception as e:
               print(e)
               return 'something wrong'
        else:
                if request.method=='POST':
                        uotp=request.form['otp']
                        if data['otp']==uotp:
                                bytes = data['password'].encode('utf-8')
                                salt = bcrypt.gensalt() 
                                hash = bcrypt.hashpw(bytes, salt) 
                                print(hash)
                                cursor=mydb.cursor(buffered=True)
                                cursor.execute('insert into user(user_lname,user_fname,email,password) values(%s,%s,%s,%s)',[data['stu_lname'],data['stu_fname'],data['email'],hash])
                                mydb.commit()
                                cursor.close()
                                flash('registration created Successfully')
                                return redirect(url_for('login'))
                        else:
                                flash('invalied otp')
                                return redirect(url_for('home'))
        return render_template('userotp.html')
@app.route("/login",methods=['GET','POST'])
def login():
        if session.get('username'):
                return redirect(url_for('panel'))
        if request.method=='POST':
                email=request.form['email']
                password=request.form['password']
                userpassword=password.encode('utf-8')
                cursor=mydb.cursor(buffered=True)
                cursor.execute('select email,password from user where email=%s',[email])
                count=cursor.fetchone()
                if count:
                        print(count[1])
                        if bcrypt.checkpw(userpassword, count[1]):
                                session['username']=email
                                if not session.get(email):
                                        session[email]={}
                                return redirect(url_for('panel'))
                        else:

                                return 'password wrong'
                else:
                        return 'email wrong'
        return render_template('login.html')
@app.route("/panel")
def panel():
            if session.get('username'): 
                print(session)
                return render_template('panel.html')
            else:
                return redirect(url_for('login'))
@app.route("/logout")
def logout():
        if session.get('username'):
                session.pop('username')
                return redirect(url_for('home'))
        else:
                return redirect(url_for('login'))
@app.route("/addnotes",methods=['GET','POST'])
def addnotes():
        if request.method=='POST':
                title=request.form['title']
                content=request.form['content']
                cursor=mydb.cursor(buffered=True)
                cursor.execute('select user_id from user where email=%s',[session.get('username')])
                data=cursor.fetchone()
                if data:
                        try:
                                uid=data[0]
                                cursor.execute('insert into notes(title,content,added_by) values(%s,%s,%s)',[title,content,uid])
                                mydb.commit()
                                cursor.close
                        except Exception as e:
                                print(e)
                        else:
                                flash(f'notes {title} added succesfully')
                                return redirect(url_for('panel'))
        return render_template('addnotes.html')
@app.route("/viewallnotes",methods=['GET','POST'])
def viewallnotes():
        if not session.get('username'):
                return redirect(url_for('login'))
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select user_id from user where email=%s',[session.get('username')])
        data=cursor.fetchone()
        if data:
                try:
                        uid=data[0]
                        cursor.execute('select notes_id,title,created_at from notes where added_by=%s',[uid])
                        allnotes=cursor.fetchall()
                        print(allnotes)
                        if allnotes:
                                return render_template('viewallnotes.html',allnotes=allnotes)
                except Exception as e:
                        print(e)
                        return 'something went wrong'
        return 'user_id not found'
@app.route("/view_note/<nid>")
def view_note(nid):
        if not session.get('username'):
                return redirect(url_for('login'))
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select user_id from user where email=%s',[session.get('username')])
        data=cursor.fetchone()
        if data:
                uid=data[0]
                cursor.execute('select * from notes where notes_id=%s and added_by=%s',[nid,uid])
                note_data=cursor.fetchone()
                if note_data:
                        return render_template('viewnotes.html',note_data=note_data)
                return 'notes not found'
        return 'userid not found'
@app.route("/deletenotes/<nid>")
def deletenotes(nid):
        if not session.get('username'):
                return redirect(url_for('login'))
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select user_id from user where email=%s',[session.get('username')])
        data=cursor.fetchone()
        if data:
                uid=data[0]
                cursor.execute('delete from notes where notes_id=%s and added_by=%s',[nid,uid])
                mydb.commit()
                cursor.close()
                flash(f'Notes deleted successfully')
                return redirect(url_for('viewallnotes'))
        return 'user_id not found'
@app.route("/updatenotes/<nid>",methods=['GET','POST'])
def updatenotes(nid):
        if not session.get('username'):
                return redirect(url_for('login'))
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select * from notes where notes_id=%s',[nid])
        note_data=cursor.fetchone()
        if request.method=='POST':
                title=request.form['title']
                content=request.form['content']
                cursor.execute('update notes set title=%s,content=%s where notes_id=%s',[title,content,nid])
                mydb.commit()
                cursor.close()
                flash(f'notes {title} updated successfully')
                return redirect(url_for('view_note',nid=nid))
        if note_data:
                return render_template('updatenotes.html',note_data=note_data)
        return 'notes not found'
@app.route('/addfile',methods=['GET','POST'])
def addfile():
    if not session.get('username'):
        return redirect(url_for('login'))
    if request.method=='POST':
        fdata=request.files['file']
        print(fdata)
        file_data=fdata.read()
        file_ext=fdata.filename.split('.')[-1]
        filename=genotp()+'.'+file_ext
        cursor=mydb.cursor(buffered=True)
        cursor.execute('select user_id from user where email=%s',[session.get('username')])
        data=cursor.fetchone()
        if data:
            uid=data[0]
            cursor.execute('insert into upload_files(file_data,filename,added_by) values (%s,%s,%s)',[file_data,filename,uid])
            mydb.commit()
            cursor.close()
            flash(f'file uploaded successfully')
            return redirect(url_for('panel'))
    return render_template('uploadfile.html')
@app.route('/viewall_files')
def viewall_files():
    if not session.get('username'):
        return redirect(url_for('login'))
    cursor=mydb.cursor(buffered=True)
    cursor.execute('select user_id from user where email=%s',[session.get('username')])
    data=cursor.fetchone()
    if data:
        uid=data[0]
        cursor.execute('select f_id,filename,created_at from upload_files where added_by=%s',[uid])
        fdata=cursor.fetchall()
        if fdata:
            return render_template('viewallfiles.html',fdata=fdata)
        return "file not found"
    return render_template('viewallfiles.html')
@app.route('/viewfiles/<fid>')
def viewfiles(fid):
    if not session.get('username'):
        return redirect(url_for('login'))
    cursor=mydb.cursor(buffered=True)
    cursor.execute('select filename,file_data from upload_files where f_id=%s',[fid])
    filename,bin_data=cursor.fetchone()
    bytes_data=BytesIO(bin_data)
    return send_file(bytes_data,download_name=filename,as_attachment=False)
@app.route('/downloadfiles/<fid>')
def downloadfiles(fid):
    if not session.get('username'):
        return redirect(url_for('login'))
    cursor=mydb.cursor(buffered=True)
    cursor.execute('select filename,file_data from upload_files where f_id=%s',[fid])
    filename,bin_data=cursor.fetchone()
    bytes_data=BytesIO(bin_data)
    return send_file(bytes_data,download_name=filename,as_attachment=True)
@app.route("/getexceldata")
def getexceldata():
       if session.get('username'):
              user=session.get('username')
              cursor=mydb.cursor(buffered=True)
              cursor.execute('select user_id from user where email=%s',[session.get('username')])
              data=cursor.fetchone()
              if data:
                uid=data[0]
                cursor.execute('select title,content,created_at from notes where added_by=%s',[uid])
                allnotesdata=cursor.fetchall()
                columns=['Title','Content','Created_at']
                array_data=[list(i) for i in allnotesdata]
                array_data.insert(0,columns)
                return excel.make_response_from_array(array_data,'xlsx',filename='notesdata')
       else:
              return redirect(url_for('login'))
@app.route("/search",methods=['GET','POST'])
def search():
        if session.get('username'):
                if request.method=='POST':
                        name=request.form['sname']
                        strg=['A-Za-z0-9']
                        pattren=re.compile(f'^{strg}',re.IGNORECASE)
                        if (pattren.match(name)):
                                cursor=mydb.cursor(buffered=True)
                                cursor.execute('select user_id from user where email=%s',[session.get('username')])
                                data=cursor.fetchone()[0]
                                cursor.execute('select notes_id,title,created_at from notes where added_by=%s and title like %s',[data,name+'%'])
                                sdata=cursor.fetchall()
                                cursor.close()
                                return render_template('panel.html',sdata=sdata)
                        else:
                                return "no search file"
                return render_template("panel")
        else:
              return redirect(url_for('login'))
app.run(debug=True,use_reloader=True)