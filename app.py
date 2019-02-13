from flask import Flask,render_template,url_for,request,redirect,flash,session,logging
from wtforms import Form,StringField,PasswordField,validators
from flask_mysqldb import MySQL
from functools import wraps
from passlib.hash import sha256_crypt

app=Flask(__name__)
app.secret_key = '_5#y2L"F4Q8z\n\xec]/'


#config mysql
mysql=MySQL()
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'password123'
app.config['MYSQL_DB'] = 'connection_flask_db'
app.config['MYSQL_HOST'] = 'localhost'
app.config["MYSQL_CURSORCLASS"]="DictCursor"
mysql=MySQL(app)





@app.route("/")
def root():
    return render_template("index.html")




class RegisterForm(Form):
    username=StringField("username",[validators.length(min=3),validators.DataRequired()])
    name = StringField("name", [validators.length(min=3)])
    password=PasswordField("password",[validators.length(min=3),validators.DataRequired(),
                                       validators.EqualTo("confirm")])
    email = StringField("email", [validators.length(min=3)])
    confirm=PasswordField("password confirm",[validators.DataRequired()])


#user register
@app.route("/register",methods=["GET","POST"])
def register():
    form =RegisterForm(request.form)
    if request.method=="POST" and form.validate():
        name=form.name.data
        email=form.email.data
        username=form.username.data
        password=sha256_crypt.encrypt(str(form.password.data))

        #create a cursor
        cur=mysql.connection.cursor()

        #execute query
        cur.execute("INSERT INTO example(username,name,email,password) VALUES(%s,%s,%s,%s)",[username,name,email,password])

        #Commit to DB
        mysql.connection.commit()

        #Colse connection
        cur.close()

        flash("you are now registered and can log in","success")
        return redirect(url_for("root"))

    return render_template("register.html",form=form)




class LoginForm(Form):
    email=StringField("email")
    password=PasswordField("password")


@app.route("/login",methods=["GET","POST"])
def login():
    form=LoginForm(request.form)
    if request.method=="POST" and form.validate():
        email=form.email.data
        password=form.password.data

        #inizializzo il db
        cur=mysql.connection.cursor()
        result=cur.execute("select email,password,username from example where email=%s",[email])



        if result>0:
            data=cur.fetchone()
            password_db=data["password"]


            #comparazione password
            if sha256_crypt.verify(password,password_db):
                #accesso effettuato, l utente e' in sessione
                session['logged_in']=True
                session['username']=data["username"]
                flash("accesso riuscito","success")
                return redirect(url_for("dashboard",nome=data["username"]))

            else:
                flash("invalid login ","danger")
                return render_template("login.html")

            cur.close()

        else:
            flash("email invalid","danger")
            return render_template("login.html")

    return render_template("login.html")


#check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args,**kwargs):
        if"logged_in" in session:
            return f(*args,**kwargs)
        else:
            flash("unauthorized,Please log in","danger")
            return redirect(url_for("login"))
    return wrap


#logout
@app.route("/logout")
@is_logged_in
def log_out():
    session.clear()
    flash("now you are logged_out")
    return redirect(url_for("root"))





@app.route("/dashboard/<string:nome>")
@is_logged_in
def dashboard(nome):
    return render_template("dashboard.html",nome=nome)




if __name__=="__main__":
    app.run(debug=True)
