from flask import Flask, flash, redirect, render_template, request, session, abort, send_file
import time
import os
 
app = Flask(__name__)
boole = False
 
@app.route('/')
def home():
	return bounce1()

@app.route("/bounce1")
def bounce1():
    return render_template('bounce1.html')

@app.route("/bounce2")
def bounce2():
    global boole
    boole = True 
    return render_template('bounce2.html')

@app.route("/extra")
def extra():
    return render_template('extra1.html')

@app.route("/getTime", methods=['GET'])
def getTime():
    print("browser time: ", request.args.get("time"))
    print("server time : ", time.strftime('%A %B, %d %Y %H:%M:%S'));
    global boole
    return return_files_tut(boole)

@app.route('/redirect')
def hello():
    return redirect('foo.html')

@app.route('/foo')
def foo():
    return 'Hello Foo!'

@app.route('/download-pdf')
def return_files_tut(check):
	try:
		if check:
			print os.path.dirname(os.path.abspath(__file__))
			path = os.path.dirname(os.path.abspath(__file__)) + '/var/www/cprogram.zip'
			return send_file(path, attachment_filename='cprogram.zip')
		else:
			return "FAILED"	
	except Exception as e:
		return str(e)

if __name__ == "__main__":
    app.secret_key = os.urandom(12)
    app.run(debug=True,host='0.0.0.0', port=4000)
