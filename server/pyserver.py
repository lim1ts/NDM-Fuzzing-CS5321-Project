from flask import Flask, flash, redirect, render_template, request, session, abort, send_file
import time
import os
 
app = Flask(__name__)
 
@app.route('/')
def home():
	return bounce1()

@app.route("/bounce1")
def bounce1():
    return render_template('bounce1.html')

@app.route("/bounce2")
def bounce2():
    return render_template('bounce2.html')

@app.route("/extra")
def extra():
    return render_template('extra1.html')

@app.route("/getTime", methods=['GET'])
def getTime():
    print("browser time: ", request.args.get("time"))
    print("server time : ", time.strftime('%A %B, %d %Y %H:%M:%S'));
    return return_files_tut(True)

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
			return send_file('/home/cs4239/Desktop/var/www/malicious.pdf', attachment_filename='malicious.pdf')
		else:
			return "FAILED"	
	except Exception as e:
		return str(e)

if __name__ == "__main__":
    app.secret_key = os.urandom(12)
    app.run(debug=True,host='0.0.0.0', port=4000)
