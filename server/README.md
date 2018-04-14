Env: ubuntu 14.04, python 2.7.4, flask 0.12.2

Don't need to copy files anywhere, just keep them in the same folder as pyserver and run python pyserver.py to start the server. 
It will connect to port 4000.

On the client side, access using server’s ip:port in the browser

The server will first connect to bounce1 (200) -> it will then tell the client to connect to bounce2 (200) -> it will then ask for the browser time (after getting the time, the server will send the pdf file to the client) and ask client to connect to extra (200) -> extra will redirect client to foo (302) -> but foo doesn’t exist (404)   

The goal will be to receive the pdf file. 
Useless connections are extra and foo. Bounce1 is not needed to retrieve pdf too

