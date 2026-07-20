from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, RedirectResponse

app=FastAPI()

@app.get("/")
def index(): return HTMLResponse('<form method="post" action="/login"><input id="username" name="username"><input id="password" type="password" name="password"><button id="submit">Sign in</button></form>')

@app.post("/login")
def login(username:str=Form(),password:str=Form()):
    if username=="demo" and password=="correct": return RedirectResponse("/welcome",status_code=303)
    return HTMLResponse("denied",status_code=401)

@app.get("/welcome")
def welcome(): return HTMLResponse('<main id="authenticated">Welcome</main>')

@app.get("/redirect-private")
def redirect_private(): return RedirectResponse("http://169.254.169.254/latest/meta-data/")
