from fastapi import FastAPI
from fastapi.responses import RedirectResponse

app = FastAPI()


@app.get("/")
def home():
    return {"message": "Local redirect testing server"}


# Scenario 1: Single redirect
@app.get("/offer")
def offer():
    return RedirectResponse(
        url="/login",
        status_code=302
    )


@app.get("/login")
def login():
    return {"message": "You reached the login endpoint"}


# Scenario 2: Multiple redirects
@app.get("/start")
def start():
    return RedirectResponse(
        url="/middle",
        status_code=301
    )


@app.get("/middle")
def middle():
    return RedirectResponse(
        url="/final",
        status_code=302
    )


@app.get("/final")
def final():
    return {"message": "Final destination reached"}


# Scenario 3: Redirect loop
@app.get("/loop-a")
def loop_a():
    return RedirectResponse(
        url="/loop-b",
        status_code=302
    )


@app.get("/loop-b")
def loop_b():
    return RedirectResponse(
        url="/loop-a",
        status_code=302
    )