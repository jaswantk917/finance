import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    user = session["user_id"]
    # shares
    rows = db.execute("SELECT * FROM user_stocks WHERE user_id = ? AND amount > 0", user)
    total = 0
    for row in rows:
        price = lookup(row["stock_symbol"])
        row["price"] = price["price"]
        total+=row["price"]*row["amount"]

    # their balance
    
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    print(rows, flush=True)


    return render_template("index.html", stocks=rows, cash=cash, usd=usd, total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy_form.html")
    else :
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Symbol is required")
        shares = request.form.get("shares")
        if not shares:
            return apology("Number of shares is required")
        try:
            shares = int(shares)

        except ValueError:
            return apology("Invalid input for conversion to int")
        if shares < 1:
            return apology("Number of shares should be positive")
        # symbol
        x = lookup(symbol)
        if not x:
            apology("Symbol not found")
        price = x["price"]*shares


        # their balance
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]


        if price>cash:
            return apology("Can't afford")

        # begin transaction
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash-price, session["user_id"])
        # check if already exists
        rows = db.execute("SELECT amount FROM user_stocks WHERE user_id = ? AND stock_symbol = ?", session["user_id"], x["symbol"])
        if len(rows) == 0:
            db.execute("INSERT INTO user_stocks (user_id, amount, stock_symbol) VALUES (?, ?, ?)", session["user_id"], shares, x["symbol"])
        else:
            db.execute("UPDATE user_stocks SET amount = ? WHERE user_id = ? AND stock_symbol = ?", shares+ rows[0]["amount"], session["user_id"], x["symbol"])
        db.execute("INSERT INTO transactions (user_id, stock_symbol, transaction_amount, transaction_price, transaction_type) VALUES (?, ?, ?, ?, ?)", session["user_id"], x["symbol"],  shares, x["price"], "BUY")
        return redirect("/")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    userid = session["user_id"]
    # Query database for username
    rows = db.execute("SELECT * FROM transactions WHERE user_id = ? ORDER BY transaction_date DESC", userid)

    return render_template("history.html", transactions=rows)
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote_form.html")
    else:
        stock = request.form.get("symbol")
        if not stock:
            return apology("Enter a stock name to search")
        x = lookup(stock)
        if not x:
            return apology("Symbol not found")
        return render_template("quoted.html", stock=x, usd=usd)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        # Get username from request
        user = request.form.get("username")
        if not user:
            return apology("username required")

        # Get password from the request
        password = request.form.get("password")
        if not password:
            return apology("password required")
        if  password!= request.form.get("confirm"):
            return apology("password should match")

        # Ensure username doesn't exists
        rows = db.execute("SELECT * FROM users WHERE username = ?", user)
        if len(rows) != 0:
            return apology("user already exists", 409)

        # Insert into the table
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", user, generate_password_hash(password=password))
        user_id = db.execute("SELECT id FROM users WHERE username = ?", user)[0]["id"]

        # Remember which user has logged in
        session["user_id"] = user_id

        # Redirect user to home page
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "GET":
        user = session["user_id"]
        # shares
        rows = db.execute("SELECT * FROM user_stocks WHERE user_id = ? AND amount > 0", user)

        return render_template("sell_form.html", stocks=rows)
    else:
        user = session["user_id"]
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Symbol is required")
        shares = request.form.get("shares")
        if not shares:
            return apology("Number of shares is required")
        try:
            shares = int(shares)

        except ValueError:
            return apology("Invalid input for conversion to int")
        if shares < 1:
            return apology("Number of shares should be positive")
        print(symbol, flush=True)
        # symbol
        x = lookup(symbol)
        if not x:
            return apology("Invalid symbol")
        rows = db.execute("SELECT amount FROM user_stocks WHERE user_id = ? AND amount > 0 AND stock_symbol = ?", user, symbol)
        if len(rows) == 0:
            apology("You don't have enough stocks")
        if len(rows) > 0:
            apology("We have something wrong")

        amount = rows[0]["amount"]

        if amount<shares:
            return apology("You don't have enough stocks")
        price = x["price"]*shares
        # begin transaction
        cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash+price, session["user_id"])
        # check if already exists
        rows = db.execute("SELECT amount FROM user_stocks WHERE user_id = ? AND stock_symbol = ?", session["user_id"], symbol)

        db.execute("UPDATE user_stocks SET amount = ? WHERE user_id = ? AND stock_symbol = ?",  rows[0]["amount"]-shares, session["user_id"], symbol)
        db.execute("INSERT INTO transactions (user_id, stock_symbol, transaction_amount, transaction_price, transaction_type) VALUES (?, ?, ?, ?, ?)", session["user_id"], symbol, -1 * shares, x["price"], "SELL")
        return redirect("/")

