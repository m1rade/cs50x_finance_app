import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


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

    user_id = session["user_id"]
    deals_rows = db.execute("SELECT symbol, stock, price, SUM(quantity) AS quantity, SUM(total_price) AS total_price FROM deals WHERE user_id = ? GROUP BY symbol HAVING SUM(quantity) > 0 ORDER BY id", user_id)
    cash = float(db.execute("SELECT cash FROM users WHERE id = ?", user_id)[0]["cash"])

    if not deals_rows:
        # if user hasn't got stocks show current cash balance
        return render_template("index.html", money=cash)
    # if user has stocks
    else:
        # add summary of total price of all stocks to current user's money on account
        summary = cash
        for deals_row in deals_rows:
            summary += deals_row["total_price"]

        return render_template("index.html", rows=deals_rows, cash=cash, sum=summary)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    user_id = session["user_id"]
    if request.method == "POST":
        # Get user input
        symbol = request.form.get("symbol").upper()
        shares = request.form.get("shares")

        # Validate user's input
        if not symbol:
            return apology("must provide symbol", 400)
        elif not shares:
            return apology("must provide quantity", 400)
        elif not shares.isdigit():
            return apology("invalid quantity", 400)
        # convert input as the request method returns str
        shares = float(shares)
        if shares < 0:
            return apology("invalid quantity", 400)

        # Search quote in database
        stock = lookup(symbol)
        if stock == None:
            return render_template("buy.html", message="Not found")

        user_cash = db.execute("SELECT cash FROM users WHERE id == ?", user_id)[0]["cash"]

        # Calculate total price
        total_price = stock["price"] * shares

        # Render apology if user cannot afford stock
        if total_price > user_cash:
            return apology("Not enough money!")

        # Save a transaction in database
        db.execute("BEGIN TRANSACTION")
        db.execute("INSERT INTO deals (symbol, stock, price, quantity, total_price, status, user_id, date) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))", symbol, stock["name"], stock["price"], shares, total_price, "purchase", user_id)

        # Update user's cash
        new_cash = user_cash - total_price
        db.execute("UPDATE users SET cash = ? WHERE id = ?", new_cash, user_id)
        db.execute("COMMIT")

        flash("Bought successfully")
        return redirect("/")

    else:
        # display form to buy stocks
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    history_rows = db.execute("SELECT * FROM deals WHERE user_id = ? ORDER BY date", session["user_id"])
    return render_template("history.html", rows=history_rows)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        flash("You were successfully logged in")
        return redirect("/")

    # User reached route via GET
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
    if request.method == "POST":
        # Get user input
        symbol = request.form.get("symbol").upper()

        if not symbol:
            return apology("Missing symbol", 400)

        # Search stock in database
        stock_quote = lookup(symbol)

        if stock_quote is not None:
            return render_template("quote.html", stock_quote=stock_quote)

        # if lookup was unsuccessful
        return render_template("quote.html", message="Not found")
    # GET
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        conf_pass = request.form.get("confirmation")

        # Ensure that any input field isn't left blank
        if not username:
            return apology("must provide username", 400)
        elif not password:
            return apology("must provide password", 400)
        elif len(password) != 4:
            return apology("password must be min 4 characters long", 400)
        elif not conf_pass:
            return apology("must confirm password", 400)
        # Ensure that passwords match
        elif password != conf_pass:
            return apology("password doesn't match", 400)
        # Ensure that username is unique
        try:
            # Store user's input in database and log in a new account
            session["user_id"] = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, generate_password_hash(password, method='pbkdf2:sha256', salt_length=4))
        except:
            return apology("this username was already taken", 400)

        # Redirect user to home page
        flash("You were registered!")
        return redirect("/")
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    owned_stocks = {}

    user_id = session["user_id"]

    owned_stocks_db = db.execute("SELECT symbol, SUM(quantity) AS quantity FROM deals WHERE user_id = ? GROUP BY symbol HAVING SUM(quantity) > 0", user_id)

    # save stocks that user owns and its amount in a dict to simplify access to them

    for i in range(len(owned_stocks_db)):
        owned_stocks[owned_stocks_db[i]["symbol"]] = owned_stocks_db[i]["quantity"]

    if request.method == "POST":
        selected_symbol = request.form.get("symbol")
        symbols = owned_stocks.keys()
        # error check
        # render an apology if the user fails to select a stock
        if not selected_symbol:
            return apology("Please, select stock symbol", 400)
        elif selected_symbol not in symbols:
            return apology("Invalid stock symbol", 400)

        quantity = int(request.form.get("shares"))
        # check if the user owns that many shares of the stock
        if quantity > owned_stocks[selected_symbol]:
            return apology("Too many shares", 400)

        """ Sell stock """
        # get market price and save data in dict
        stock = lookup(selected_symbol)
        # get stock price
        price = stock["price"]
        # calculate selling price
        total_price = price * quantity

        db.execute("BEGIN TRANSACTION")
        # add revenue to current account cash
        row = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        cash = row[0]["cash"]
        db.execute("UPDATE users SET cash = ? WHERE id = ?", cash + total_price, user_id)
        db.execute("INSERT INTO deals (symbol, stock, price, quantity, total_price, status, user_id, date) VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'))", stock["symbol"], stock["name"], price, (quantity * -1), (total_price * -1), 'sell', user_id)
        db.execute("COMMIT")

        flash("Sold successfully")
        return redirect("/")

    # method GET
    else:
        return render_template("sell.html", owned_stocks=owned_stocks)
