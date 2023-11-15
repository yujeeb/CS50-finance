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

    total = 0
    history =[]
    stocks_history = db.execute(
        "SELECT symbol, symbol as name, SUM(shares) as shares, AVG(price) as price FROM (SELECT * FROM history WHERE user_id = ?) GROUP BY symbol",
        session["user_id"],
    )

    for i in range(len(stocks_history)):
        if stocks_history[i]["shares"] > 0:
            stocks_history[i]["total"] = (
                stocks_history[i]["shares"] * stocks_history[i]["price"]
            )
            total += stocks_history[i]["total"]
            history.append(stocks_history[i])

    cash_available = db.execute(
        "SELECT cash FROM users WHERE id = ?", session["user_id"]
    )[0]["cash"]
    total += cash_available

    return render_template(
        "index.html", stocks=history, cash=cash_available, total=total
    )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must type in a stock symbol", 403)

        elif not lookup(request.form.get("symbol").strip()):
            return apology("Symbol does not exist")

        elif not request.form.get("shares").isdigit():
            return apology("Enter an integer", 400)

        elif int(request.form.get("shares")) < 1:
            return apology("Please enter a value greater than 0", 400)

        cash_available = db.execute(
            "SELECT cash FROM users WHERE id = ?", session["user_id"]
        )[0]["cash"]
        stock = lookup(request.form.get("symbol").strip())
        transaction_value = stock["price"] * int(request.form.get("shares"))
        new_cash_total = cash_available - transaction_value

        if cash_available < transaction_value:
            return apology("Cash not enough", 403)

        else:
            db.execute(
                "UPDATE users SET cash = ? WHERE id = ?",
                new_cash_total,
                session["user_id"],
            )
            db.execute(
                "INSERT INTO history (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
                session["user_id"],
                stock["symbol"],
                request.form.get("shares"),
                stock["price"],
            )

        return redirect("/")

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    transactions = db.execute(
        "SELECT symbol, shares, price, transacted FROM history WHERE user_id = ? ORDER BY transacted DESC",
        session["user_id"],
    )

    for record in transactions:
        record["price"] = float(record["price"])

    return render_template("history.html", history=transactions)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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

    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("must type a symbol", 400)

        symbol = request.form.get("symbol")

        stock = lookup(symbol)

        if not stock:
            return apology("Invalid symbol", 400)

        return render_template(
            "quoted.html",
            name=stock["name"],
            price=stock["price"],
            symbol=stock["symbol"],
        )

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted or username does not exist
        if not request.form.get("username"):
            return apology("must provide username", 400)

        elif db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        ):
            return apology("username already taken", 400)

        elif not request.form.get("password"):
            return apology("must provide password", 400)

        elif not request.form.get("confirmation"):
            return apology("must confirm the password", 400)

        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("passwords do not match", 400)

        db.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)",
            request.form.get("username"),
            generate_password_hash(request.form.get("password")),
        )

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    symbols = db.execute(
        "SELECT DISTINCT symbol FROM history WHERE user_id = ?", session["user_id"]
    )
    symbols_list = []

    shares_available = db.execute(
        "SELECT symbol, SUM(shares) as shares FROM (SELECT * FROM history WHERE user_id = ?) GROUP BY symbol",
        session["user_id"],
    )
    shares_dict = {}

    for i in range(len(shares_available)):
        shares_dict[shares_available[i]["symbol"]] = shares_available[i]["shares"]

    for symbol in symbols:
        if int(shares_dict[symbol["symbol"]]) > 0:
            symbols_list.append(symbol["symbol"])

    if request.method == "POST":
        user_id = session["user_id"]
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))
        price = db.execute(
            "SELECT symbol, AVG(price) as price FROM (SELECT * FROM history WHERE user_id = ?) GROUP BY symbol",
            session["user_id"],
        )

        if not request.form.get("symbol"):
            return apology("Select a Stock symbol", 403)

        elif not request.form.get("symbol") in symbols_list:
            return apology("You do not own the selected Stock", 403)

        elif not request.form.get("shares") or not int(request.form.get("shares")) > 0:
            return apology("Enter a number greater than 0", 400)

        elif (
            not int(request.form.get("shares"))
            <= shares_dict[request.form.get("symbol")]
        ):
            return apology(
                "Entered number of shares not available in your account", 400
            )

        for i in range(len(symbols)):
            if price[i]["symbol"] == symbol:
                price = db.execute(
                    "SELECT symbol, AVG(price) as price FROM (SELECT * FROM history WHERE user_id = ?) GROUP BY symbol",
                    session["user_id"],
                )[i]["price"]
                break

        cash_available = db.execute(
            "SELECT cash FROM users WHERE id = ?", session["user_id"]
        )[0]["cash"]
        new_cash_total = cash_available + (shares * price)

        db.execute(
            "UPDATE users SET cash = ? WHERE id = ?", new_cash_total, session["user_id"]
        )
        db.execute(
            "INSERT INTO history (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)",
            user_id,
            symbol,
            -1 * shares,
            price,
        )

        return redirect("/")

    else:
        return render_template("sell.html", symbols=symbols_list)


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    """Change password"""

    if request.method == "POST":
        user_info = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[
            0
        ]

        if not request.form.get("current_password"):
            return apology("Enter current password", 403)

        elif not request.form.get("new_password"):
            return apology("Enter a new password", 403)

        elif request.form.get("current_password") == request.form.get("new_password"):
            return apology("Enter a different password", 403)

        elif not request.form.get("confirm"):
            return apology("Confirm the password", 403)

        elif request.form.get("new_password") != request.form.get("confirm"):
            return apology("Passwords do not match", 403)

        elif not check_password_hash(
            user_info["hash"], request.form.get("current_password")
        ):
            return apology("Enter correct password", 403)

        hash = generate_password_hash(request.form.get("new_password"))

        db.execute("UPDATE users SET hash = ? WHERE id = ?", hash, session["user_id"])

        session.clear()

        return redirect("/login")

    else:
        return render_template("change_password.html")
