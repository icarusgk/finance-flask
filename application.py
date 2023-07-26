from logging import logProcesses, raiseExceptions
import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True


# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")

# Link
# https://cloud.iexapis.com/stable/stock/nflx/quote?token=pk_4a67454c0ad946c08c7a965509df5455


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # Select current user grouping them by stock
    stocks = db.execute(
        'SELECT SUM(shares) AS shares, symbol FROM portfolio GROUP BY symbol HAVING person_id = ?', session['user_id'])
    cash = db.execute('SELECT cash FROM users WHERE id = ?',
                      session['user_id'])
    holdings = 0

    for stock in stocks:
        stock['name'] = lookup(stock['symbol'])['name']
        stock['price'] = lookup(stock['symbol'])['price']
        stock['total'] = float(stock['price'] * stock['shares'])
        holdings += stock['total']

    total = cash[0]['cash'] + holdings

    return render_template('portfolio.html', stocks=stocks, cash=cash[0]['cash'], total=total)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'POST':
        symbol = request.form.get('symbol')
        shares = request.form.get('shares')

        # Error checking
        if not symbol and not shares:
            return apology('Please fill out the form.')

        if not symbol:
            return apology('Enter a valid symbol.')

        if not shares:
            return apology('Enter a valid ammount of shares')

        if lookup(symbol) == None:
            return apology('This symbol doesn\'t exists')

        try:
            f_shares = int(shares)
        except ValueError:
            return apology('Enter a valid number of shares')

        if f_shares <= 0:
            return apology('Shares must be a positive number')

        # Lookup the stock price
        stock = lookup(symbol)

        # Check if the user can afford it
        rows = db.execute(
            'SELECT cash FROM users WHERE id = ?', session["user_id"])
        cash = rows[0]['cash']

        # Total price of the stocks a user wants to buy
        total = stock['price'] * f_shares
        # Buy the stock
        if cash > total:
            # Buy it

            # Check if a stock exists
            stock_check = db.execute(
                'SELECT symbol, SUM(shares) AS shares FROM portfolio WHERE symbol = ? AND person_id = ?', symbol, session['user_id'])

            # If stock doesn't exists insert new value
            if stock_check[0]['symbol'] == None and stock_check[0]['shares'] == None:
                db.execute('INSERT INTO portfolio(person_id, shares, symbol) VALUES (?, ?, ?)',
                           session['user_id'], f_shares, symbol)
            else:
                # If it does exists update the current value
                db.execute('UPDATE portfolio SET shares = ? WHERE person_id = ? AND symbol = ?',
                           stock_check[0]['shares'] + f_shares, session['user_id'], symbol)

            # Register it into history
            db.execute('INSERT INTO history(person_id, reason, shares, symbol, time_transacted) VALUES (?, ?, ?, ?, datetime(\'now\'))',
                       session['user_id'], 'buy', f_shares, symbol)

            # Update user cash amount
            db.execute('UPDATE users SET cash = ? WHERE id = ?',
                       cash - total, session['user_id'])

            return redirect('/')
        else:
            return apology('Not enough money')
    # Render GET method of page
    else:
        return render_template('buy.html')


@app.route("/history")
@login_required
def history():
    """Show history of history"""
    stocks = db.execute(
        'SELECT * FROM history WHERE person_id = ?', session['user_id'])

    for stock in stocks:
        stock['price'] = lookup(stock['symbol'])['price']

    return render_template('history.html', stocks=stocks)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?",
                          request.form.get("username"))

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
    if request.method == 'POST':

        stock = request.form.get('symbol')

        if not stock:
            return apology('Please enter a stock name to quote.')

        f_stock = lookup(stock)

        if f_stock == None:
            return apology('Enter a valid name')

        return render_template('quoted.html', stock=f_stock)
    else:
        return render_template('quote.html')


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == 'POST':
        # Register user
        username = request.form.get('username')
        password = request.form.get('password')
        confirmation = request.form.get('confirmation')

        # Check database if user already exists
        exists = db.execute(
            'SELECT username FROM users WHERE username = ?', username)

        # Display error messages for missing registration information
        if exists:
            return apology('Username already exists')

        if not username:
            return apology('Missing username')

        if not password:
            return apology('Missing password')

        if not confirmation:
            return apology('Missing confirmation')

        if password != confirmation:
            return apology('Passwords don\'t match')
        elif password == confirmation and not exists:
            db.execute('INSERT INTO users (username, hash) VALUES (?, ?)',
                       username, generate_password_hash(password))

        return redirect('/')
    else:

        return render_template('register.html')


@app.route('/change',  methods=["GET", "POST"])
@login_required
def change():
    if request.method == 'POST':
        username = request.form.get('username')
        old = request.form.get('oldPassword')
        new = request.form.get('newPassword')

        # Select user and unhash password
        rows = db.execute('SELECT * FROM users WHERE username = ?', username)

        if not check_password_hash(rows[0]['hash'], old):
            return apology('Wrong credentials')

        if old == new:
            return apology('Password must be different')

        db.execute('UPDATE users SET hash = ? WHERE id = ?',
                   generate_password_hash(new), session['user_id'])

        return redirect('/')
    else:
        return render_template('change.html')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    # Stocks for the select menu
    stocks = db.execute(
        'SELECT symbol FROM portfolio GROUP BY symbol HAVING person_id = ?', session['user_id'])

    if request.method == 'POST':
        symbol = request.form.get('symbol')
        shares = request.form.get('shares')

        portfolio = db.execute(
            'SELECT shares, symbol FROM portfolio WHERE symbol = ?', symbol)

        # Display error messages for missing information
        if not symbol and not shares:
            return apology('Please fill out the form.')

        if not symbol:
            return apology('Please enter a valid symbol.')

        if not shares:
            return apology('Please enter a valid ammount.')

        if not portfolio:
            return apology('You don\'t own any holdings of that stock')

        f_shares = int(shares)  # form shares
        p_shares = int(portfolio[0]['shares'])  # portfolio shares

        # Error checking
        if p_shares <= f_shares:
            return apology('You don\'t own that many stocks')

        if f_shares <= 0:
            return apology('Please enter a positive number of stocks.')

        # Sell stock
        # Update the portfolio
        db.execute('UPDATE portfolio SET shares = ? WHERE symbol = ? AND person_id = ?', int(
            portfolio[0]['shares']) - int(shares), symbol, session['user_id'])

        # Update cash count
        cash = db.execute(
            'SELECT cash FROM users WHERE id = ?', session['user_id'])
        db.execute('UPDATE users SET cash = ? WHERE id = ?',
                   cash[0]['cash'] + (int(shares) * lookup(symbol)['price']), session['user_id'])

        # Update the history
        db.execute('INSERT INTO history(person_id, reason, shares, symbol, time_transacted) VALUES (?, ?, ?, ?, datetime(\'now\'))',
                   session['user_id'], 'sell', int(shares), symbol)

        return redirect('/')

    else:
        return render_template('sell.html', options=stocks)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
