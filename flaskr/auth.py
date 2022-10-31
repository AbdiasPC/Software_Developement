import functools
from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

"""
This creates a Blueprint name 'auth'. Like the application object, the blueprint needs to know where it's defined, so __name__ is passed as the second argument. the url_prefix will be prepened toa ll the URLs associated with the blueprint.
"""
bp =  Blueprint('auth', __name__, url_prefix = '/auth')

#Register view

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        
        if error is None:
            try:
                db.execute(
                    "INSERT INTO user(username, password) VALUES(?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))

            flash(error)

            return render_template('auth/register.html')

#Login view which follows the same pattern as the register view

@bp.route('/login', methods=('GET','POST'))
def login():
    if request.method == 'POST':
        username =  request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        user = db.execute(
            'SELECT * FROM user WHERE username = ?',
            (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'
        
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')

#This function runs before hte view function no matter what URL is requested.
"""
It checks if a user id  is stored in the session and gets that user's data from database, storing it on g.user which lasts for the length of the request. if there is no user id, or if the id doesn't exist, g.user will be None
"""

@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?',
            (user_id,)
        ).fetchone()

#Logout
#To log out, you need to remove the user id from the sssion. then load_logged_in_user won't load a user on subsequent requests
@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index')) #url_for function generate the URL to a view base on a name and arguments. Tha name associated with a view is also called endpoint, and by default it's the same as the name of the view function


#Require Authentication in Other views
"""
Creating, editing and deleting blog posts will require a user to be logged in. A decorator can be used to check for each view it;s applied to.
"""

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view

"""
This decorator returns a new view function that wraps the orifinal view it's applied to. the new function checks if a user is loaded and redirects to the login page otherwise. If a user is loaded the original view is called and continues normally.
"""
