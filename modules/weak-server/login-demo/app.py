from flask import (
    Flask,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
    send_from_directory
)
from werkzeug.middleware.proxy_fix import ProxyFix


class User:
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password = password

    def __repr__(self):
        return '<User: ' + self.username + '>'


users = [User(id=1, username='Anthony', password='password'),
         User(id=2, username='Becca', password='secret'),
         User(id=3, username='Carlos', password='somethingsimple')]

app = Flask(__name__,
            template_folder="templates")
app.secret_key = 'somesecretkeythatonlyishouldknow'
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1 ,x_proto=1)

@app.before_request
def before_request():
    g.user = None

    if 'user_id' in session:
        user = [x for x in users if x.id == session['user_id']][0]
        g.user = user


@app.route('/flask/')
def main():
    return redirect(url_for('login'))


@app.route('/flask/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        session.pop('user_id', None)

        username = request.form['username']
        password = request.form['password']

        user = [x for x in users if x.username == username]
        if len(user) > 0 and user[0].password == password:
            session['user_id'] = user[0].id
            return redirect(url_for('profile'))

        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/flask/profile')
def profile():
    if not g.user:
        return redirect(url_for('login'))

    return render_template('profile.html')


@app.route('/flask/static/<path:path>')
def static_files(path):
    return send_from_directory('./static', path)

if __name__ == "__main__":
    app.run()
