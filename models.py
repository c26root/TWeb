from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_COMMIT_TEARDOWN'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:root@localhost/tweb'
db = SQLAlchemy(app)


class Rule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    method = db.Column(db.String(80))
    path = db.Column(db.String(80))
    code = db.Column(db.String(80))
    headers = db.Column(db.String(80))
    remote = db.Column(db.String(80))
    body = db.Column(db.Text())

    def __repr__(self):
        return '<Rule %r>' % self.path


class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rid = db.Column(db.Integer, db.ForeignKey('rule.id'))
    request = db.Column(db.Text())

    def __repr__(self):
        return '<Log %r>' % self.request


class Config(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80))
    value = db.Column(db.String(80))

    def __repr__(self):
        return '<Config %r>' % self.name


if __name__ == '__main__':
    db.create_all()
