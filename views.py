#!/usr/bin/env python
import os

from catalog.models import Base, Project, Task, User
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine, desc
from flask import (Flask, render_template, request, redirect, url_for, jsonify)

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
# "client_id":"28315248340-l3h40plg6m44nde6j1359bgbplft9bh4.apps.googleusercontent.com"
APPLICATION_NAME = "Project Management App"

engine = create_engine("sqlite:///projectmgtwithuser.db")
Base.metadata.bind = engine
Session = sessionmaker(bind=engine)
session = Session()

# user helper function
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session['email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id

def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user

def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

@app.route('/projects/JSON')
def projects_json():
    projects = session.query(Project).all()
    return jsonify(Projects=[i.serialize for i in projects])

@app.route('/project/<string:project_name>/JSON')
def project_tasks_json(project_name):
    project = session.query(Project).filter_by(name=project_name).one()
    tasks = session.query(Task).filter_by(project_id=project.id).all()
    return jsonify(ProjectTasks=[i.serialize for i in tasks])

@app.route('/project/<string:project_name>/task/<string:task_name>/JSON')
def task_json(project_name, task_name):
    project = session.query(Project).filter_by(name=project_name).one()
    task = session.query(Task).filter_by(project_id=project.id, name=task_name).one()
    return jsonify(Task=[task.serialize])

@app.route('/login')
def show_login():
    state = ''.join(random.choice(string.ascii_uppercase+string.digits) for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Step 3's request from browser to server is sent to here.
    # Codes below are how the server handles step 2's request 
    
    # validate state token
    # when state token is invalid
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # when state token is valid, obtain authorization code
    # requst object in Flask holds all incoming data from the request,
    # mimetype, referrer, IP address, raw data, HTTP method, and headers, etc.
    # data: Contains the incoming request data as string in case it came with 
    # a mimetype Flask does not handle.
    authorization_code = request.data

    try:
        # upgrate the authorization code into a credential object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'

        # Step 4: server sends authorization code to google
        # Step 5: google validates authorization code, and if validated, 
        # google returns an object credentials to server. Object credentials
        # contains access token and other information.
        # Function step2_exchange does step 4 and 5. 
        credentials = oauth_flow.step2_exchange(authorization_code)
        print (credentials.client_id)
    except FlowExchangeError:
        response = make_response(json.dumps('Failed to upgrade the authorization code'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # verify the access token
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=%s' % access_token)
    h = httplib2.Http()

    # the return value is a tuple of (response, content)
    # response is an instance of response class
    # content is a string that contains the response entity body
    (response, content) = h.request(url, 'GET')
    result = json.loads(content)
    print(result)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.

    # An ID Token is a JWT (JSON Web Token), that is, a cryptographically 
    # signed Base64-encoded JSON object
    gplus_id = credentials.id_token['sub']
    if result['sub'] != gplus_id:
        response = make_response(json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['aud'] != CLIENT_ID:
        response = make_response(json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    print data
    
    # store username, email in login_session
    login_session['username'] = data['name']
    login_session['email'] = data['email']

    # check if this user has logged in before 
    # and retrieve user's user_id that is stored in user table
    user_id = getUserID(login_session['email'])
    print user_id

    # if user_id is not found in user table, then create an entry for this user in user table
    # in database
    if not user_id:
        user_id = createUser(login_session)

    # store user's user_id that is stored in table user in databse into login_session
    login_session['user_id'] = user_id

    return render_template('index.html', email=login_session['email'])

@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    print 'In gdisconnect access token is %s', access_token
    print 'User email is: '
    print login_session['email']

    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    (result, content) = h.request(url, 'GET')
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['email']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return redirect(url_for('index'))
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

@app.route('/')
def index():
    projects = session.query(Project).all()
    print projects
    if 'email' not in login_session:
        return render_template('publicindex.html', projects=projects)
    return render_template('index.html',
                           projects=projects,
                           email=login_session['email'])

@app.route('/project/<string:project_name>')
def project(project_name):
    # find the project's id in table Project
    projects = session.query(Project).all()
    project = session.query(Project).filter_by(name = project_name).one()
    tasks = session.query(Task).filter_by(project_id = project.id)
    if 'email' not in login_session:
        return render_template('publicproject.html', 
                               projects=projects,
                               u_project_name=project.name,
                               tasks=tasks)
    return render_template('project.html', 
                           projects=projects,
                           u_project_name=project_name,
                           tasks=tasks,
                           email=login_session['email'])

@app.route('/project/new', methods=['POST', 'GET'])
def new_project():
    if 'email' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        name = request.form['project_name']
        new_project = Project(name=name, user_id=login_session['user_id'])
        session.add(new_project)
        session.commit()
        return redirect(url_for('project', project_name=name))
    else:
        return render_template('newproject.html', email=login_session['email'])

@app.route('/project/<string:project_name>/edit', methods=['POST', 'GET'])
def edit_project(project_name):
    project = session.query(Project).filter_by(name = project_name).one()
    if 'email' not in login_session:
        return redirect('/login')
    if project.user_id != login_session['user_id']:
        return """<script>
                  function myFunction() {
                    alert('You are not authorized to edit this project. ' +
                          'Please create your own project in order to edit.');
                  }
                  </script>
                  <body onload='myFunction()'>
               """
    if request.method == 'POST':
        if request.form['new_project_name']:
            project.name = request.form['new_project_name']
            session.commit()
            return redirect(url_for('project', project_name=project.name))
    else:
        return render_template('editproject.html',
                               project_name=project_name,
                               email=login_session['email'])

@app.route('/project/<string:project_name>/delete', methods=['POST', 'GET'])
def delete_project(project_name):
    project = session.query(Project).filter_by(name = project_name).one()
    if 'email' not in login_session:
        return redirect('/login')
    if project.user_id != login_session['user_id']:
        return """<script>
                  function myFunction() {
                      alert('You are not authorized to delete this project. ' +
                        'Please create your own project in order to delete.');
                  }
                  </script>
                  <body onload='myFunction()'>
               """
    if request.method == 'POST':
        session.delete(project)
        session.commit()
        return redirect(url_for('index'))
    else:
        return render_template('deleteproject.html', 
                               project_name=project_name,
                               email=login_session['email'])

@app.route('/project/<string:project_name>/task/<string:task_name>')
def task(project_name, task_name):
    projects = session.query(Project).all()
    task = session.query(Task).filter_by(name=task_name).one()
    if 'email' not in login_session:
        return render_template('publictask.html',
                               projects=projects,
                               project_name=project_name,
                               task=task)
    return render_template('task.html',
                           projects=projects,
                           project_name=project_name,
                           task=task,
                           email=login_session['email'])

@app.route('/project/<string:project_name>/task/new', methods=['POST', 'GET'])
def new_task(project_name):
    project = session.query(Project).filter_by(name = project_name).one()
    if 'email' not in login_session:
        return redirect('/login')
    if project.user_id != login_session['user_id']:
        return """<script>
                  function myFunction() {
                      alert('You are not authorized to add task. ' +
                        'Please create your own task.');
                  }
                  </script>
                  <body onload='myFunction()'>
               """
    if request.method == 'POST':
        name = request.form['task_name']
        content = request.form['task_content']
        new_task = Task(name=name,
                        content=content,
                        project_id=project.id,
                        user_id=login_session['user_id'])
        session.add(new_task)
        session.commit()
        return redirect(url_for('project', project_name=project_name))
    else:
        return render_template('newtask.html',
                               project_name=project.name,
                               email=login_session['email'])

@app.route('/project/<string:project_name>/task/<string:task_name>/edit', methods=['POST', 'GET'])
def edit_task(project_name, task_name):
    task = session.query(Task).filter_by(name = task_name).one()
    if 'email' not in login_session:
        return redirect('/login')
    if task.user_id != login_session['user_id']:
        return """<script>
                  function myFunction() {
                      alert('You are not authorized to edit this task. ' +
                        'Please create your own task in order to delete.');
                  }
                  </script>
                  <body onload='myFunction()'>
               """
    if request.method == 'POST':
        if request.form['new_task_name']:
            task.name = request.form['new_task_name']
        if request.form['new_task_content']:
            task.content = request.form['new_task_content']
        session.commit()
        return redirect(url_for('project', project_name=project_name))
    else:
        return render_template('edittask.html',
                               project_name=project_name,
                               task_name=task_name,
                               email=login_session['email'])

@app.route('/project/<string:project_name>/task/<string:task_name>/delete', methods=['POST', 'GET'])
def delete_task(project_name, task_name):
    task = session.query(Task).filter_by(name=task_name).one()
    if 'email' not in login_session:
        return redirect('/login')
    if task.user_id != login_session['user_id']:
        return """<script>
                  function myFunction() {
                      alert('You are not authorized to delete this task. ' +
                        'Please create your own task in order to delete.');
                  }
                  </script>
                  <body onload='myFunction()'>
               """
    if request.method == 'POST':
        session.delete(task)
        session.commit()
        return redirect(url_for('project', project_name=project_name))
    else:
        return render_template('deletetask.html',
                               project_name=project_name,
                               task_name=task_name,
                               email=login_session['email'])

if __name__ == "__main__":
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8080)
