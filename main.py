#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import jinja2
import re
import hmac
import random
import hashlib
import string

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

#validating
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)


secret = "hahaha"

#create and secure cookie
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


#salt and password hashing
##### user stuff
def make_salt(length = 5):
    str = ""
    for i in range(0,5):
	    str += random.choice(string.ascii_letters)
    return str

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h,salt)

def valid_pw(name, password, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, password, salt)



class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self,template,**params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
		    'Set-Cookie',
		    '%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')


class User(db.Model):
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty()

	@classmethod
	def by_id(cls, uid):
		return User.get_by_id(uid)

	@classmethod
	def by_name(cls, name):
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		pw_hash = make_pw_hash(name, pw)
		return User(name = name,
		            pw_hash = pw_hash,
		            email = email)

	@classmethod
	def login(cls, name, pw):
	    u = cls.by_name(name)
	    if u and valid_pw(name, pw, u.pw_hash):
	        return u


#ROUTES
class MainPage(Handler):
    def get(self):
        self.render("base.html")

class RegisterPage(Handler):
	def get(self):
		self.render("register.html")

	def post(self):
		has_errors = False
		errors = {}
		username = self.request.get("username")
		password = self.request.get("password")
		verify   = self.request.get("verify")
		email    = self.request.get("email")

		if not valid_username(username):
			errors["error_username"] = "Invalid Username"
			has_errors = True

		if not valid_password(password):
			errors["error_password"] = "Invalid Password"
			has_errors = True

		if password != verify:
			errors["error_verify"] = "Passwords don't match"
			has_errors = True

		if not valid_email(email):
			errors["error_email"] = "Invalid Email"
			has_errors = True

		if has_errors:
			self.render("register.html", **errors)
		else:
			#set cookie and create user object
			#check if another same name user
			u = User.by_name(username)
			if u:
				msg = 'That user already exists.'
				self.render('register.html', error_username = msg)
			else:
				u = User.register(name=username, pw=password, email=email)
				print u
				u.put()
				#set cookie using login from handler class
				self.login(u)

				self.redirect("/blog/welcome")
				

			

class WelcomePage(Handler):
	def get(self):
		if self.user:
			self.render("welcome.html", username=self.user.name)
		else:
			self.redirect('/blog/register')

class LoginPage(Handler):
	def get(self):
		self.render('login.html')

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')

		valid_user = User.login(username,password)
		if valid_user:
			self.login(valid_user)
			self.redirect('/blog/welcome')
		else:
			error = "Invalid Username or Password"
			self.render("login.html", error_message=error)


class Logout(Handler):
	def get(self):
		self.logout()
		self.redirect('/')


class Post(db.Model):
	subject = db.StringProperty(required=True)
	content = db.TextProperty(required=True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	created_by    = db.StringProperty(required = True)

	# @classmethod
	# def getUser(cls, user):
	# 	print user.by_id(uid)

class BlogPage(Handler):
	def get(self):
		uid = self.read_secure_cookie('user_id')
		if uid and User.by_id(int(uid)):
			created = self.user.name
			post = Post(subject = "hi first", content="some content here", created_by=created)
			#TODO change post back to posts
			self.render("blog.html", post = post, username = created)

class BlogForm(Handler):
	def get(self):
		self.render("blogform.html")

class BlogPost(Handler):
	def get(self):
		self.render("blogpost.html")


app = webapp2.WSGIApplication([
    ('/', MainPage), 
    ('/blog/register', RegisterPage),
    ('/blog/welcome', WelcomePage),
    ('/blog', BlogPage),
    ('/blog/form', BlogForm),
    ('/blog/post', BlogPost),
    ('/blog/login',LoginPage),
    ('/blog/logout', Logout)
], debug=True)
