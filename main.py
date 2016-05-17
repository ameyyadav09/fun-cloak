
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

import logging
import webapp2
import jinja2
import os
import string
import random
import socket
from Models import Community, Members, Request, Posts, Comments
from google.appengine.ext import db
from google.appengine.api import mail

from webapp2_extras import auth
from webapp2_extras import sessions

from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError
from google.appengine.ext.webapp.mail_handlers import BounceNotificationHandler

templates_dir = os.path.join(os.path.dirname(__file__),'template')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(templates_dir), autoescape = True)

def uniqueCommunity(community):
	com = Community.gql("WHERE community_name=:1",community).get()
	if com is not None:
		return True
	else:
		return False

def generate_random():
	id_chars = string.ascii_letters + string.digits
	rand = random.SystemRandom()
	random_id = ''.join([rand.choice(id_chars) for i in range(16)])
	return random_id

def create_new_user_confirmation(user_address):
	random_id = generate_random()
	addr = 'https://{}/user/confirm?code={}'.format(socket.getfqdn(socket.gethostname()), random_id)
	return random_id+","+addr

class LogBounceHandler(BounceNotificationHandler):
    def receive(self, bounce_message):
        logging.info('Received bounce post ... [%s]******', self.request)
        logging.info('Bounce original: %s +++++++', bounce_message.original)
        logging.info('Bounce notification: %s >>>>>>>', bounce_message.notification)

def user_required(func):
	"""
	Decorator that checks if there's a user associated with the current session.
	Will also fail if there's no session present.
	"""
	def check_login(self):
		auth = self.session.get("name")
		if auth:
			return func(self)
		else:
			self.redirect('/signin', abort=True)
	return check_login

def ifNotLogged(func):
	# this decorator checks if user is already logged in and redirects them to home page

	def check_login(self):
		auth = self.session.get("name")
		if auth:
			self.redirect('/userhome',abort=True)
		else:
			return func(self)
	return check_login

config = {}
config['webapp2_extras.sessions'] = {'secret_key': 'my-super-secret-key',}

class Pageview(webapp2.RequestHandler):
	def render(self, template, **k):
		t = jinja_env.get_template(template)
		self.response.out.write(t.render(**k))

	def dispatch(self):
		# Get a session store for this request.
		self.session_store = sessions.get_store(request=self.request)

		try:
			# Dispatch the request.
			webapp2.RequestHandler.dispatch(self)
		finally:
			# Save all sessions.
			self.session_store.save_sessions(self.response)

	@webapp2.cached_property
	def session(self):
	    # Returns a session using the default cookie key.
	    return self.session_store.get_session()


class IndexHandler(Pageview):
    def get(self):
    	c_name = self.session.get("community")
        self.render("source.html", cname = c_name)

    def post(self):
		c_name = self.request.get("community_name")
		flag = uniqueCommunity(c_name)
		if flag:
			string = 'community is unavailable, choose a different name'
			self.render("source.html",string = string)
		else:
			string = 'community is available'
			self.redirect("/com_register?string="+string+"&c_name="+c_name)

class Com_registerHandler(Pageview):
	@ifNotLogged
	def get(self):
		string = self.request.get("string")
		c_name = self.request.get("c_name")
		if string and c_name:
			self.render("community_register.html", string = string, c_name = c_name)
		else:
			self.render("community_register.html")

	@ifNotLogged
	def post(self):
		c_name = self.request.get("community_name")
		member_name = self.request.get("name")
		email = self.request.get("email")
		passcode = self.request.get("password")

		# confirm community
		flag = uniqueCommunity(c_name)
		if not flag:
			# creating a community
			com_rec = Community(community_name = c_name, admin_name = email)
			com_obj = com_rec.put()

			# validating user
			mem_obj = Members(community_id = com_obj, member_name = member_name, email = email, passcode = passcode, authority = 1)
			mem_obj.put()
			self.render("signin.html")
		else:
			string = 'community is unavailable, choose a different name'
			self.render("source.html",string = string, cname = None)

class MainHandler(Pageview):
	@user_required
	def get(self):
		c_name = self.session.get("community")

		com_obj = db.GqlQuery("SELECT * FROM Community WHERE community_name=:1",c_name).get()

		p = Posts.all()
		
		p.filter("community_id =",com_obj)

		p.order("-created")
		
		posts = p.fetch(limit = 10)

		authority = self.session.get("authority")

		name = self.session.get("name")
		nickname = self.session.get("nickname").split(' ')[0]

		self.render("userhome.html", posts = posts, authority = authority, User = name, nickname= nickname)

	@user_required
	def post(self):
		content = self.request.get("content")
		c_name = self.session.get("community")
		m_name = self.session.get("name")

		com_obj = db.GqlQuery("SELECT * FROM Community WHERE community_name=:1",c_name).get()

		mem_obj = db.GqlQuery("SELECT * FROM Members WHERE community_id=:1 AND email=:2",com_obj,m_name).get()

		post = Posts(community_id = com_obj, member_id = mem_obj, post_content = content, likes = 0, dislikes = 0)
		post_obj = post.put();

		self.redirect("/userhome")

class SigninHandler(Pageview):
	@ifNotLogged
	def get(self):
		msg = self.request.get("msg")
		self.render("signin.html", msg = msg)

	@ifNotLogged
	def post(self):
		c_name = self.request.get("community_name")
		u_name = self.request.get("username")
		passcode = self.request.get("password")

		com_obj = db.GqlQuery("SELECT * FROM Community WHERE community_name=:1",c_name).get()
		if com_obj:
			mem_obj = db.GqlQuery("SELECT * FROM Members WHERE community_id=:1 and email=:2",com_obj,u_name).get()
			if mem_obj:
				if mem_obj.passcode == passcode:
					self.session["name"] = u_name
					self.session["nickname"] = mem_obj.member_name
					self.session["community"] = c_name
					if u_name == com_obj.admin_name:
						self.session["authority"] = 1
						self.redirect("/userhome")
					else:
						self.session["authority"] = 0
						self.redirect("/userhome")
				else:
					self.render("signin.html",msg = "Password Error")
			else:
				self.render("signin.html",msg = "Username Error")
		else:
			self.render("signin.html",msg = "community name Error")

class LogoutHandler(Pageview):
	@user_required
	def get(self):
		self.session.clear()
		self.redirect("/signin")

class AdminHandler(Pageview):
	@user_required
	def get(self):
		c_name = self.session.get("community")

		com_obj = db.GqlQuery("SELECT * FROM Community WHERE community_name=:1",c_name).get()

		m = Members.all()

		m.filter("community_id =",com_obj)

		mem_list = m.fetch(limit = 10)

		name = self.session.get("name")
		nickname = self.session.get("nickname").split(' ')[0]

		self.render("adminPage.html", mem_list = mem_list, User = name, nickname = nickname)

class RequestSendingHandler(Pageview):
	@user_required
	def get(self):
		name = self.session.get("name")
		nickname = self.session.get("nickname").split(' ')[0]
		self.render("sendRequest.html", User = name, nickname = nickname)

	@user_required
	def post(self):
		u_name = self.request.get("email")
		c_name = str(self.session.get("community"))
		addr = create_new_user_confirmation(u_name).split(',')
		req_obj = Request(member_name = u_name, secret_code = addr[0])
		req_obj.put()
		addr[1] = addr[1]+"&email="+u_name+"&c_name="+c_name
		try:			
			mail.send_mail(sender= "ameykumar.tkr@gmail.com",
							to= str(u_name),
							subject="Your account has been approved",
							body="""Dear {}:
							Your example.com account has been approved.  You can now visit
							{} and sign in fun-cloak to
							access new features.
							""".format(u_name, addr[1]))
		except Exception:
			logging.info("Sending failed to %s"%(u_name))
		self.redirect("/sendrequest")

class ConformationHandler(Pageview):
	def get(self):
		secret_code = str(self.request.get("code"))
		user_mail = str(self.request.get("email"))
		c_name = str(self.request.get("c_name"))
		r = Request.all()
		req_obj = None
		for each in r:
			if each.member_name == user_mail and each.secret_code == secret_code:
				req_obj = each
		if req_obj is not None:
			req_obj.delete()
			msg = "Welcome, You are a fun-cloaker now jz set a password to your account \n our Community is %s"%(c_name)
			self.render("register.html", msg = msg, email = user_mail, c_name = c_name)
		else:
			self.redirect("/signin?msg=Unauthorized access or link is not valid anymore")

	def post(self):
		user_mail = str(self.request.get("email"))
		fullname = str(self.request.get("fullname"))
		c_name = str(self.request.get("c_name"))
		password1 = str(self.request.get("password1"))
		password2 = str(self.request.get("password2"))
		if password1 == password2:
			com_obj = db.GqlQuery("SELECT * FROM Community WHERE community_name=:1",c_name).get()
			mem_obj = db.GqlQuery("SELECT * FROM Members WHERE community_id=:1 and email=:2",com_obj,user_mail).get()
			if com_obj:
				if not mem_obj:
					mem_obj = Members(community_id = com_obj, member_name = fullname, email = user_mail, passcode = password1, authority = 0)
					mem_obj.put()
					self.session["name"] = user_mail
					self.session["nickname"] = mem_obj.member_name
					self.session["community"] = c_name
					self.session["authority"] = 0
					self.redirect("/userhome")
				else:
					msg = "your are already a member please login or click on forgot password"
					self.redirect("/signin?msg="+msg)
			else:
				msg = "community does not exist"
				self.redirect("/signin?msg="+msg)
		else:
			msg = "passwords donot match Enter Again"
			self.render("register.html", msg = msg, email = user_mail, c_name = c_name)

class ForgotHandler(Pageview):
	@ifNotLogged
	def get(self):
		msg = self.request.get("msg")
		self.render("forgot.html", msg = msg)

	@ifNotLogged
	def post(self):
		c_name = self.request.get("c_name")
		email = self.request.get("username")
		msg = ""
		com_obj = db.GqlQuery("SELECT * FROM Community WHERE community_name=:1",c_name).get()
		if com_obj:
			mem_obj = db.GqlQuery("SELECT * FROM Members WHERE community_id=:1 and email=:2",com_obj,email).get()
			if mem_obj:
				random_id = generate_random()
				req_obj = Request(member_name = email, secret_code = random_id)
				req_obj.put()
				addr = 'https://{}/user/forgot?code={}'.format(socket.getfqdn(socket.gethostname()), random_id)
				addr = addr+"&email="+email+"&c_name="+c_name
				try:			
					mail.send_mail(sender= "ameykumar.tkr@gmail.com",
									to= str(email),
									subject="Forgot password, fun-cloak.appspot.com",
									body="""Dear {}:
									Your example.com {} account password can be modified at this link {} """.format(email, c_name, addr))
				except Exception:
					logging.info("Sending failed to %s"%(email))
				msg = "conformation has been sent to your mail"
				self.redirect("/signin?msg="+msg)
			else:
				msg = "enter correct mail id related to your %s account"%(c_name)
		else:
			msg = "community name error"
		self.redirect("/forgot?msg="+msg)

class PasswordHandler(Pageview):
	def get(self):
		secret_code = str(self.request.get("code"))
		user_mail = str(self.request.get("email"))
		c_name = str(self.request.get("c_name"))
		r = Request.all()
		req_obj = None
		for each in r:
			if each.member_name == user_mail and each.secret_code == secret_code:
				req_obj = each
		if req_obj is not None:
			req_obj.delete()
			msg = "set your account password for Community %s, here"%(c_name)
			self.render("setpassword.html", msg = msg, email = user_mail, c_name = c_name)
		else:
			self.redirect("/signin?msg=Unauthorized access or the link is invalid")

	def post(self):
		email = str(self.request.get("email"))
		c_name = str(self.request.get("c_name"))
		password1 = str(self.request.get("password1"))
		password2 = str(self.request.get("password2"))
		if password1 == password2:
			com_obj = db.GqlQuery("SELECT * FROM Community WHERE community_name=:1",c_name).get()
			if com_obj:
				mem_obj = db.GqlQuery("SELECT * FROM Members WHERE community_id=:1 and email=:2",com_obj,email).get()
				if mem_obj:
					mem_obj.passcode = password1
					mem_obj.put()
					msg = "Password reset has been successfull"
					self.redirect("/signin?msg="+msg)
				else:
					msg = "Something has gone wrong, try again"
			else:
				msg = "Something has gone wrong, try again"
		else:
			msg = "Passwords didnot match"
		self.redirect("/forgot?msg="+msg)

app = webapp2.WSGIApplication([
	webapp2.Route('/', IndexHandler),
	webapp2.Route('/signin',SigninHandler),
	webapp2.Route('/com_register',Com_registerHandler),
	webapp2.Route('/userhome',MainHandler),
	webapp2.Route('/logout',LogoutHandler),
	webapp2.Route('/logoutcheck',LogoutHandler),
	webapp2.Route('/adminPage',AdminHandler),
	webapp2.Route('/sendrequest',RequestSendingHandler),
	webapp2.Route('/_ah/bounce',LogBounceHandler.mapping()),
	webapp2.Route('/user/confirm', ConformationHandler),
	webapp2.Route('/user/forgot', PasswordHandler),
	webapp2.Route('/forgot', ForgotHandler),
], config = config, debug=True)