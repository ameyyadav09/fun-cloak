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

templates_dir = os.path.join(os.path.dirname(__file__),'template')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(templates_dir), autoescape = True)

def uniqueCommunity(community):
	com = Community.gql("WHERE community_name=:1",community).get()
	if com is not None:
		return True
	else:
		return False

def create_new_user_confirmation(user_address):
	id_chars = string.ascii_letters + string.digits
	rand = random.SystemRandom()
	random_id = ''.join([rand.choice(id_chars) for i in range(16)])
	addr = 'https://{}/user/confirm?code={}'.format(socket.getfqdn(socket.gethostname()), random_id)
	return random_id+","+addr

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
        self.render("source.html")

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
	def get(self):
		string = self.request.get("string")
		c_name = self.request.get("c_name")
		if string and c_name:
			self.render("community_register.html", string = string, c_name = c_name)
		else:
			self.render("community_register.html")

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
			self.render("source.html",string = string)

class MainHandler(Pageview):
	@user_required
	def get(self):
		c_name = self.session.get("community")

		com_obj = db.GqlQuery("SELECT * FROM Community WHERE community_name=:1",c_name).get()

		p = Posts.all()
		
		p.filter("community_id =",com_obj)
		
		posts = p.fetch(limit = 10)
		
		self.render("userhome.html", posts = posts, baseURL = "/userhome")

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
	def get(self):
		self.render("signin.html")

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
					self.session["community"] = c_name
					self.redirect("/userhome")
				else:
					self.render("signin.html",string = "Password Error")
			else:
				self.render("signin.html",string = "Username Error")
		else:
			self.render("signin.html",string = "community name Error")

class LogoutHandler(Pageview):
	def get(self):
		logging.info("+++++++++++++++++++++++++++++++++++++++++++")
		if self.request.get('vara'):
			logging.info("+++++++++++++++++++++++++++++++++++++++++++")
			if self.session:
				return 1
		self.session.clear()
		self.redirect("/signin")

class AdminHandler(Pageview):
	def get(self):
		c_name = self.session.get('name')
		com_obj = db.GqlQuery("SELECT * FROM Community WHERE community_name=:1",c_name).get()

		m = db.GqlQuery("SELECT * FROM Members WHERE community_id=:1",com_obj)
		mem_list = m.fetch(limit = 500)
		self.render("adminPage.html", mem_list = mem_list)

class RequestSendingHandler(Pageview):
	def get(self):
		self.render("sendRequest.html")

	def post(self):
		u_name = self.request.get('email')
		addr = create_new_user_confirmation(u_name).split(',')
		req_obj = Request(member_name = u_name, secret_code = addr[0])
		message = mail.EmailMessage()
		message.sender = "ameykumar.tkr@gmail.com"
		message.to = u_name
		message.subject = "Request to join the community"
		message.body = """<p>Hello, This is a request to join our new Community Blog.</p>
						<p>Please click on this link to join</p>
						<b>{}</b>""".format({addr[1]})
		logging.info(message.body)
		message.send()
		self.render("sendRequest.html")

app = webapp2.WSGIApplication([
	webapp2.Route('/', IndexHandler),
	webapp2.Route('/signin',SigninHandler),
	webapp2.Route('/com_register',Com_registerHandler),
	webapp2.Route('/userhome',MainHandler),
	webapp2.Route('/logout',LogoutHandler),
	webapp2.Route('/logoutcheck',LogoutHandler),
	webapp2.Route('/adminPage',AdminHandler),
	webapp2.Route('/sendrequest',RequestSendingHandler),
], config = config, debug=True)