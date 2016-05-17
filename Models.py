from google.appengine.ext import db

class Community(db.Model):
	community_name = db.StringProperty(required = True)
	admin_name = db.StringProperty(required = True)

class Members(db.Model):
	community_id = db.ReferenceProperty(Community)
	member_name = db.StringProperty(required = True)
	email = db.EmailProperty(required = True)
	passcode = db.TextProperty(required = True)
	authority = db.IntegerProperty(default = 1)

class Request(db.Model):
	member_name = db.StringProperty(required = True)
	secret_code = db.TextProperty(required = True)

class Posts(db.Model):
	community_id = db.ReferenceProperty(Community)
	member_id = db.ReferenceProperty(Members)
	post_content = db.TextProperty(required = True)
	likes = db.IntegerProperty(default = 0)
	dislikes = db.IntegerProperty(default = 0)
	created = db.DateTimeProperty(auto_now_add = True)

	def render(self):
		self._render_text = self.post_content.replace('\n','<br>')
		return render("post.html",p = self)

class Comments(db.Model):
	post_id = db.ReferenceProperty(Posts)
	comment = db.TextProperty(default = None)
