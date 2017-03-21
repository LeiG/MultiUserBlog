# -*- coding: utf-8 -*-

import re
import hmac

import webapp2

from google.appengine.ext import db

import utils
from models import blog_key, User, Post, Comment, Like


secret = '&uarr;&uarr;&darr;&darr;&larr;&larr;&rarr;&rarr;ABAB'


def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


class BlogHandler(webapp2.RequestHandler):
    """Base request handler for blog.
    """
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return utils.render_str(template, **params)

    def render(self, template, **kw):
        self.response.out.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s, Path=/' % (name, cookie_val)
        )

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)


class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, this is Commit Logs!')


########
# User #
########

def valid_username(username):
    USER_RE = re.compile(r"[a-zA-Z0-9_-]{3,20}$")
    return username and USER_RE.match(username)


def valid_password(password):
    PASS_RE = re.compile(r"^.{3,20}$")
    return password and PASS_RE.match(password)


def valid_email(email):
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    return email and EMAIL_RE.match(email)


class Signup(BlogHandler):
    """Render signup-form.html with POST method for user creation.
    """
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(
            username=self.username,
            email=self.email,
        )

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if User.by_name(self.username):
            params['error_username'] = "That user already exists."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That's not a valid password."
            have_error = True
        elif self.verify != self.password:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render("signup-form.html", **params)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')
            return


class Login(BlogHandler):
    """Render login-form.html
    """
    def get(self):
        self.render("login-form.html", error=self.request.get('error'))

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
            return
        else:
            msg = 'Invalid login'
            self.render("login-form.html", error=msg)


class Logout(BlogHandler):
    def get(self):
        if self.user:
            self.logout()
            self.redirect('/blog')
            return
        else:
            self.redirect('/login')
            return


def login_required(func):
    """A decorator to confirm a user is logged in or redirect as needed
    """
    def login(self, *args, **kwargs):
        if not self.user:
            self.redirect(
                "/login?error=You need to login in to perform the action!"
            )
        else:
            func(self, *args, **kwargs)
    return login


########
# Post #
########
class BlogFront(BlogHandler):
    """Render front.html with sorted list of posts by created time.
    """
    def get(self):
        deleted_post = self.request.get('deleted_post')

        if deleted_post == '':
            posts = Post.all().order('-created')
        else:
            # sort "subject" first due to GAE limitation
            # BadArgumentError: First ordering property must be the same as
            # inequality filter property, if specified for this query;
            posts = Post.all()\
                        .filter("subject !=", deleted_post)\
                        .order('subject')\
                        .order('-created')

        self.render(
            "front.html",
            posts=posts,
            user=self.user,
            deleted_post=deleted_post
        )


class PostPage(BlogHandler):
    """Render permalink.html with POST method to add likes and comments.
    """
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        likes = Like.all()\
                    .filter("post_id =", int(post_id))\
                    .count()

        comments = Comment.all()\
                          .filter("post_id =", int(post_id))\
                          .order('-created')

        error = self.request.get('error')

        self.render(
            "permalink.html",
            post=post,
            likes=likes,
            comments=comments,
            error=error,
        )

    @login_required
    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        user_id = self.user.key().id()

        if self.request.get('like') and \
           self.request.get('like') == 'update':
            likes = Like.all()\
                        .filter("post_id =", int(post_id))\
                        .filter("user_id =", user_id)

            if user_id == post.user_id:
                self.redirect("/blog/" + post_id +
                              "?error=You cannot like your own post!")
                return
            elif likes.count() > 0:
                self.redirect("/blog/" + post_id +
                              "?error=You already liked this post!")
                return
            else:
                l = Like(
                    parent=blog_key(),
                    user_id=user_id,
                    post_id=int(post_id),
                )
                l.put()
                self.redirect('/blog/' + post_id)
                return

        if self.request.get('new-comment'):
            c = Comment(
                parent=blog_key(),
                user_id=user_id,
                post_id=int(post_id),
                user_name=User.by_id(user_id).name,
                comment=self.request.get('new-comment'),
            )
            c.put()
            self.redirect('/blog/' + post_id)
            return


class NewPost(BlogHandler):
    """Render newpost.html that creates a new post.
    """
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login?error=You need to login to post!")
            return

    @login_required
    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(
                    parent=blog_key(),
                    user_id=self.user.key().id(),
                    subject=subject,
                    content=content,
                )
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
            return
        else:
            error = "subject and content, please!"
            self.render(
                "newpost.html",
                subject=subject,
                content=content,
                error=error,
            )


class EditPost(BlogHandler):
    """Render editpost.html to create update existing post.
    """
    def get(self, post_id):
        if self.user:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if not post:
                self.error(404)
                return

            if post.user_id == self.user.key().id():
                self.render(
                    "editpost.html",
                    subject=post.subject,
                    content=post.content,
                )
            else:
                self.redirect(
                    "/blog/%s?error=you can only edit your post!" % post_id
                )
                return

        else:
            self.redirect("/login?error=you need to login to edit post!")
            return

    @login_required
    def post(self, post_id):
        subject = self.request.get('subject')
        content = self.request.get('content')

        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if post.user_id == self.user.key().id():

            if subject and content:
                post.subject = subject
                post.content = content
                post.put()

                self.redirect('/blog/%s' % post_id)
                return
            else:
                error = "subject and content, please!"
                self.render(
                    "editpost.html",
                    post_id=post_id,
                    subject=subject,
                    content=content,
                    error=error,
                )
        else:
            self.redirect(
                "/blog/%s?error=you can only edit your post!" % post_id
            )
            return


class DeletePost(BlogHandler):
    @login_required
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        if post.user_id == self.user.key().id():
            post.delete()
            self.redirect("/blog?deleted_post=%s" % post.subject)
            return
        else:
            self.redirect(
                "/blog/%s?error=you can only delete your post!"
                % post_id
            )
            return


###########
# Comment #
###########
class EditComment(BlogHandler):
    """Render editcomment.html to edit existing comments.
    """
    @login_required
    def get(self, comment_id):
        key = db.Key.from_path(
            'Comment',
            int(comment_id),
            parent=blog_key(),
        )
        comment = db.get(key)

        if comment.user_id == self.user.key().id():
            self.render(
                "editcomment.html",
                comment=comment.comment,
                post_id=comment.post_id,
            )
        else:
            self.redirect(
                "/blog/%s?error=you can only edit your comment!"
                % str(comment.post_id)
            )
            return

    @login_required
    def post(self, comment_id):
        key = db.Key.from_path(
            'Comment',
            int(comment_id),
            parent=blog_key(),
        )
        comment = db.get(key)

        comment_message = self.request.get('comment')

        if comment.user_id == self.user.key().id():
            if comment_message:
                comment.comment = comment_message
                comment.put()

                self.redirect("/blog/%s" % str(comment.post_id))
                return
            else:
                self.render(
                    "editcomment.html",
                    comment=comment_message,
                    post_id=comment.post_id,
                    error="comment message, please!",
                )
        else:
            self.redirect(
                "/blog/%s?error=you can only edit your comment!"
                % str(comment.post_id)
            )
            return


class DeleteComment(BlogHandler):
    @login_required
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        comment = db.get(key)

        if comment.user_id == self.user.key().id():
            comment.delete()
            self.redirect("/blog/%s" % str(comment.post_id))
            return
        else:
            self.redirect(
                "/blog/%s?error=you can only delete your comment!"
                % str(comment.post_id)
            )
            return


app = webapp2.WSGIApplication(
    [
        ('/', MainPage),
        ('/blog/?', BlogFront),
        ('/blog/([0-9]+)', PostPage),
        ('/blog/newpost', NewPost),
        ('/blog/editpost/([0-9]+)', EditPost),
        ('/blog/deletepost/([0-9]+)', DeletePost),
        ('/blog/editcomment/([0-9]+)', EditComment),
        ('/blog/deletecomment/([0-9]+)', DeleteComment),
        ('/signup', Signup),
        ('/login', Login),
        ('/logout', Logout),
    ],
    debug=True,
)
