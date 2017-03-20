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
USER_RE = re.compile(r"[a-zA-Z0-9_-]{3,20}$")


def valid_username(username):
    return username and USER_RE.match(username)


PASS_RE = re.compile(r"^.{3,20}$")


def valid_password(password):
    return password and PASS_RE.match(password)


EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")


def valid_email(email):
    return email and EMAIL_RE.match(email)


class Signup(BlogHandler):
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


class Login(BlogHandler):
    def get(self):
        self.render("login-form.html", error=self.request.get('error'))

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalid login'
            self.render("login-form.html", error=msg)


class Logout(BlogHandler):
    def get(self):
        if self.user:
            self.logout()
            self.redirect('/blog')
        else:
            self.redirect('/login')


########
# Post #
########
class BlogFront(BlogHandler):
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

    def post(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        if self.user:
            user_id = self.user.key().id()

            if self.request.get('like') and \
               self.request.get('like') == 'update':
                likes = Like.all()\
                            .filter("post_id =", int(post_id))\
                            .filter("user_id =", user_id)

                if user_id == post.user_id:
                    self.redirect("/blog/" + post_id +
                                  "?error=You cannot like your own post!")
                elif likes.count() > 0:
                    self.redirect("/blog/" + post_id +
                                  "?error=You already liked this post!")
                else:
                    l = Like(
                        parent=blog_key(),
                        user_id=user_id,
                        post_id=int(post_id),
                    )
                    l.put()
                    self.redirect('/blog/' + post_id)

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
        else:
            self.redirect("/login?error=You need to login to like or comment!")


class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login?error=You need to login to post!")

    def post(self):
        if not self.user:
            self.redirect('/blog')

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
        else:
            error = "subject and content, please!"
            self.render(
                "newpost.html",
                subject=subject,
                content=content,
                error=error,
            )


class EditPost(BlogHandler):
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

        else:
            self.redirect("/login?error=you need to login to edit post!")

    def post(self, post_id):
        if not self.user:
            self.redirect('/blog/' + post_id +
                          "?error=You need to login to edit!")

        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            post.subject = subject
            post.content = content
            post.put()

            self.redirect('/blog/%s' % post_id)
        else:
            error = "subject and content, please!"
            self.render(
                "editpost.html",
                post_id=post_id,
                subject=subject,
                content=content,
                error=error,
            )


class DeletePost(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if self.user:
            if not post:
                self.error(404)
                return

            if post.user_id == self.user.key().id():
                post.delete()
                self.redirect("/blog?deleted_post=%s" % post.subject)
            else:
                self.redirect(
                    "/blog/%s?error=you can only delete your post!"
                    % post_id
                )

        else:
            self.redirect("/login?error=you need to login to delete post!")


###########
# Comment #
###########
class EditComment(BlogHandler):
    def get(self, comment_id):
        if self.user:
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
        else:
            self.redirect("/login?error=you need to login to edit comment!")

    def post(self, comment_id):
        if not self.user:
            self.redirect("/login?error=you need to login to edit comment!")

        key = db.Key.from_path(
            'Comment',
            int(comment_id),
            parent=blog_key(),
        )
        comment = db.get(key)

        comment_message = self.request.get('comment')

        if comment_message:
            comment.comment = comment_message
            comment.put()

            self.redirect("/blog/%s" % str(comment.post_id))
        else:
            self.render(
                "editcomment.html",
                comment=comment_message,
                post_id=comment.post_id,
                error="comment message, please!",
            )


class DeleteComment(BlogHandler):
    def get(self, comment_id):
        key = db.Key.from_path('Comment', int(comment_id), parent=blog_key())
        comment = db.get(key)

        if self.user:
            if comment.user_id == self.user.key().id():
                comment.delete()
                self.redirect("/blog/%s" % str(comment.post_id))
            else:
                self.redirect(
                    "/blog/%s?error=you can only delete your comment!"
                    % str(comment.post_id)
                )
        else:
            self.redirect("/login?error=you need to login to delete comment!")


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
