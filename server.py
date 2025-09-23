import os, secrets
from flask import Flask, request, jsonify, redirect, url_for, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import or_
from werkzeug.security import generate_password_hash, check_password_hash
from flask_socketio import SocketIO, emit, join_room, leave_room
from authlib.integrations.flask_client import OAuth
from flask_cors import CORS
import re
import base64
from sqlalchemy import func
import io
from PIL import Image
from datetime import datetime, date, timedelta
import pytz

# -------------------------------------------------
# App / Config
# -------------------------------------------------
app = Flask(__name__)
CORS(app)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(16))
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///app.db?timeout=15")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Google OAuth config (환경변수에서 읽음)
app.config["GOOGLE_CLIENT_ID"] = os.environ.get("GOOGLE_CLIENT_ID", "")
app.config["GOOGLE_CLIENT_SECRET"] = os.environ.get("GOOGLE_CLIENT_SECRET", "")
KST = pytz.timezone('Asia/Seoul')
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")
oauth = OAuth(app)

# OpenID Connect (Google)
google = oauth.register(
    name="google",
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)

followers = db.Table('followers',
                     db.Column('follower_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                     db.Column('followed_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
                     )


# -------------------------------------------------
# Models
# -------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=True)  # 소셜 로그인은 비번 없을 수 있음

    # --- New Account Type Field ---
    account_type = db.Column(db.String(50), default="student", nullable=False)  # "student", "teacher", "team"

    full_name = db.Column(db.String(100), nullable=True)
    username = db.Column(db.String(80), unique=True, nullable=True, index=True)
    profile_pic = db.Column(db.Text, nullable=True)
    school = db.Column(db.String(100), nullable=True)
    rank = db.Column(db.String(50), default="user", nullable=False)

    # --- Role-Specific Fields ---
    dob = db.Column(db.String(20), nullable=True)  # Nullable for Team accounts
    grade = db.Column(db.String(10), nullable=True)  # For Students only
    subject = db.Column(db.String(100), nullable=True)  # For Teachers only

    # --- System Fields ---
    is_banned = db.Column(db.Boolean, default=False, nullable=False)
    ban_reason = db.Column(db.Text, nullable=True)

    # token = db.Column(db.String(128), unique=True, index=True)
    bio = db.Column(db.Text, default="")
    provider = db.Column(db.String(50), default="local")  # local or google
    oauth_sub = db.Column(db.String(255), unique=False)  # Google sub (고유 ID)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    following = db.relationship(
        'User', secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.followed_id == id),
        backref=db.backref('followers', lazy='dynamic'),
        lazy='dynamic'
    )


class DailyView(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.Date, nullable=False, index=True)
    count = db.Column(db.Integer, default=1, nullable=False)
    # These two columns link this view count to either an Article or a Circuit
    viewable_id = db.Column(db.Integer, nullable=False)
    viewable_type = db.Column(db.String(50), nullable=False)  # Will be 'article' or 'circuit'
    # This ensures we only have one row per item per day
    __table_args__ = (db.UniqueConstraint('date', 'viewable_id', 'viewable_type', name='_daily_view_uc'),)


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    author = db.relationship("User", backref="articles")


class MessageReaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('dm.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    emoji = db.Column(db.String(10), nullable=False)

    # --- THIS IS THE CHANGE ---
    # A user can only react with the SAME EMOJI once per message.
    __table_args__ = (db.UniqueConstraint('message_id', 'user_id', 'emoji', name='_message_user_emoji_reaction_uc'),)
    # --- END OF CHANGE ---


class Conversation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # Store user IDs consistently (smaller ID first) to avoid duplicate entries
    user1_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user2_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Store the theme name for this specific chat
    theme = db.Column(db.String(50), default="apex", nullable=False)

    # This ensures that a conversation between two users can only exist once
    __table_args__ = (db.UniqueConstraint('user1_id', 'user2_id', name='_user_conversation_uc'),)


class Lounge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

    owner = db.relationship("User", backref="owned_lounges")
    # Add a relationship to easily get channels from a lounge
    channels = db.relationship("LoungeChannel", backref="lounge", cascade="all, delete-orphan")


class LoungeChannel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    lounge_id = db.Column(db.Integer, db.ForeignKey('lounge.id'), nullable=False)


class LoungeMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=True)
    image = db.Column(db.Text, nullable=True)
    # --- THIS IS THE FIX ---
    # This explicitly saves the time in UTC, removing timezone confusion.
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(pytz.timezone('UTC')))
    # --- END OF FIX ---
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    channel_id = db.Column(db.Integer, db.ForeignKey('lounge_channel.id'), nullable=False)

    author = db.relationship("User", backref="lounge_messages")
    # Add a relationship for easy access from message to its channel
    channel = db.relationship("LoungeChannel", backref="messages")


# In server.py

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # The user who will RECEIVE the notification
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # A short description of the event, e.g., 'new_follower'
    event_type = db.Column(db.String(50), nullable=False)
    # The user who CAUSED the event (e.g., the person who followed you)
    actor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    reference_id = db.Column(db.Integer, nullable=True)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships to easily get user info
    user = db.relationship('User', foreign_keys=[user_id], backref='notifications')
    actor = db.relationship('User', foreign_keys=[actor_id])


class DM(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    # --- MODIFICATIONS ---
    message = db.Column(db.Text, nullable=True)  # Now nullable
    image = db.Column(db.Text, nullable=True)  # New column for image data
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    # --- END MODIFICATIONS ---

    reaction = db.Column(db.String(10), nullable=True)
    is_deleted = db.Column(db.Boolean, default=False, nullable=False)

    effect = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    sender = db.relationship("User", foreign_keys=[sender_id], backref="sent_messages")
    receiver = db.relationship("User", foreign_keys=[receiver_id], backref="received_messages")


post_likes = db.Table('post_likes',
                      db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
                      db.Column('post_id', db.Integer, db.ForeignKey('circuit_post.id'), primary_key=True)
                      )


class APIToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # This creates the link back to the User model
    user = db.relationship('User', backref='api_tokens')


class CircuitPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    image = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Foreign Keys to link posts to users and circuits
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    circuit_id = db.Column(db.Integer, db.ForeignKey("circuit.id"), nullable=False)

    # Relationships (how SQLAlchemy understands the links)
    author = db.relationship("User", backref="circuit_posts")
    circuit = db.relationship("Circuit", backref="posts")
    likes = db.relationship('User', secondary=post_likes, backref='liked_posts')


class Circuit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    host_school = db.Column(db.String(100))
    code = db.Column(db.String(10), unique=True, nullable=False)
    cover_image = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    owner = db.relationship("User", backref="owned_circuits")


# -------------------------------------------------
# Helpers
# -------------------------------------------------

def is_users_birthday(dob_str: str) -> bool:
    """Checks if the user's birthday is today in KST."""
    if not dob_str:
        return False
    try:
        # Get today's date in Korea Standard Time
        today_kst = datetime.now(KST).date()
        # Parse the user's date of birth string
        user_dob = datetime.strptime(dob_str, '%Y-%m-%d').date()
        # Compare month and day
        return user_dob.month == today_kst.month and user_dob.day == today_kst.day
    except (ValueError, TypeError):
        # Handle cases where the DOB is not a valid date string
        return False


def _increment_view(item_id, item_type):
    today_kst = datetime.now(KST).date()

    daily_view = DailyView.query.filter_by(
        date=today_kst,
        viewable_id=item_id,
        viewable_type=item_type
    ).first()

    if daily_view:
        daily_view.count += 1
    else:
        daily_view = DailyView(
            date=today_kst,
            viewable_id=item_id,
            viewable_type=item_type,
            count=1
        )
        db.session.add(daily_view)

    db.session.commit()
    return daily_view.count


def infer_grade_from_email(email: str) -> str | None:
    """
    Infers a student's grade level based on the graduation year in their email address.
    e.g., 'student2029@school.com' -> 'G9' (in Fall 2024).
    """
    if not email:
        return None

    # Regex to find a 4-digit year (20xx) or a 2-digit year (xx).
    # We remove the word boundaries (\b) to match numbers anywhere, like '29kim'.

    # --- BEFORE CHANGE ---
    # year_match = re.search(r'\b(20\d{2}|\d{2})\b', email)

    # --- AFTER CHANGE ---
    year_match = re.search(r'(20\d{2}|\d{2})', email)  # 👈 MODIFIED LINE

    if not year_match:
        return None

    grad_year_str = year_match.group(1)
    if len(grad_year_str) == 2:
        grad_year_str = '20' + grad_year_str  # Convert '29' to '2029'

    try:
        grad_year = int(grad_year_str)
    except ValueError:
        return None

    # Calculate current grade based on standard international school year (turnover in August)
    today = datetime.now()
    current_year = today.year
    # If it's August (8) or later, the new school year has started.
    # Seniors graduating next year (current_year + 1) are now in Grade 12.
    senior_graduation_year = current_year + 1 if today.month >= 8 else current_year

    grade = 12 - (grad_year - senior_graduation_year)

    if 0 < grade <= 12:
        return f'G{grade}'
    elif grade > 12:
        return 'University'  # For alumni
    else:
        # If grade calculation results in 0 or negative, they haven't started yet or year is far future.
        return None


def auth_user():
    token_str = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token_str = auth.split(" ", 1)[1].strip()
    else:
        token_str = auth.strip()  # Allow token as header value directly

    if not token_str:
        return None

    # Find the token in the new table and return the user it belongs to
    token_obj = APIToken.query.filter_by(token=token_str).first()
    if token_obj:
        return token_obj.user
    return None


@app.post("/api/articles")
def create_article():
    user = auth_user()
    if not user or user.rank not in ['admin', 'moderator']:
        return jsonify({"error": "Forbidden: You do not have permission to create articles."}), 403

    data = request.get_json(force=True)
    title = data.get("title", "").strip()
    content = data.get("content", "").strip()

    if not title or not content:
        return jsonify({"error": "Title and content are required"}), 400
    if len(title) > 200:
        return jsonify({"error": "Title cannot exceed 200 characters"}), 400

    new_article = Article(
        title=title,
        content=content,
        user_id=user.id
    )
    db.session.add(new_article)
    db.session.commit()

    return jsonify({"ok": True, "message": "Article created successfully!", "article_id": new_article.id}), 201


@app.get("/api/articles")
def get_articles():
    school_filter = request.args.get('school')
    query = Article.query
    if school_filter:
        query = query.join(User).filter(User.school == school_filter)

    articles = query.order_by(Article.created_at.desc()).all()
    today_kst = datetime.now(KST).date()

    # Get all of today's article views in one efficient query
    todays_views = {
        v.viewable_id: v.count
        for v in DailyView.query.filter_by(date=today_kst, viewable_type='article')
    }

    article_list = [
        {
            "id": article.id,
            "title": article.title,
            "excerpt": re.sub('<[^<]+?>', '', article.content)[:150],
            "schoolTag": article.author.school,
            "author": article.author.full_name,
            "daily_views": todays_views.get(article.id, 0)  # Get view from our dictionary
        } for article in articles
    ]
    return jsonify(article_list)


@app.get("/api/article/<int:article_id>")
def get_article(article_id):
    article = Article.query.get(article_id)
    if not article:
        return jsonify({"error": "Article not found"}), 404

    today_kst = datetime.now(KST).date()
    todays_view_obj = DailyView.query.filter_by(date=today_kst, viewable_type='article', viewable_id=article.id).first()
    views_today = todays_view_obj.count if todays_view_obj else 0

    return jsonify({
        "id": article.id,
        "title": article.title,
        "content": article.content,
        "schoolTag": article.author.school,
        "author": article.author.full_name,
        "daily_views": views_today  # <-- ADDED THIS
    })


@app.get("/api/dm/history/<username>")
def get_dm_history(username):
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401

    other_user = User.query.filter_by(username=username).first()
    if not other_user: return jsonify({"error": "User not found"}), 404

    DM.query.filter_by(sender_id=other_user.id, receiver_id=user.id, is_read=False).update({"is_read": True})
    db.session.commit()

    # Find conversation theme
    user1_id, user2_id = sorted((user.id, other_user.id))
    conversation = Conversation.query.filter_by(user1_id=user1_id, user2_id=user2_id).first()
    current_theme = conversation.theme if conversation else "apex"

    # Get all messages in the conversation
    messages = DM.query.filter(
        or_(
            (DM.sender_id == user.id) & (DM.receiver_id == other_user.id),
            (DM.sender_id == other_user.id) & (DM.receiver_id == user.id)
        )
    ).order_by(DM.created_at.asc()).all()

    # --- NEW: Efficiently fetch all reactions for this conversation ---
    message_ids = [msg.id for msg in messages]
    all_reactions = db.session.query(
        MessageReaction.message_id,
        MessageReaction.emoji,
        func.count(MessageReaction.user_id)
    ).filter(MessageReaction.message_id.in_(message_ids)).group_by(MessageReaction.message_id,
                                                                   MessageReaction.emoji).all()

    reactions_map = {}
    for msg_id, emoji, count in all_reactions:
        if msg_id not in reactions_map:
            reactions_map[msg_id] = {}
        reactions_map[msg_id][emoji] = count
    # --- END NEW LOGIC ---

    message_list = [
        {
            "id": msg.id,
            "sender": "me" if msg.sender_id == user.id else other_user.username,
            "text": msg.message,
            "image": msg.image,
            "is_deleted": msg.is_deleted,
            "time": msg.created_at.isoformat() + "Z",
            "reactions": reactions_map.get(msg.id, {})  # Get reactions from our map
        } for msg in messages
    ]

    return jsonify({"messages": message_list, "theme": current_theme})


@app.put("/api/dm/message/<int:message_id>/react")
def react_to_message(message_id):
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True)
    emoji = data.get("emoji")

    dm = DM.query.get(message_id)
    if not dm or (dm.sender_id != user.id and dm.receiver_id != user.id):
        return jsonify({"error": "Message not found"}), 404

    # --- NEW TOGGLE LOGIC ---
    # Check if this specific reaction from this user already exists.
    existing_reaction = MessageReaction.query.filter_by(
        message_id=message_id,
        user_id=user.id,
        emoji=emoji
    ).first()

    if existing_reaction:
        # If it exists, the user is toggling it OFF. So we delete it.
        db.session.delete(existing_reaction)
    else:
        # If it doesn't exist, the user is toggling it ON. So we add it.
        new_reaction = MessageReaction(message_id=message_id, user_id=user.id, emoji=emoji)
        db.session.add(new_reaction)
    # --- END OF NEW LOGIC ---

    db.session.commit()

    # After changes, get the new aggregated reactions for this message
    reactions_agg = db.session.query(
        MessageReaction.emoji,
        func.count(MessageReaction.user_id)
    ).filter_by(message_id=message_id).group_by(MessageReaction.emoji).all()

    reactions_payload = {emoji: count for emoji, count in reactions_agg}

    # Notify both users in the chat with the new, full reaction object
    socketio.emit("message_updated", {"message_id": dm.id, "reactions": reactions_payload}, room=f"user_{dm.sender_id}")
    socketio.emit("message_updated", {"message_id": dm.id, "reactions": reactions_payload},
                  room=f"user_{dm.receiver_id}")

    return jsonify({"ok": True})


@app.get("/api/users/for-chat")
def get_users_for_chat():
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    # Define weights for our relevance score
    POST_WEIGHT = 2
    FOLLOWER_WEIGHT = 3

    # This query calculates a "relevance_score" for each user
    # It joins the User table with CircuitPost and followers to get counts.
    users_with_scores = db.session.query(
        User,
        (func.count(func.distinct(CircuitPost.id)) * POST_WEIGHT + \
         func.count(func.distinct(followers.c.follower_id)) * FOLLOWER_WEIGHT).label('relevance_score')
    ).outerjoin(CircuitPost, User.id == CircuitPost.user_id) \
        .outerjoin(followers, User.id == followers.c.followed_id) \
        .filter(
        User.id != user.id,
        User.username != "ANNOUNCEMENTS"
    ).group_by(User.id).order_by(db.desc('relevance_score')).all()

    # Format the data for the frontend
    user_list = [
        {
            "username": u.username,
            "fullName": u.full_name,
            "rank": u.rank,
            "profile_pic": u.profile_pic,
            "account_type": u.account_type
        } for u, score in users_with_scores
    ]

    return jsonify(user_list)


@app.get("/api/dm/message/<int:message_id>/reaction/<emoji>")
def get_reaction_users(message_id, emoji):
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401

    # Find all reactions matching the message and emoji
    reactions = MessageReaction.query.filter_by(message_id=message_id, emoji=emoji).all()

    # Get the usernames of the users who reacted
    user_ids = [r.user_id for r in reactions]
    users = User.query.filter(User.id.in_(user_ids)).all()
    usernames = [u.username for u in users]

    return jsonify(usernames)


@app.put("/api/dm/message/<int:message_id>/edit")
def edit_message(message_id):
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True)
    new_text = data.get("new_text", "").strip()

    dm = DM.query.get(message_id)
    # Security: Only the sender can edit their own message
    if not dm or dm.sender_id != user.id:
        return jsonify({"error": "Message not found or you cannot edit it"}), 404
    if not new_text:
        return jsonify({"error": "Message cannot be empty"}), 400

    dm.message = new_text
    db.session.commit()

    socketio.emit("message_updated", {"message_id": dm.id, "text": dm.message}, room=f"user_{dm.sender_id}")
    socketio.emit("message_updated", {"message_id": dm.id, "text": dm.message}, room=f"user_{dm.receiver_id}")

    return jsonify({"ok": True})


@app.delete("/api/dm/message/<int:message_id>")
def delete_message(message_id):
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401

    dm = DM.query.get(message_id)
    # Security: Only the sender can delete their own message
    if not dm or dm.sender_id != user.id:
        return jsonify({"error": "Message not found or you cannot delete it"}), 404

    dm.is_deleted = True
    dm.message = None  # Clear message content
    dm.image = None  # Clear image content
    dm.reaction = None  # Clear reaction
    db.session.commit()

    socketio.emit("message_updated", {"message_id": dm.id, "is_deleted": True}, room=f"user_{dm.sender_id}")
    socketio.emit("message_updated", {"message_id": dm.id, "is_deleted": True}, room=f"user_{dm.receiver_id}")

    return jsonify({"ok": True})


@app.put("/api/dm/conversation/<username>/theme")
def set_conversation_theme(username):
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    other_user = User.query.filter_by(username=username).first()
    if not other_user:
        return jsonify({"error": "User not found"}), 404

    data = request.get_json(force=True)
    theme = data.get("theme")
    if theme not in ["apex", "colorless"]:  # Add more themes here in the future
        return jsonify({"error": "Invalid theme"}), 400

    # Find or create the conversation entry
    user1_id = min(user.id, other_user.id)
    user2_id = max(user.id, other_user.id)
    conversation = Conversation.query.filter_by(user1_id=user1_id, user2_id=user2_id).first()

    if not conversation:
        conversation = Conversation(user1_id=user1_id, user2_id=user2_id)
        db.session.add(conversation)

    conversation.theme = theme
    db.session.commit()

    return jsonify({"ok": True, "message": f"Theme set to {theme}"})


@app.get("/api/notifications")
def get_notifications():
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    notifications = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).limit(
        20).all()

    notif_list = []
    for notif in notifications:
        message = "A new notification."
        actor_username = notif.actor.username if notif.actor else None

        notif_dict = {
            "id": notif.id,
            "is_read": notif.is_read,
            "timestamp": notif.created_at.isoformat(),
            "actor_username": actor_username
        }

        if notif.event_type == 'new_follower' and notif.actor:
            message = f"**{notif.actor.username}** started following you!"
            notif_dict["reference_type"] = "user"  # Default to user profile

        elif notif.event_type == 'new_like' and notif.actor:
            post = CircuitPost.query.get(notif.reference_id)
            if post and post.circuit:
                message = f"**{notif.actor.username}** liked your post from **{post.circuit.title}**."
                # 👇 THIS IS THE FIX: Add post/circuit details for navigation
                notif_dict["reference_type"] = "post"
                notif_dict["reference_details"] = {
                    "post_id": post.id,
                    "circuit_id": post.circuit.id,
                    "circuit_title": post.circuit.title,
                    "circuit_host": post.circuit.host_school
                }
            else:
                message = f"**{notif.actor.username}** liked your post."
                notif_dict["reference_type"] = "user"  # Fallback to user profile

        notif_dict["message"] = message
        notif_list.append(notif_dict)

    return jsonify(notif_list)


@app.post("/api/posts/<int:post_id>/like")
def like_post(post_id):
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    post = CircuitPost.query.get(post_id)
    if not post:
        return jsonify({"error": "Post not found"}), 404

    if user in post.likes:
        return jsonify({"error": "You already liked this post"}), 409

    post.likes.append(user)

    if post.author.id != user.id:
        notification = Notification(
            user_id=post.author.id,
            event_type='new_like',
            actor_id=user.id,
            # 👇 THIS IS THE FIX 👇
            reference_id=post.id  # Add the ID of the post that was liked
        )
        db.session.add(notification)
        socketio.emit("new_notification", room=f"user_{post.author.id}")

    db.session.commit()
    return jsonify({"ok": True, "likes": len(post.likes)})


@app.post("/api/lounges")
def create_lounge():
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True)
    name = data.get("name", "").strip()
    description = data.get("description", "").strip()

    if not name:
        return jsonify({"error": "Lounge name is required"}), 400
    if len(name) > 30:
        return jsonify({"error": "Lounge name cannot exceed 30 characters"}), 400

    new_lounge = Lounge(
        name=name,
        description=description,
        owner_id=user.id
    )
    db.session.add(new_lounge)
    db.session.flush()  # Flush to get the new_lounge.id

    # --- ADD THIS BLOCK TO CREATE DEFAULT CHANNELS ---
    general_channel = LoungeChannel(name="general", lounge_id=new_lounge.id)
    random_channel = LoungeChannel(name="random", lounge_id=new_lounge.id)
    db.session.add_all([general_channel, random_channel])
    # --- END BLOCK ---

    db.session.commit()

    return jsonify({
        "ok": True,
        "message": "Lounge created successfully!",
        "lounge": {"id": new_lounge.id, "name": new_lounge.name}
    }), 201


@app.get("/api/lounges")
def get_lounges():
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    lounges = Lounge.query.order_by(Lounge.created_at.desc()).all()
    lounge_list = [
        {
            "id": lounge.id,
            "name": lounge.name,
            "description": lounge.description
        } for lounge in lounges
    ]
    return jsonify(lounge_list)


@app.get("/api/lounge/<int:lounge_id>/channels")
def get_lounge_channels(lounge_id):
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    lounge = Lounge.query.get(lounge_id)
    if not lounge:
        return jsonify({"error": "Lounge not found"}), 404

    channels = LoungeChannel.query.filter_by(lounge_id=lounge.id).order_by(LoungeChannel.id).all()
    return jsonify([{"id": c.id, "name": c.name} for c in channels])


# Modify the message fetching endpoint to get messages from a CHANNEL
@app.get("/api/lounge/channel/<int:channel_id>/messages")
def get_lounge_channel_messages(channel_id):
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    messages = LoungeMessage.query.filter_by(channel_id=channel_id).order_by(LoungeMessage.timestamp.desc()).limit(
        50).all()
    messages.reverse()

    message_list = []
    for msg in messages:
        if not msg.author:
            continue
        message_list.append({
            "id": msg.id,
            "text": msg.text,
            "image": msg.image,  # <-- ADD THIS
            "timestamp": msg.timestamp.isoformat(),
            "author": {
                "username": msg.author.username,
                "fullName": msg.author.full_name,
                "profilePic": msg.author.profile_pic,
                "rank": msg.author.rank
            }
        })
    return jsonify(message_list)




# In server.py, find and MODIFY the socketio event handlers

@socketio.on('send_lounge_message')
def handle_send_lounge_message(data):
    # Your user lookup logic is correct
    user = None
    token_str = socket_connections.get(request.sid)
    if token_str:
        token_obj = APIToken.query.filter_by(token=token_str).first()
        if token_obj:
            user = token_obj.user

    if not user:
        return

    text = data.get('text', '').strip()
    image_data = data.get('image') # Get image data if it exists
    # FIX 1: Get the correct key from the frontend ('channel_id' instead of 'lounge_id')
    channel_id = data.get('channel_id')

    # Make sure we have content (text or image) and a channel to post to
    if not (text or image_data) or not channel_id:
        return

    # FIX 2: Save the message with the correct 'channel_id'
    new_message = LoungeMessage(
        text=text,
        image=image_data,
        user_id=user.id,
        channel_id=channel_id
    )
    db.session.add(new_message)
    db.session.commit()

    # Create the full payload that the frontend's renderLoungeMessage function expects
    message_payload = {
        "id": new_message.id,
        "text": new_message.text,
        "image": new_message.image,
        "timestamp": new_message.timestamp.isoformat(),
        "channel_id": channel_id, # <-- ADD THIS LINE
        "author": {
            "username": user.username,
            "fullName": user.full_name,
            "profilePic": user.profile_pic,
            "rank": user.rank
        }
    }

    # FIX 3: Emit the message to the correct 'channel_X' room that users are in
    emit('new_lounge_message', message_payload, room=f"channel_{channel_id}")


# ADD these new handlers for joining/leaving lounge rooms
@socketio.on('join_lounge_channel')
def handle_join_lounge_channel(data):
    channel_id = data.get('channel_id')
    if channel_id:
        join_room(f"channel_{channel_id}")


@socketio.on('leave_lounge_channel')
def handle_leave_lounge_channel(data):
    channel_id = data.get('channel_id')
    if channel_id:
        leave_room(f"channel_{channel_id}")


@app.post("/api/posts/<int:post_id>/unlike")
def unlike_post(post_id):
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    post = CircuitPost.query.get(post_id)
    if not post:
        return jsonify({"error": "Post not found"}), 404

    if user not in post.likes:
        return jsonify({"error": "You have not liked this post"}), 409

    post.likes.remove(user)
    db.session.commit()
    return jsonify({"ok": True, "likes": len(post.likes)})


@app.post("/api/user/<username>/follow")
def follow_user(username):
    current_user = auth_user()
    if not current_user:
        return jsonify({"error": "unauthorized"}), 401

    user_to_follow = User.query.filter_by(username=username).first()
    if not user_to_follow:
        return jsonify({"error": "User not found"}), 404

    if current_user.id == user_to_follow.id:
        return jsonify({"error": "You cannot follow yourself"}), 400

    # Check if already following
    if current_user.following.filter(followers.c.followed_id == user_to_follow.id).count() > 0:
        return jsonify({"error": "You are already following this user"}), 409

    current_user.following.append(user_to_follow)

    notification = Notification(
        user_id=user_to_follow.id,
        event_type='new_follower',
        actor_id=current_user.id
    )
    db.session.add(notification)
    socketio.emit("new_notification", room=f"user_{user_to_follow.id}")
    db.session.commit()
    return jsonify({"ok": True, "message": f"You are now following {username}"})


@app.post("/api/notifications/mark-all-read")
def mark_notifications_read():
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    # Find all unread notifications for the user and update them
    Notification.query.filter_by(user_id=user.id, is_read=False).update({"is_read": True})
    db.session.commit()

    return jsonify({"ok": True})


@app.post("/api/user/<username>/unfollow")
def unfollow_user(username):
    current_user = auth_user()
    if not current_user:
        return jsonify({"error": "unauthorized"}), 401

    user_to_unfollow = User.query.filter_by(username=username).first()
    if not user_to_unfollow:
        return jsonify({"error": "User not found"}), 404

    # Check if the user is being followed
    if current_user.following.filter(followers.c.followed_id == user_to_unfollow.id).count() == 0:
        return jsonify({"error": "You are not following this user"}), 409

    current_user.following.remove(user_to_unfollow)
    db.session.commit()
    return jsonify({"ok": True, "message": f"You have unfollowed {username}"})


def issue_api_token(user: User) -> str:
    # Create a new token object linked to the user
    new_token = APIToken(
        user_id=user.id,
        token=secrets.token_hex(32)
    )
    db.session.add(new_token)
    db.session.commit()
    return new_token.token


# -------------------------------------------------
# Health
# -------------------------------------------------

@app.get("/api/circuits")
def get_circuits():
    if not auth_user():
        return jsonify({"error": "unauthorized"}), 401

    circuits = Circuit.query.all()
    today_kst = datetime.now(KST).date()

    # Get all of today's circuit views in one efficient query
    todays_views = {
        v.viewable_id: v.count
        for v in DailyView.query.filter_by(date=today_kst, viewable_type='circuit')
    }

    circuit_list = [
        {
            "id": circuit.id,
            "title": circuit.title,
            "hostSchool": circuit.host_school,
            "coverImage": circuit.cover_image,
            "code": circuit.code,
            "daily_views": todays_views.get(circuit.id, 0)
        } for circuit in circuits
    ]
    return jsonify(circuit_list)


@app.get("/health")
def health():
    return jsonify({"ok": True, "time": datetime.utcnow().isoformat()})


# -------------------------------------------------
# Auth (Local)
# -------------------------------------------------


# In server.py, replace the existing /api/signup function:

@app.post("/api/signup")
def signup():
    # --- Create APEX user on first-ever signup if it doesn't exist ---
    if not User.query.filter_by(username="APEX").first():
        print("First signup detected, creating APEX user...")
        system_user = User(username="APEX", email="apex@internal", rank="admin", password_hash="<UNUSABLE_PASSWORD>")
        db.session.add(system_user)
        db.session.commit()

    # --- Standard Signup Logic ---
    data = request.get_json(force=True)
    email = (data.get("email") or "").strip().lower()
    password = (data.get("password") or "").strip()
    full_name = data.get("fullName", "").strip()
    username = data.get("username", "").strip()
    school = data.get("school", "")
    account_type = data.get("accountType", "student")

    # --- Input Validation Block ---
    if not re.match(r'^[a-z0-9!._*-]{3,20}$', username):
        return jsonify({
            "error": "Username must be 3-20 characters, lowercase, and can only contain letters, numbers, and !._-*"
        }), 400
    if not re.match(r'^[a-zA-Z0-9!@#$%^&*()_+\-=<>,.?/]{5,}$', password):
        return jsonify({
            "error": "Password must be at least 5 characters and can only contain letters, numbers, and !@#$%^&*()_+-=<>,.?/"
        }), 400

    # --- Existing User Checks ---
    if not email or not password or not full_name or not username or not school:
        return jsonify({"error": "Missing required fields"}), 400
    if User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already registered"}), 409
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username is already taken"}), 409

    # --- First Human User Admin Logic ---
    is_first_human_user = User.query.filter(User.username != "APEX").first() is None
    new_rank = 'admin' if is_first_human_user else 'user'

    # --- Create Base User Object ---
    user = User(
        email=email,
        password_hash=generate_password_hash(password),
        full_name=full_name,
        username=username,
        school=school,
        account_type=account_type,
        rank=new_rank,
        provider="local"
    )

    # --- THIS IS THE REFACTORED AND CORRECTED LOGIC ---

    # Handle fields for Students and Teachers together since they share DOB
    if account_type in ['student', 'teacher']:
        dob_str = data.get("dob")
        if not dob_str:
            return jsonify({"error": "Date of Birth is required for this account type"}), 400
        try:
            datetime.strptime(dob_str, '%Y-%m-%d')
            user.dob = dob_str
        except ValueError:
            return jsonify({"error": "Invalid Date of Birth format. Please use the date picker."}), 400

        # Student-specific logic
        if account_type == 'student':
            user.grade = infer_grade_from_email(email)

        # Teacher-specific logic
        if account_type == 'teacher':
            user.subject = data.get("subject")
            if not user.subject:
                return jsonify({"error": "Subject is required for teacher accounts"}), 400

    # Handle fields for Team accounts
    elif account_type == 'team':
        user.dob = None  # Teams do not have a DOB

    # --- END OF REFACTORED LOGIC ---

    # --- Save the New User ---
    db.session.add(user)
    db.session.commit()

    # You might want to issue a token and log the user in directly here,
    # but for now, we'll just confirm creation.
    return jsonify({"ok": True, "message": "Account created successfully. Please log in."})


@app.post("/api/login")
def login():
    data = request.get_json(force=True)
    identifier = (data.get("email") or "").strip()
    password = (data.get("password") or "").strip()

    if not identifier or not password:
        return jsonify({"error": "username/email and password required"}), 400

    user = User.query.filter(
        or_(
            User.email == identifier.lower(),
            User.username == identifier
        )
    ).first()

    if user and user.is_banned:
        reason = f" Reason: {user.ban_reason}" if user.ban_reason else ""
        return jsonify({"error": f"This account has been banned.{reason}"}), 403

    if not user or not user.password_hash or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "invalid credentials"}), 401

    token = issue_api_token(user)

    # --- NEW: Gather user data to return directly ---
    following_list = [u.username for u in user.following]
    user_data = {
        "email": user.email,
        "fullName": user.full_name,
        "username": user.username,
        "school": user.school,
        "dob": user.dob,
        "bio": user.bio,
        "rank": user.rank,
        "provider": user.provider,
        "created_at": user.created_at.isoformat(),
        "has_bio": bool(user.bio),
        "following": following_list,
        "profile_pic": user.profile_pic,
        "account_type": user.account_type,
        "grade": user.grade,
        "subject": user.subject
    }
    # Return both the token and the user data object
    return jsonify({"token": token, "user": user_data})


@app.post("/api/logout")
def logout():
    # We need to get the raw token string to delete the correct entry
    token_str = None
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        token_str = auth.split(" ", 1)[1].strip()

    if not token_str:
        return jsonify({"error": "unauthorized"}), 401

    # Find the token in the database and delete it
    token_to_delete = APIToken.query.filter_by(token=token_str).first()
    if token_to_delete:
        db.session.delete(token_to_delete)
        db.session.commit()

    return jsonify({"ok": True})


@app.post("/api/user/<username>/ban")
def ban_user(username):
    admin_user = auth_user()
    if not admin_user or admin_user.rank != 'admin':
        return jsonify({"error": "Forbidden: Admin access required"}), 403

    target_user = User.query.filter_by(username=username).first()
    if not target_user:
        return jsonify({"error": "Target user not found"}), 404

    reason = request.get_json(force=True).get("reason", "")
    target_user.is_banned = True
    target_user.ban_reason = reason
    target_user.token = None  # Log them out
    db.session.commit()
    return jsonify({"ok": True, "message": f"User {username} has been banned."})


@app.post("/api/user/<username>/unban")
def unban_user(username):
    admin_user = auth_user()
    if not admin_user or admin_user.rank != 'admin':
        return jsonify({"error": "Forbidden: Admin access required"}), 403

    target_user = User.query.filter_by(username=username).first()
    if not target_user:
        return jsonify({"error": "Target user not found"}), 404

    target_user.is_banned = False
    target_user.ban_reason = None
    db.session.commit()
    return jsonify({"ok": True, "message": f"User {username} has been unbanned."})


@app.get("/api/user/<username>/whois")
def whois_user(username):
    mod_user = auth_user()
    if not mod_user or mod_user.rank not in ['admin', 'moderator']:
        return jsonify({"error": "Forbidden: Moderator access required"}), 403

    target_user = User.query.filter_by(username=username).first()
    if not target_user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "username": target_user.username,
        "fullName": target_user.full_name,
        "email": target_user.email,
        "rank": target_user.rank,
        "school": target_user.school,
        "join_date": target_user.created_at.isoformat(),
        "is_banned": target_user.is_banned,
        "ban_reason": target_user.ban_reason
    })


@app.post("/api/dm/system-send")
def system_send_dm():
    mod_user = auth_user()
    if not mod_user or mod_user.rank not in ['admin', 'moderator']:
        return jsonify({"error": "Forbidden: Moderator access required"}), 403

    system_user = User.query.filter_by(username="APEX").first()
    if not system_user:
        return jsonify({"error": "System user not found. Critical error."}), 500

    data = request.get_json(force=True)
    message = data.get("message", "")
    to_username = data.get("to_username")  # For /warn
    broadcast = data.get("broadcast", False)  # For /broadcast

    if not message:
        return jsonify({"error": "Message is required"}), 400

    if broadcast:
        all_users = User.query.filter(User.username != "System").all()
        for user in all_users:
            dm = DM(sender_id=system_user.id, receiver_id=user.id, message=message)
            db.session.add(dm)
        db.session.commit()
        return jsonify({"ok": True, "message": "Broadcast sent to all users."})

    elif to_username:
        target_user = User.query.filter_by(username=to_username).first()
        if not target_user:
            return jsonify({"error": f"User {to_username} not found."}), 404
        dm = DM(sender_id=system_user.id, receiver_id=target_user.id, message=message)
        db.session.add(dm)
        db.session.commit()
        return jsonify({"ok": True, "message": f"Warning sent to {to_username}."})

    else:
        return jsonify({"error": "Recipient or broadcast flag required."}), 400


@app.put("/api/circuit/<int:circuit_id>")
def edit_circuit(circuit_id):
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    circuit = Circuit.query.get(circuit_id)
    if not circuit:
        return jsonify({"error": "Circuit not found"}), 404

    if circuit.user_id != user.id and user.rank != 'admin':
        return jsonify({"error": "Forbidden: You are not the owner of this circuit."}), 403

    data = request.get_json(force=True)
    # --- THIS IS THE FIX ---
    # We define title and host_school first from the incoming data.
    title = data.get("title", circuit.title).strip()
    host_school = data.get("hostSchool", circuit.host_school).strip()

    # Now we can check their length.
    if len(title) > 30:
        return jsonify({"error": "Title cannot exceed 30 characters"}), 400
    if len(host_school) > 20:
        return jsonify({"error": "Affiliation cannot exceed 20 characters"}), 400

    # And finally, we assign the validated values back to the circuit object.
    circuit.title = title
    circuit.host_school = host_school
    # --- END OF FIX ---

    # Process a new cover image if one was sent
    cover_image_data_url = data.get("coverImage")
    if cover_image_data_url and cover_image_data_url.startswith('data:image'):
        try:
            header, encoded = cover_image_data_url.split(",", 1)
            image_bytes = base64.b64decode(encoded)
            with Image.open(io.BytesIO(image_bytes)) as img:
                img.thumbnail((512, 512))
                output_buffer = io.BytesIO()
                img.save(output_buffer, format='WEBP', quality=85)
                webp_image_bytes = output_buffer.getvalue()
            base64_webp = base64.b64encode(webp_image_bytes).decode('utf-8')
            circuit.cover_image = f"data:image/webp;base64,{base64_webp}"
        except Exception as e:
            print(f"Could not process edited circuit cover image: {e}")

    db.session.commit()
    return jsonify({"ok": True, "message": "Circuit updated successfully!"})


@app.delete("/api/circuit/<int:circuit_id>")
def delete_circuit(circuit_id):
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    circuit = Circuit.query.get(circuit_id)
    if not circuit:
        return jsonify({"error": "Circuit not found"}), 404

    # --- PERMISSION CHECK ---
    # Only allow the owner of the circuit or an admin to delete it.
    if circuit.user_id != user.id and user.rank != 'admin':
        return jsonify({"error": "Forbidden: You do not have permission to delete this circuit."}), 403

    # --- DELETION LOGIC ---
    # First, delete all posts associated with this circuit to maintain database integrity.
    CircuitPost.query.filter_by(circuit_id=circuit.id).delete()

    # Now, delete the circuit itself.
    db.session.delete(circuit)
    db.session.commit()

    return jsonify({"ok": True, "message": "Circuit and all its posts have been deleted."})


@app.get("/api/circuit/<int:circuit_id>")
def get_circuit_details(circuit_id):
    if not auth_user():
        return jsonify({"error": "unauthorized"}), 401

    circuit = Circuit.query.get(circuit_id)
    if not circuit:
        return jsonify({"error": "Circuit not found"}), 404

    today_kst = datetime.now(KST).date()
    todays_view_obj = DailyView.query.filter_by(date=today_kst, viewable_type='circuit', viewable_id=circuit.id).first()
    views_today = todays_view_obj.count if todays_view_obj else 0

    return jsonify({
        "id": circuit.id,
        "title": circuit.title,
        "hostSchool": circuit.host_school,
        "coverImage": circuit.cover_image,
        "code": circuit.code,
        "owner_username": circuit.owner.username if circuit.owner else None,
        "daily_views": views_today  # This now correctly returns today's view count
    })


@app.get("/api/circuit/<int:circuit_id>/posts")
def get_circuit_posts(circuit_id):
    user = auth_user()  # We need to know who is asking
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    posts = CircuitPost.query.filter_by(circuit_id=circuit_id).order_by(CircuitPost.created_at.desc()).all()

    post_list = [
        {
            "id": post.id,
            "text": post.text,
            "image": post.image,
            "timestamp": post.created_at.isoformat(),
            "author": {
                "username": post.author.username,
                "fullName": post.author.full_name,
                "rank": post.author.rank
            },
            # 👇 ADD THESE TWO NEW FIELDS
            "likes": len(post.likes),
            "is_liked_by_me": user in post.likes
        } for post in posts
    ]
    return jsonify(post_list)


@app.post("/api/circuits")
def create_circuit():
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True)
    title = data.get("title", "").strip()
    host_school = data.get("hostSchool", "").strip()

    if len(title) > 30:
        return jsonify({"error": "Title cannot exceed 30 characters"}), 400
    if len(host_school) > 20:
        return jsonify({"error": "Affiliation cannot exceed 20 characters"}), 400

    # 👇 NEW IMAGE PROCESSING LOGIC
    cover_image_data_url = data.get("coverImage")
    processed_image_data = None
    if cover_image_data_url and cover_image_data_url.startswith('data:image'):
        try:
            header, encoded = cover_image_data_url.split(",", 1)
            image_bytes = base64.b64decode(encoded)
            with Image.open(io.BytesIO(image_bytes)) as img:
                img.thumbnail((512, 512))  # Resize to a reasonable size for a cover
                output_buffer = io.BytesIO()
                img.save(output_buffer, format='WEBP', quality=85)
                webp_image_bytes = output_buffer.getvalue()
            base64_webp = base64.b64encode(webp_image_bytes).decode('utf-8')
            processed_image_data = f"data:image/webp;base64,{base64_webp}"
        except Exception as e:
            print(f"Could not process circuit cover image: {e}")
    # 👆 END OF NEW LOGIC

    if not title or not host_school:
        return jsonify({"error": "Title and host school are required"}), 400

    while True:
        new_code = str(secrets.randbelow(900000) + 100000)
        if not Circuit.query.filter_by(code=new_code).first():
            break

    new_circuit = Circuit(
        title=title,
        host_school=host_school,
        cover_image=processed_image_data,  # Use the processed image
        code=new_code,
        user_id=user.id  # 👈 STORE THE OWNER
    )

    db.session.add(new_circuit)
    db.session.commit()

    return jsonify({
        "ok": True,
        "message": "Circuit created successfully!",
        "circuit": {
            "id": new_circuit.id,
            "title": new_circuit.title,
            "hostSchool": new_circuit.host_school,
            "code": new_circuit.code
        }
    }), 201


@app.post("/api/circuit/<int:circuit_id>/posts")
def create_circuit_post(circuit_id):
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    circuit = Circuit.query.get(circuit_id)
    if not circuit:
        return jsonify({"error": "Circuit not found"}), 404

    data = request.get_json(force=True)
    text = data.get("text", "").strip()
    image_data_url = data.get("image")  # Get the image from the request
    processed_image_data = None

    if not text:
        return jsonify({"error": "Post text cannot be empty"}), 400
    if len(text) > 600:
        return jsonify({"error": "Post cannot exceed 600 characters"}), 413

    # --- ADD THIS IMAGE PROCESSING BLOCK ---
    if image_data_url and image_data_url.startswith('data:image'):
        try:
            header, encoded = image_data_url.split(",", 1)
            image_bytes = base64.b64decode(encoded)
            with Image.open(io.BytesIO(image_bytes)) as img:
                img.thumbnail((1024, 1024))  # Larger size for posts
                output_buffer = io.BytesIO()
                img.save(output_buffer, format='WEBP', quality=85)
                webp_image_bytes = output_buffer.getvalue()
            base64_webp = base64.b64encode(webp_image_bytes).decode('utf-8')
            processed_image_data = f"data:image/webp;base64,{base64_webp}"
        except Exception as e:
            print(f"Could not process post image: {e}")
    # --- END OF BLOCK ---

    new_post = CircuitPost(
        text=text,
        image=processed_image_data,  # Save the processed image
        user_id=user.id,
        circuit_id=circuit.id
    )
    db.session.add(new_post)
    db.session.commit()

    return jsonify({"ok": True, "message": "Post created successfully!"}), 201


STOP_WORDS = set(['a', 'an', 'and', 'the', 'in', 'on', 'is', 'are', 'it', 'of', 'for', 'to', 'i'])


@app.get("/api/search")
def search():
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    query = request.args.get('q', '').strip().lower()
    if not query:
        return jsonify({"error": "Search query cannot be empty"}), 400

    # 1. Tokenize the search query and remove stop words
    search_terms = [term for term in re.split(r'\s+', query) if term not in STOP_WORDS]
    if not search_terms:
        return jsonify({"users": [], "circuits": [], "lounges": [], "articles": []})

    # 2. Build flexible filter conditions for each content type
    user_filters = or_(*[User.full_name.ilike(f'%{term}%') for term in search_terms],
                       *[User.username.ilike(f'%{term}%') for term in search_terms])

    circuit_filters = or_(*[Circuit.title.ilike(f'%{term}%') for term in search_terms],
                          *[Circuit.host_school.ilike(f'%{term}%') for term in search_terms])

    lounge_filters = or_(*[Lounge.name.ilike(f'%{term}%') for term in search_terms],
                         *[Lounge.description.ilike(f'%{term}%') for term in search_terms])

    article_filters = or_(*[Article.title.ilike(f'%{term}%') for term in search_terms],
                          *[Article.content.ilike(f'%{term}%') for term in search_terms])

    # 3. Execute all search queries, limiting results to 10 per category
    users = User.query.filter(user_filters).limit(10).all()
    circuits = Circuit.query.filter(circuit_filters).limit(10).all()
    lounges = Lounge.query.filter(lounge_filters).limit(10).all()
    articles = Article.query.filter(article_filters).limit(10).all()

    # 4. Format and return all results in organized categories
    results = {
        "users": [{"username": u.username, "fullName": u.full_name, "rank": u.rank, "profile_pic": u.profile_pic} for u
                  in users],
        "circuits": [{"id": c.id, "title": c.title, "hostSchool": c.host_school, "coverImage": c.cover_image} for c in
                     circuits],
        "lounges": [{"id": l.id, "name": l.name, "description": l.description} for l in lounges],
        "articles": [{"id": a.id, "title": a.title, "author": a.author.full_name, "schoolTag": a.author.school} for a in
                     articles]
    }
    return jsonify(results)


@app.get("/api/trending")
def get_trending_items():
    # --- THIS IS THE NEW PART ---
    # Get a limit from the request args, defaulting to 5.
    # We'll fetch more for the "All Trending" page.
    limit = request.args.get('limit', 5, type=int)
    # --- END NEW PART ---

    today_kst = datetime.now(KST).date()
    yesterday_kst = today_kst - timedelta(days=1)

    todays_views_raw = DailyView.query.filter_by(date=today_kst).all()
    yesterdays_views_raw = DailyView.query.filter_by(date=yesterday_kst).all()

    todays_map = {(v.viewable_type, v.viewable_id): v.count for v in todays_views_raw}
    yesterdays_map = {(v.viewable_type, v.viewable_id): v.count for v in yesterdays_views_raw}

    trending = []
    for (item_type, item_id), today_count in todays_map.items():
        yesterday_count = yesterdays_map.get((item_type, item_id), 0)
        growth = today_count - yesterday_count
        if growth > 0:
            trending.append({
                "id": item_id,
                "type": item_type,
                "views": today_count,
                "growth": growth
            })

    trending.sort(key=lambda x: (x['growth'], x['views']), reverse=True)

    top_items = []
    # --- THIS PART NOW USES THE NEW LIMIT ---
    for item_data in trending[:limit]:
        if item_data['type'] == 'article':
            item = Article.query.get(item_data['id'])
            if item and item.author:
                top_items.append({
                    "type": "article", "id": item.id, "title": item.title,
                    "author": item.author.full_name, "schoolTag": item.author.school,
                    "daily_views": item_data['views']
                })
        elif item_data['type'] == 'circuit':
            item = Circuit.query.get(item_data['id'])
            if item:
                top_items.append({
                    "type": "circuit", "id": item.id, "title": item.title,
                    "hostSchool": item.host_school, "coverImage": item.cover_image,
                    "daily_views": item_data['views']
                })

    return jsonify(top_items)


# In server.py, update the /api/me endpoint:
@app.get("/api/me")
def me():
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    following_list = [u.username for u in user.following]
    post_count = CircuitPost.query.filter_by(user_id=user.id).count()
    return jsonify({
        "email": user.email,
        "fullName": user.full_name,
        "username": user.username,
        "school": user.school,
        "dob": user.dob,
        "bio": user.bio,
        "rank": user.rank,
        "provider": user.provider,
        "created_at": user.created_at.isoformat(),
        "has_bio": bool(user.bio),
        "post_count": post_count,
        "following": following_list,
        "profile_pic": user.profile_pic,
        # --- ADD NEW FIELDS ---
        "account_type": user.account_type,
        "grade": user.grade,
        "subject": user.subject,
        "is_birthday": is_users_birthday(user.dob)
    })


# Helper dictionary to map connection IDs to tokens
socket_connections = {}


@socketio.on("connect")
def handle_connect():
    token_str = request.args.get("token")
    if not token_str:
        return False

    token_obj = APIToken.query.filter_by(token=token_str).first()
    if not token_obj:
        return False

    socket_connections[request.sid] = token_str

    user = token_obj.user
    join_room(f"user_{user.id}")
    emit("system", {"msg": f"Connected as {user.email}"})


@socketio.on('disconnect')
def handle_disconnect_event():
    if request.sid in socket_connections:
        del socket_connections[request.sid]


# In server.py, update the /api/user/<username> endpoint:
@app.get("/api/user/<username>")
def get_user_profile(username):
    if not auth_user():
        return jsonify({"error": "unauthorized"}), 401

    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({"error": "User not found"}), 404
    post_count = CircuitPost.query.filter_by(user_id=user.id).count()
    return jsonify({
        "username": user.username,
        "fullName": user.full_name,
        "email": user.email,
        "school": user.school,
        "bio": user.bio,
        "rank": user.rank,
        "post_count": post_count,
        "profile_pic": user.profile_pic,
        # --- ADD NEW FIELDS ---
        "account_type": user.account_type,
        "grade": user.grade,
        "subject": user.subject,
        "is_birthday": is_users_birthday(user.dob)
    })


@app.post("/api/users/details")
def get_users_details():
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True)
    usernames = data.get("usernames", [])

    if not usernames:
        return jsonify([])

    # Find all users whose username is in the provided list
    users = User.query.filter(User.username.in_(usernames)).all()

    user_list = [
        {
            "username": u.username,
            "fullName": u.full_name,
            "rank": u.rank,
            "profile_pic": u.profile_pic
        } for u in users
    ]
    return jsonify(user_list)


@app.get("/api/users")
def get_users():
    current_user = auth_user()
    if not current_user:
        return jsonify({"error": "unauthorized"}), 401

    system_usernames = ["ANNOUNCEMENTS"]
    users = User.query.filter(
        User.id != current_user.id,
        User.username.notin_(system_usernames)
    ).order_by(User.created_at.desc()).limit(10).all()

    user_list = [
        {
            "username": user.username,
            # --- THIS IS THE FIX ---
            "fullName": user.full_name,  # Changed from user.fullName
            # --- END OF FIX ---
            "rank": user.rank,
            "profile_pic": user.profile_pic,
            "account_type": user.account_type,
            "is_birthday": is_users_birthday(user.dob)
        }
        for user in users
    ]
    return jsonify(user_list)


@app.post("/api/user/<username>/rank")
def set_user_rank(username):
    # Step 1: Check if the person making the request is an admin
    admin_user = auth_user()
    if not admin_user or admin_user.rank != 'admin':
        return jsonify({"error": "Forbidden: Admin access required"}), 403

    # Step 2: Get the new rank from the request
    data = request.get_json(force=True)
    new_rank = data.get("rank")
    if new_rank not in ['user', 'moderator', 'admin']:
        return jsonify({"error": "Invalid rank provided"}), 400

    # Step 3: Find the target user and update their rank
    target_user = User.query.filter_by(username=username).first()
    if not target_user:
        return jsonify({"error": "Target user not found"}), 404

    target_user.rank = new_rank
    db.session.commit()

    return jsonify({"ok": True, "message": f"{username}'s rank has been updated to {new_rank}."})


# In server.py


@app.get("/api/dm/conversations")
def get_conversations():
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    # --- NEW: Efficiently get all unread message counts in one query ---
    unread_counts_query = db.session.query(
        DM.sender_id, func.count(DM.id)
    ).filter_by(
        receiver_id=user.id, is_read=False
    ).group_by(DM.sender_id).all()
    
    unread_map = dict(unread_counts_query)
    # --- END NEW ---

    sent_dms = DM.query.filter_by(sender_id=user.id).all()
    received_dms = DM.query.filter_by(receiver_id=user.id).all()
    conversations = {}
    all_dms = sorted(sent_dms + received_dms, key=lambda dm: dm.created_at)

    for dm in all_dms:
        other_user = dm.receiver if dm.sender_id == user.id else dm.sender
        if dm.sender_id == user.id:
            last_message_text = f"You: {dm.message}" if dm.message else "You sent an image."
        else:
            last_message_text = dm.message if dm.message else "Sent you an image."

        conversations[other_user.username] = {
            "last_message": last_message_text,
            "timestamp": dm.created_at.isoformat(),
            "unread_count": unread_map.get(other_user.id, 0), # <-- ADD THIS
            "other_user": {
                "username": other_user.username,
                "fullName": other_user.full_name,
                "rank": other_user.rank,
                "profile_pic": other_user.profile_pic,
                "account_type": other_user.account_type
            }
        }

    sorted_convos = sorted(conversations.values(), key=lambda x: x['timestamp'], reverse=True)
    return jsonify(sorted_convos)


@app.post("/api/article/<int:article_id>/view")
def increment_article_view(article_id):
    if not Article.query.get(article_id):
        return jsonify({"error": "Article not found"}), 404
    views = _increment_view(article_id, 'article')
    return jsonify({"ok": True, "views": views})


@app.post("/api/circuit/<int:circuit_id>/view")
def increment_circuit_view(circuit_id):
    if not Circuit.query.get(circuit_id):
        return jsonify({"error": "Circuit not found"}), 404
    views = _increment_view(circuit_id, 'circuit')
    return jsonify({"ok": True, "views": views})


@app.put("/api/profile")  # 👈 Note the new URL
def set_profile():
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True)
    new_username = data.get("username", "").strip()

    # Check if another user already has the new username
    if new_username and new_username != user.username:
        if User.query.filter_by(username=new_username).first():
            return jsonify({"error": "Username is already taken"}), 409
        user.username = new_username

    user.full_name = data.get("fullName", user.full_name).strip()
    user.bio = data.get("bio", user.bio)

    profile_pic_data_url = data.get("profilePic")
    if profile_pic_data_url and profile_pic_data_url.startswith('data:image'):
        try:
            # 1. Parse the Data URL to get the Base64 string
            header, encoded = profile_pic_data_url.split(",", 1)

            # 2. Decode the Base64 string into bytes
            image_bytes = base64.b64decode(encoded)

            # 3. Open the image with Pillow
            with Image.open(io.BytesIO(image_bytes)) as img:
                # 4. Resize the image to a max of 256x256 to save space
                img.thumbnail((256, 256))

                # 5. Save the resized image to a buffer in WEBP format
                output_buffer = io.BytesIO()
                img.save(output_buffer, format='WEBP', quality=80)
                webp_image_bytes = output_buffer.getvalue()

            # 6. Encode the new WEBP image back to a Base64 string
            base64_webp = base64.b64encode(webp_image_bytes).decode('utf-8')

            # 7. Store the full Data URL in the database
            user.profile_pic = f"data:image/webp;base64,{base64_webp}"

        except Exception as e:
            print(f"Could not process profile image: {e}")
            # This will skip the image update if something goes wrong

    db.session.commit()
    return jsonify({
        "ok": True,
        "message": "Profile updated successfully!",
        "user": {
            "fullName": user.full_name,
            "username": user.username,
            "bio": user.bio,
            "profile_pic": user.profile_pic
        }
    })


# -------------------------------------------------
# Auth (Google OAuth)
# -------------------------------------------------
@app.get("/auth/google/login")
def google_login():
    # 콜백 URL
    redirect_uri = url_for("google_callback", _external=True)
    # (선택) 클라이언트로 되돌아갈 URL을 쿼리로 전달 가능
    client_redirect = request.args.get("redirect")
    if client_redirect:
        # state에 넣어 왕복
        return google.authorize_redirect(redirect_uri, state=client_redirect)
    return google.authorize_redirect(redirect_uri)


@app.get("/auth/google/callback")
def google_callback():
    # 토큰 교환
    try:
        token = google.authorize_access_token()
    except Exception as e:
        return make_response(f"Google OAuth failed: {e}", 400)

    # OpenID Connect ID 토큰(또는 userinfo) 파싱
    try:
        idinfo = google.parse_id_token(token)
    except Exception:
        idinfo = token.get("userinfo", {})

    email = (idinfo.get("email") or "").lower().strip()
    sub = idinfo.get("sub")  # 구글 고유 ID
    if not email:
        return make_response("No email returned from Google.", 400)

    user = User.query.filter_by(email=email).first()
    if not user:
        user = User(email=email, provider="google", oauth_sub=sub)
        db.session.add(user)
        db.session.commit()
    else:
        # 기존 로컬 계정이더라도 구글 연동 허용(필요 시 정책에 맞게 제한)
        user.provider = user.provider or "google"
        if not user.oauth_sub:
            user.oauth_sub = sub
        db.session.commit()

    api_token = issue_api_token(user)

    # state에 전달된 클라이언트 리다이렉트 경로가 있다면 거기로 보냄
    client_redirect = request.args.get("state")
    if client_redirect:
        # 토큰을 쿼리로 넘김 (HTTPS에서만 사용 권장! 실제 배포 시 보안 고려)
        sep = "&" if "?" in client_redirect else "?"
        return redirect(f"{client_redirect}{sep}token={api_token}")

    # 기본 응답(간단 HTML: window.opener로 토큰 전달 → 팝업 로그인 시 용이)
    html = f"""
<!doctype html>
<html>
  <body>
    <script>
      (function(){{
        try {{
          if (window.opener) {{
            window.opener.postMessage({{"type":"GOOGLE_LOGIN_SUCCESS","token":"{api_token}"}}, "*");
            window.close();
          }}
        }} catch (e) {{}}
      }})();
    </script>
    <pre>Google login success. Your API token:
{api_token}

You can now close this window.</pre>
  </body>
</html>
"""
    resp = make_response(html, 200)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    return resp


# -------------------------------------------------
# Bio APIs
# -------------------------------------------------
@app.get("/api/bio")
def get_bio():
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"bio": user.bio or ""})


@app.put("/api/bio")
def set_bio():
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(force=True)
    bio = data.get("bio")
    if bio is None or not isinstance(bio, str):
        return jsonify({"error": "bio string required"}), 400
    if len(bio) > 20000:
        return jsonify({"error": "bio too long"}), 413
    user.bio = bio
    db.session.commit()
    return jsonify({"ok": True, "bio": user.bio})


# -------------------------------------------------
# DM APIs
# -------------------------------------------------
@app.post("/api/dm/send")
def send_dm():
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(force=True)
    receiver_username = data.get("to_username", "").strip()
    message_text = data.get("message", "").strip()
    image_data = data.get("image")  # Can be a Base64 string

    if not receiver_username or (not message_text and not image_data):
        return jsonify({"error": "Receiver and message/image are required"}), 400

    receiver = User.query.filter_by(username=receiver_username).first()
    if not receiver:
        return jsonify({"error": "Receiver not found"}), 404

    dm = DM(
        sender_id=user.id,
        receiver_id=receiver.id,
        message=message_text if message_text else None,
        image=image_data
    )
    db.session.add(dm)
    db.session.commit()

    # Update the socket event to include image data
    socketio.emit("dm_received", {
        "id": dm.id,
        "from": user.username,
        "message": dm.message,
        "image": dm.image,  # <-- ADD THIS LINE
        "created_at": dm.created_at.isoformat() + "Z"
    }, room=f"user_{receiver.id}")

    return jsonify({"ok": True, "dm_id": dm.id})


@app.get("/api/dm/inbox")
def inbox():
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    dms = DM.query.filter_by(receiver_id=user.id).order_by(DM.created_at.desc()).all()
    return jsonify([
        {"id": dm.id, "from": dm.sender.email, "message": dm.message,
         "created_at": dm.created_at.isoformat()} for dm in dms
    ])


@app.get("/api/dm/sent")
def sent():
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401
    dms = DM.query.filter_by(sender_id=user.id).order_by(DM.created_at.desc()).all()
    return jsonify([
        {"id": dm.id, "to": dm.receiver.email, "message": dm.message,
         "created_at": dm.created_at.isoformat()} for dm in dms
    ])


# -------------------------------------------------
# Socket.IO (실시간 DM)
# -------------------------------------------------


# -------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        # --- THIS IS THE FIX ---
        # Create APEX user if it doesn't exist
        if not User.query.filter_by(username="ANNOUNCEMENTS").first():
            print("Creating APEX user...")
            # The username is now 'APEX' and the email is 'apex@internal'
            system_user = User(username="ANNOUNCEMENTS", full_name="ANNOUNCEMENTS", email="apex@announcements",
                               rank="admin")
            db.session.add(system_user)
            db.session.commit()
        # --- END OF FIX ---

        # Seeding logic for circuits
        if not Circuit.query.first():
            print("Seeding database with initial circuits...")
            # c1 = Circuit(title='KAIAC Soccer Finals 2025', host_school='YISS', code='100001')
            # c2 = Circuit(title='SFS Fall Festival', host_school='SFS', code='100002')
            # db.session.add_all([c1, c2])
            db.session.commit()

    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=True)