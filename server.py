import os, secrets, markdown
from flask import Flask, request, jsonify, redirect, url_for, make_response, send_file, render_template
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
from flask_migrate import Migrate
import subprocess

# -------------------------------------------------
# App / Config
# -------------------------------------------------
app = Flask(__name__, template_folder='.')

CORS(app)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", secrets.token_hex(16))
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///app.db?timeout=15")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Google OAuth config (환경변수에서 읽음)
app.config["GOOGLE_CLIENT_ID"] = os.environ.get("GOOGLE_CLIENT_ID", "")
app.config["GOOGLE_CLIENT_SECRET"] = os.environ.get("GOOGLE_CLIENT_SECRET", "")
KST = pytz.timezone('Asia/Seoul')
db = SQLAlchemy(app)
migrate = Migrate(app, db)
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

class StoredAsset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)  # e.g., 'logo.png'
    mimetype = db.Column(db.String(100), nullable=False)          # e.g., 'image/webp'
    data = db.Column(db.Text, nullable=False) 

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
        lazy='dynamic')
    lounge_memberships = db.relationship('LoungeMember', backref='user', cascade='all, delete-orphan')
    
class LoungeMessageReaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.Integer, db.ForeignKey('lounge_message.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    emoji = db.Column(db.String(10), nullable=False)

    __table_args__ = (db.UniqueConstraint('message_id', 'user_id', 'emoji', name='_lounge_message_user_emoji_uc'),)

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


class LoungeMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    lounge_id = db.Column(db.Integer, db.ForeignKey('lounge.id'), nullable=False)
    role = db.Column(db.String(50), nullable=False, default='member')  # 'member', 'moderator', 'owner'

    # A user can only have one role per lounge
    __table_args__ = (db.UniqueConstraint('user_id', 'lounge_id', name='_user_lounge_uc'),)

class Lounge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # --- ADD THESE TWO LINES ---
    cover_image = db.Column(db.Text, nullable=True)
    privacy = db.Column(db.String(50), default='public', nullable=False) # 'public', 'private', 'unlisted'

    owner = db.relationship("User", backref="owned_lounges")
    channels = db.relationship("LoungeChannel", backref="lounge", cascade="all, delete-orphan")
    members = db.relationship('LoungeMember', backref='lounge', cascade="all, delete-orphan")


class LoungeChannel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    lounge_id = db.Column(db.Integer, db.ForeignKey('lounge.id'), nullable=False)
    permission_level = db.Column(db.String(50), default='public', nullable=False)
    
    # ▼▼▼ ADD THIS LINE ▼▼▼
    is_main = db.Column(db.Boolean, default=False, nullable=False, index=True)

    messages = db.relationship("LoungeMessage", backref="channel", cascade="all, delete-orphan")


class LoungeMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=True)
    image = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(pytz.timezone('UTC')))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    channel_id = db.Column(db.Integer, db.ForeignKey('lounge_channel.id'), nullable=False)
    message_type = db.Column(db.String(50), default='user_message', nullable=False)
    
    reactions = db.relationship('LoungeMessageReaction', backref='message', cascade='all, delete-orphan')
    author = db.relationship("User", backref="lounge_messages")


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
    status = db.Column(db.String(50), default='pending', nullable=True)
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

@app.delete("/api/lounge/<int:lounge_id>")
def delete_lounge(lounge_id):
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    lounge = Lounge.query.get(lounge_id)
    if not lounge:
        return jsonify({"error": "Lounge not found"}), 404

    # --- PERMISSION CHECK: Only the owner can delete the lounge ---
    if lounge.owner_id != user.id:
        return jsonify({"error": "Forbidden: You are not the owner of this lounge."}), 403

    # Thanks to the cascade settings, deleting the lounge will also delete
    # its channels, members, messages, and reactions automatically.
    db.session.delete(lounge)
    db.session.commit()

    return jsonify({"ok": True, "message": "Lounge has been permanently deleted."})

def _post_lounge_join_message(user_id, lounge_id):
    """Helper to post a system message when a user joins a lounge."""
    user = User.query.get(user_id)
    if not user: return

    main_channel = LoungeChannel.query.filter_by(lounge_id=lounge_id, is_main=True).first()
    if not main_channel: return

    system_message = LoungeMessage(
        text=f"{user.username} joined the lounge.",
        user_id=user.id,
        channel_id=main_channel.id,
        message_type='system_event'
    )
    db.session.add(system_message)
    db.session.commit()

    message_payload = {
        "id": system_message.id, "text": system_message.text, "image": None,
        "timestamp": system_message.timestamp.isoformat(), "channel_id": main_channel.id,
        "reactions": {}, "message_type": system_message.message_type,
        "author": { "username": user.username, "fullName": user.full_name, "profilePic": user.profile_pic, "rank": user.rank }
    }
    socketio.emit('new_lounge_message', message_payload, room=f"channel_{main_channel.id}")

def seed_initial_assets():
    assets_to_seed = [
        {'name': 'default-avatar.png', 'path': 'default-avatar.png', 'mimetype': 'image/png'},
        {'name': 'apex.png', 'path': 'apex.png', 'mimetype': 'image/png'},
        {'name': 'apex2.png', 'path': 'apex2.png', 'mimetype': 'image/png'},
        {'name': 'terms.txt', 'path': 'terms.txt', 'mimetype': 'text/plain'},
        {'name': 'about.txt', 'path': 'about.txt', 'mimetype': 'text/plain'},
        {'name': 'contact.txt', 'path': 'contact.txt', 'mimetype': 'text/plain'},
    ]

    for asset_info in assets_to_seed:
        if not StoredAsset.query.filter_by(name=asset_info['name']).first():
            try:
                with open(asset_info['path'], 'rb') as f:
                    file_bytes = f.read()
                
                # --- Process file into a Data URL ---
                processed_data = None
                asset_mimetype = asset_info['mimetype']

                if asset_mimetype.startswith('image/'):
                    with Image.open(io.BytesIO(file_bytes)) as img:
                        img.thumbnail((512, 512))
                        output_buffer = io.BytesIO()
                        img.save(output_buffer, format='WEBP', quality=85)
                        webp_image_bytes = output_buffer.getvalue()
                    
                    base64_webp = base64.b64encode(webp_image_bytes).decode('utf-8')
                    processed_data = f"data:image/webp;base64,{base64_webp}"
                    asset_mimetype = 'image/webp' # Update mimetype for storage
                else:
                    # For non-image files, create a standard data URL
                    base64_data = base64.b64encode(file_bytes).decode('utf-8')
                    processed_data = f"data:{asset_mimetype};base64,{base64_data}"

                new_asset = StoredAsset(
                    name=asset_info['name'],
                    mimetype=asset_mimetype,
                    data=processed_data
                )
                db.session.add(new_asset)
                print(f"Seeded and processed asset: {asset_info['name']}")

            except FileNotFoundError:
                print(f"WARNING: Could not find {asset_info['path']}")
            except Exception as e:
                print(f"WARNING: Failed to process {asset_info['name']}: {e}")

    db.session.commit()

@app.get("/api/asset/<string:asset_name>")
def get_asset(asset_name):
    asset = StoredAsset.query.filter_by(name=asset_name).first()
    if not asset:
        return jsonify({"error": "Asset not found"}), 404

    # --- Parse the Data URL from the database ---
    try:
        # asset.data is now a string like "data:image/webp;base64,..."
        header, encoded_data = asset.data.split(",", 1)
        decoded_bytes = base64.b64decode(encoded_data)

        return send_file(
            io.BytesIO(decoded_bytes),
            mimetype=asset.mimetype,
            as_attachment=False
        )
    except (ValueError, IndexError) as e:
        print(f"Error parsing data URL for asset {asset_name}: {e}")
        return "Internal server error: Invalid asset format", 500

def get_lounge_role(user_id, lounge_id):
    membership = LoungeMember.query.filter_by(user_id=user_id, lounge_id=lounge_id).first()
    return membership.role if membership else None

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

@app.route('/asset/<path:asset_name>')
def serve_asset(asset_name):
    """
    Serves a stored asset (like an image) from the database.
    """
    try:
        asset = StoredAsset.query.filter_by(name=asset_name).first()

        if asset:
            # --- Parse the Data URL from the database ---
            header, encoded_data = asset.data.split(",", 1)
            decoded_bytes = base64.b64decode(encoded_data)
            return send_file(
                io.BytesIO(decoded_bytes),
                mimetype=asset.mimetype,
                as_attachment=False,
                download_name=asset.name
            )
        else:
            return "Asset not found", 404
            
    except Exception as e:
        print(f"Error serving asset {asset_name}: {e}")
        return "Internal server error", 500


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

@app.delete("/api/lounge/<int:lounge_id>/leave")
def leave_lounge(lounge_id):
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401

    membership = LoungeMember.query.filter_by(user_id=user.id, lounge_id=lounge_id).first()
    if not membership:
        return jsonify({"error": "You are not a member of this lounge."}), 404

    if membership.role == 'owner':
        return jsonify({"error": "Owners cannot leave a lounge. You must delete it instead."}), 403

    db.session.delete(membership)

    # --- THIS IS THE FIX ---
    # Find the designated main channel to post the system message.
    main_channel = LoungeChannel.query.filter_by(lounge_id=lounge_id, is_main=True).first()
    
    if main_channel:
        system_message = LoungeMessage(
            text=f"{user.username} left the lounge.",
            user_id=user.id,
            channel_id=main_channel.id, # Use the main channel's ID
            message_type='system_event'
        )
        db.session.add(system_message)
        db.session.commit()

        message_payload = {
            "id": system_message.id, "text": system_message.text, "image": None,
            "timestamp": system_message.timestamp.isoformat(), "channel_id": main_channel.id,
            "reactions": {}, "message_type": system_message.message_type,
            "author": { "username": user.username, "fullName": user.full_name, "profilePic": user.profile_pic, "rank": user.rank }
        }
        socketio.emit('new_lounge_message', message_payload, room=f"channel_{main_channel.id}")
    else:
        # If no main channel, just commit the membership deletion
        db.session.commit()
    # --- END OF FIX ---

    return jsonify({"ok": True, "message": "You have left the lounge."})

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

    conversation_start_info = None
    if messages:
        first_message = messages[0]
        starter_username = first_message.sender.username
        starter_is_me = (starter_username == user.username)
        conversation_start_info = {
            "starter_name": "You" if starter_is_me else first_message.sender.full_name,
            "timestamp": first_message.created_at.isoformat()
        }
    # --- ▲▲▲ END OF NEW LOGIC ▲▲

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
    if not user: return jsonify({"error": "unauthorized"}), 401

    notifications = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).limit(20).all()

    notif_list = []
    for notif in notifications:
        message = "A new notification."
        actor_username = notif.actor.username if notif.actor else None
        actionable = notif.status == 'pending' and notif.event_type in ['lounge_invite', 'lounge_access_request']

        notif_dict = {
            "id": notif.id,
            "is_read": notif.is_read,
            "timestamp": notif.created_at.isoformat(),
            "actor_username": actor_username,
            "event_type": notif.event_type,
            "status": notif.status,
            "actionable": actionable
        }

        if notif.event_type == 'new_follower' and notif.actor:
            message = f"**{notif.actor.username}** started following you!"
            notif_dict["reference_type"] = "user"

        elif notif.event_type == 'new_like' and notif.actor:
            post = CircuitPost.query.get(notif.reference_id)
            if post and post.circuit:
                message = f"**{notif.actor.username}** liked your post from **{post.circuit.title}**."
                notif_dict["reference_type"] = "post"
                notif_dict["reference_details"] = {"post_id": post.id, "circuit_id": post.circuit.id, "circuit_title": post.circuit.title, "circuit_host": post.circuit.host_school}
            else:
                message = f"**{notif.actor.username}** liked your post."

        elif notif.event_type == 'lounge_access_accepted' and notif.actor:
            lounge = Lounge.query.get(notif.reference_id)
            if lounge:
                message = f"**{notif.actor.username}** accepted your request to join **{lounge.name}**."
                notif_dict["reference_type"] = "lounge"
                notif_dict["reference_details"] = {"lounge_id": lounge.id, "lounge_name": lounge.name}
            else:
                message = f"Your request to join a lounge was accepted."
        
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
    privacy = data.get("privacy", "public")
    cover_image_data_url = data.get("coverImage")
    processed_image_data = None

    if not name:
        return jsonify({"error": "Lounge name is required"}), 400
    if len(name) > 20:
        return jsonify({"error": "Lounge name cannot exceed 20 characters"}), 400
    if len(description) > 600:
        return jsonify({"error": "Lounge description cannot exceed 600 characters"}), 400
    if privacy not in ['public', 'private', 'unlisted']:
        return jsonify({"error": "Invalid privacy setting"}), 400

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
            processed_image_data = f"data:image/webp;base64,{base64_webp}"
        except Exception as e:
            print(f"Could not process lounge cover image: {e}")
    
    # --- THIS IS THE FIX ---
    # 1. Create the main lounge object
    new_lounge = Lounge(
        name=name,
        description=description,
        owner_id=user.id,
        privacy=privacy,
        cover_image=processed_image_data
    )

    # 2. Create the related objects
    owner_membership = LoungeMember(user=user, lounge=new_lounge, role='owner')
    general_channel = LoungeChannel(name="general", lounge=new_lounge, is_main=True)
    random_channel = LoungeChannel(name="random", lounge=new_lounge)

    # 3. Add ALL objects to the session and commit ONCE.
    # SQLAlchemy will handle the IDs and relationships correctly.
    db.session.add_all([new_lounge, owner_membership, general_channel, random_channel])
    db.session.commit()
    # --- END OF FIX ---

    return jsonify({
        "ok": True,
        "message": "Lounge created successfully!",
        "lounge": {"id": new_lounge.id, "name": new_lounge.name}
    }), 201

# In server.py, add this new endpoint

@app.put("/api/lounge/channel/<int:channel_id>/set-main")
def set_main_channel(channel_id):
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401

    target_channel = LoungeChannel.query.get(channel_id)
    if not target_channel: return jsonify({"error": "Channel not found"}), 404

    # Permission Check
    user_role = get_lounge_role(user.id, target_channel.lounge_id)
    if user_role not in ['owner', 'moderator']:
        return jsonify({"error": "Forbidden: You do not have permission to do this."}), 403

    # Find the current main channel in this lounge
    current_main = LoungeChannel.query.filter_by(lounge_id=target_channel.lounge_id, is_main=True).first()
    
    # This is a transaction: unset the old main and set the new main
    if current_main:
        current_main.is_main = False
    
    target_channel.is_main = True
    db.session.commit()

    return jsonify({"ok": True, "message": f"#{target_channel.name} is now the main channel."})

@app.get("/api/lounge/<int:lounge_id>/members")
def get_lounge_members(lounge_id):
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401

    # This query joins LoungeMember and User tables to get full details
    members = db.session.query(
        User, LoungeMember.role
    ).join(
        LoungeMember, User.id == LoungeMember.user_id
    ).filter(
        LoungeMember.lounge_id == lounge_id
    ).all()

    if not members:
        return jsonify([])

    member_list = [
        {
            "username": member_user.username,
            "fullName": member_user.full_name,
            "profile_pic": member_user.profile_pic,
            "rank": member_user.rank,
            "role": role
        } for member_user, role in members
    ]
    return jsonify(member_list)

# In server.py, add this new function

@app.post("/api/lounge/<int:lounge_id>/request-access")
def request_lounge_access(lounge_id):
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401

    lounge = Lounge.query.get(lounge_id)
    if not lounge: return jsonify({"error": "Lounge not found"}), 404
    if lounge.privacy != 'private': return jsonify({"error": "This lounge is not private."}), 400
    if get_lounge_role(user.id, lounge_id): return jsonify({"error": "You are already a member."}), 409

    # Prevent spamming requests by checking for an existing pending one
    existing_request = Notification.query.filter_by(
        actor_id=user.id,
        event_type='lounge_access_request',
        reference_id=lounge_id,
        status='pending'
    ).first()
    if existing_request:
        return jsonify({"error": "You have already requested to join this lounge."}), 409

    # Create the notification for the lounge owner
    notification = Notification(
        user_id=lounge.owner_id,
        event_type='lounge_access_request',
        actor_id=user.id,
        reference_id=lounge_id,
        status='pending'
    )
    db.session.add(notification)
    db.session.commit()
    socketio.emit("new_notification", room=f"user_{lounge.owner_id}")

    return jsonify({"ok": True, "message": "Your request has been sent to the lounge owner."})

@app.get("/api/lounges")
def get_lounges():
    user = auth_user()
    if not user:
        return jsonify({"error": "unauthorized"}), 401

    # --- THIS IS THE FIX ---
    # This single query now fetches ALL lounges, regardless of privacy.
    # The frontend will handle the logic for how to display them.
    all_lounges = Lounge.query.order_by(Lounge.created_at.desc()).all()
    # --- END OF FIX ---

    lounge_list = [
        {
            "id": lounge.id,
            "name": lounge.name,
            "description": lounge.description,
            "cover_image": lounge.cover_image,
            "privacy": lounge.privacy
        } for lounge in all_lounges
    ]
    return jsonify(lounge_list)
# In server.py, find and REPLACE your join_lounge function

@app.get("/api/lounge/<int:lounge_id>/potential-invitees")
def get_potential_invitees(lounge_id):
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401
    
    # Get the search term from the request, if any
    search_term = request.args.get('q', '').strip()

    # Step 1: Find all user IDs that are ALREADY in the lounge.
    subquery = db.session.query(LoungeMember.user_id).filter(LoungeMember.lounge_id == lounge_id)

    # Step 2: Query for users who are NOT in that list of IDs.
    # Also exclude the current user and system accounts.
    query = User.query.filter(
        User.id.notin_(subquery),
        User.id != user.id,
        User.username != "ANNOUNCEMENTS"
    )

    # Step 3: If there's a search term, filter by username or full name.
    if search_term:
        search_filter = or_(
            User.username.ilike(f'%{search_term}%'),
            User.full_name.ilike(f'%{search_term}%')
        )
        query = query.filter(search_filter)

    # Step 4: Limit the results to avoid sending too much data.
    potential_invitees = query.limit(20).all()

    # Step 5: Format and return the results.
    user_list = [
        {
            "username": u.username,
            "fullName": u.full_name,
            "profile_pic": u.profile_pic,
            "rank": u.rank
        } for u in potential_invitees
    ]
    return jsonify(user_list)
# In server.py, REPLACE your existing join_lounge function

@app.get("/api/me/lounges")
def get_my_lounges():
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401

    # Find all lounges where the current user is a member
    my_lounges = Lounge.query.join(LoungeMember).filter(
        LoungeMember.user_id == user.id
    ).order_by(Lounge.name.asc()).all()

    lounge_list = [{
        "id": lounge.id,
        "name": lounge.name,
        "description": lounge.description,
        "cover_image": lounge.cover_image,
        "privacy": lounge.privacy
    } for lounge in my_lounges]

    return jsonify(lounge_list)


@app.post("/api/lounge/<int:lounge_id>/join")
def join_lounge(lounge_id):
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401

    lounge = Lounge.query.get(lounge_id)
    if not lounge: return jsonify({"error": "Lounge not found"}), 404
    
    if lounge.privacy == 'private':
        return jsonify({"error": "This lounge is private and requires an invitation to join."}), 403

    if LoungeMember.query.filter_by(user_id=user.id, lounge_id=lounge.id).first():
        return jsonify({"error": "You are already a member of this lounge."}), 409

    db.session.add(LoungeMember(user_id=user.id, lounge_id=lounge.id, role='member'))
    
    # --- THIS IS THE FIX ---
    # Instead of looking for '#general', find the channel marked as main.
    main_channel = LoungeChannel.query.filter_by(lounge_id=lounge.id, is_main=True).first()
    
    if main_channel:
        system_message = LoungeMessage(
            text=f"{user.username} joined the lounge.",
            user_id=user.id,
            channel_id=main_channel.id, # Use the main channel's ID
            message_type='system_event'
        )
        db.session.add(system_message)
        db.session.commit()

        message_payload = {
            "id": system_message.id,
            "text": system_message.text,
            "image": None,
            "timestamp": system_message.timestamp.isoformat(),
            "channel_id": main_channel.id, # Use the main channel's ID
            "reactions": {},
            "message_type": system_message.message_type,
            "author": {
                "username": user.username, "fullName": user.full_name,
                "profilePic": user.profile_pic, "rank": user.rank
            }
        }
        socketio.emit('new_lounge_message', message_payload, room=f"channel_{main_channel.id}")
    else:
        # If no main channel is found for some reason, just commit the membership change.
        db.session.commit()
    # --- END OF FIX ---
    
    return jsonify({"ok": True, "message": f"Welcome to {lounge.name}!"})

@app.get("/api/lounge/<int:lounge_id>/channels")
def get_lounge_channels(lounge_id):
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401

    lounge = Lounge.query.get(lounge_id)
    if not lounge: return jsonify({"error": "Lounge not found"}), 404
    
    user_role = get_lounge_role(user.id, lounge_id)
    is_member = user_role is not None
    
    if lounge.privacy in ['private', 'unlisted'] and not is_member:
        if lounge.privacy == 'private':
            return jsonify({"error": "Forbidden: You are not a member of this private lounge."}), 403
        else:
            return jsonify({ "channels": [], "user_role": None, "is_member": False })

    query = LoungeChannel.query.filter_by(lounge_id=lounge.id)
    if not is_member or user_role not in ['owner', 'moderator']:
        query = query.filter(LoungeChannel.permission_level != 'mods_only_view')
    
    channels = query.order_by(LoungeChannel.is_main.desc(), LoungeChannel.name.asc()).all()
    
    return jsonify({
        # --- ▼▼▼ THIS IS THE FIX ▼▼▼ ---
        # We now include the "is_main" flag for each channel.
        "channels": [{"id": c.id, "name": c.name, "permission_level": c.permission_level, "is_main": c.is_main} for c in channels],
        # --- ▲▲▲ END OF FIX ▲▲▲ ---
        "user_role": user_role,
        "is_member": is_member
    })


@app.post("/api/admin/db-command")
def handle_db_command():
    user = auth_user()
    if not user or user.rank != 'admin':
        return jsonify({"error": "Forbidden: Admin access required"}), 403

    data = request.get_json(force=True)
    command = data.get("command")
    message = data.get("message")
    
    cmd_parts = ["flask", "db"]

    if command == "init":
        cmd_parts.append("init")
    elif command == "migrate":
        if not message:
            return jsonify({"error": "A message is required for the migrate command."}), 400
        cmd_parts.extend(["migrate", "-m", message])
    elif command == "upgrade":
        cmd_parts.append("upgrade")
    else:
        return jsonify({"error": "Invalid database command."}), 400

    try:
        # Execute the command and capture the output
        result = subprocess.run(cmd_parts, capture_output=True, text=True, check=True)
        output = result.stdout or "Command executed successfully with no output."
        return jsonify({"ok": True, "message": output})
    except subprocess.CalledProcessError as e:
        # This catches errors from the flask command itself
        error_output = e.stderr or e.stdout or "An unknown error occurred during command execution."
        return jsonify({"ok": False, "error": error_output}), 500
    except FileNotFoundError:
        # This catches the error if 'flask' isn't in the system's PATH
        return jsonify({"ok": False, "error": "Error: 'flask' command not found. The server environment may not be configured to run shell commands."}), 500

# Modify the message fetching endpoint to get messages from a CHANNEL
@app.get("/api/lounge/channel/<int:channel_id>/messages")
def get_lounge_channel_messages(channel_id):
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401

    messages = LoungeMessage.query.filter_by(channel_id=channel_id).order_by(LoungeMessage.timestamp.asc()).limit(100).all()

    # --- NEW: Efficiently fetch all reactions for these messages ---
    message_ids = [msg.id for msg in messages]
    all_reactions = db.session.query(
        LoungeMessageReaction.message_id,
        LoungeMessageReaction.emoji,
        func.count(LoungeMessageReaction.user_id)
    ).filter(LoungeMessageReaction.message_id.in_(message_ids)).group_by(LoungeMessageReaction.message_id, LoungeMessageReaction.emoji).all()
    
    reactions_map = {}
    for msg_id, emoji, count in all_reactions:
        if msg_id not in reactions_map: reactions_map[msg_id] = {}
        reactions_map[msg_id][emoji] = count
    # --- END NEW ---

    message_list = []
    for msg in messages:
        if not msg.author: continue
        message_list.append({
            "id": msg.id,
            "text": msg.text,
            "image": msg.image,
            "timestamp": msg.timestamp.isoformat(),
            "reactions": reactions_map.get(msg.id, {}), # <-- ADD THIS
            "message_type": msg.message_type,
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
    token_str = socket_connections.get(request.sid)
    token_obj = APIToken.query.filter_by(token=token_str).first() if token_str else None
    user = token_obj.user if token_obj else None
    if not user: return

    channel_id = data.get('channel_id')
    channel = LoungeChannel.query.get(channel_id)
    if not channel: return

    membership = LoungeMember.query.filter_by(user_id=user.id, lounge_id=channel.lounge_id).first()
    
    # --- MODIFIED MEMBERSHIP/PRIVACY LOGIC ---
    if not membership:
        # If user is not a member, check if the lounge is private.
        # If it's private, they cannot join automatically.
        if channel.lounge.privacy == 'private':
            return # Silently stop them from joining/sending a message
        
        # Otherwise (public or unlisted), add them as a new member.
        new_membership = LoungeMember(user_id=user.id, lounge_id=channel.lounge_id, role='member')
        db.session.add(new_membership)
    # --- END OF MODIFIED LOGIC ---

    user_role = get_lounge_role(user.id, channel.lounge_id)
    if channel.permission_level == 'mods_only_chat' and user_role not in ['owner', 'moderator']:
        return 
    
    text = data.get('text', '').strip()
    image_data = data.get('image')
    if not (text or image_data): return

    new_message = LoungeMessage(text=text, image=image_data, user_id=user.id, channel_id=channel_id)
    db.session.add(new_message)
    db.session.commit()

    # --- THIS IS THE FIX: Use .strftime() here as well ---
    message_payload = {
        "id": new_message.id,
        "text": new_message.text,
        "image": new_message.image,
        "timestamp": new_message.timestamp.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
        "channel_id": channel_id,
        "reactions": {},
        "message_type": new_message.message_type, # Added this line
        "author": {
            "username": user.username,
            "fullName": user.full_name,
            "profilePic": user.profile_pic,
            "rank": user.rank
        }
    }
    emit('new_lounge_message', message_payload, room=f"channel_{channel_id}")


@app.get("/api/me/activity")
def get_my_activity():
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401

    my_posts = CircuitPost.query.filter_by(user_id=user.id).order_by(CircuitPost.created_at.desc()).limit(10).all()
    my_liked_posts = CircuitPost.query.join(post_likes).filter(post_likes.c.user_id == user.id).order_by(CircuitPost.created_at.desc()).limit(10).all()
    my_circuits = Circuit.query.filter_by(user_id=user.id).order_by(Circuit.id.desc()).limit(10).all()
    my_owned_lounges = Lounge.query.filter_by(owner_id=user.id).order_by(Lounge.created_at.desc()).limit(10).all()

    # --- THIS IS THE FIX: Add checks to ensure timestamps exist before formatting ---
    results = {
        "posts": [{"text": p.text, "circuit_title": p.circuit.title, "circuit_id": p.circuit.id, "host_school": p.circuit.host_school, "timestamp": p.created_at.strftime('%Y-%m-%dT%H:%M:%S.%fZ') if p.created_at else None} for p in my_posts],
        "likes": [{"text": l.text, "original_author": l.author.full_name, "circuit_title": l.circuit.title, "circuit_id": l.circuit.id, "host_school": l.circuit.host_school, "timestamp": l.created_at.strftime('%Y-%m-%dT%H:%M:%S.%fZ') if l.created_at else None} for l in my_liked_posts],
        "circuits": [{"title": c.title, "host_school": c.host_school, "id": c.id} for c in my_circuits],
        "lounges": [{"name": l.name, "id": l.id, "timestamp": l.created_at.strftime('%Y-%m-%dT%H:%M:%S.%fZ') if l.created_at else None} for l in my_owned_lounges]
    }
    return jsonify(results)

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

def serve_simple_page(template_file, asset_name, page_title):
    asset = StoredAsset.query.filter_by(name=asset_name).first()

    if not asset:
        return f"{page_title} page content not found.", 404

    try:
        header, encoded_data = asset.data.split(",", 1)
        decoded_text = base64.b64decode(encoded_data).decode('utf-8')
        
        # --- THIS IS THE NEW LINE ---
        # Convert the Markdown text to HTML
        html_content = markdown.markdown(decoded_text)

    except Exception as e:
        print(f"Error decoding or converting {asset_name}: {e}")
        return f"Could not load {page_title} page.", 500

    # Pass the converted HTML to the template
    return render_template(template_file, page_title=page_title, page_content=html_content)

# --- Routes for the new pages ---
@app.route('/about')
def about_page():
    return serve_simple_page('page_template.html', 'about.txt', 'About Us')

@app.route('/contact')
def contact_page():
    return serve_simple_page('page_template.html', 'contact.txt', 'Contact Us')

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
    message = data.get("message", "").strip()
    to_username = data.get("to_username")
    broadcast = data.get("broadcast", False)

    # --- NEW: Handle special, non-messaging admin commands first ---
    if message == "/update-assets":
        if mod_user.rank != 'admin':
            return jsonify({"error": "Forbidden: This command requires admin privileges."}), 403
        
        result = _reseed_assets_from_disk()
        
        # Send a confirmation DM back to the admin who ran the command
        dm = DM(sender_id=system_user.id, receiver_id=mod_user.id, message=result["message"])
        db.session.add(dm)
        db.session.commit()
        # Notify the admin's client in real-time
        socketio.emit("dm_received", {
            "from": system_user.username, "message": dm.message, "created_at": dm.created_at.isoformat() + "Z"
        }, room=f"user_{mod_user.id}")
        
        return jsonify({"ok": True, "message": result["message"]})
    # --- END OF NEW LOGIC ---

    if not message:
        return jsonify({"error": "Message is required for sending DMs"}), 400

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
        return jsonify({"error": "Recipient or broadcast flag required for messaging commands."}), 400


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

@app.post("/api/lounge/<int:lounge_id>/invite")
def invite_to_lounge(lounge_id):
    inviter = auth_user()
    if not inviter: return jsonify({"error": "unauthorized"}), 401

    lounge = Lounge.query.get(lounge_id)
    if not lounge: return jsonify({"error": "Lounge not found"}), 404

    inviter_role = get_lounge_role(inviter.id, lounge_id)
    if inviter_role not in ['owner', 'moderator']:
        return jsonify({"error": "Forbidden: You do not have permission to invite users."}), 403

    data = request.get_json(force=True)
    username_to_invite = data.get("username")
    invitee = User.query.filter_by(username=username_to_invite).first()
    if not invitee: return jsonify({"error": "User to invite not found"}), 404

    if get_lounge_role(invitee.id, lounge_id):
        return jsonify({"error": "This user is already a member of the lounge."}), 409

    # Check for an existing pending invitation
    existing_invite = Notification.query.filter_by(
        user_id=invitee.id, 
        event_type='lounge_invite', 
        reference_id=lounge_id,
        status='pending'
    ).first()
    if existing_invite:
        return jsonify({"error": "An invitation has already been sent to this user."}), 409

    notification = Notification(
        user_id=invitee.id,
        actor_id=inviter.id,
        event_type='lounge_invite',
        reference_id=lounge_id,
        status='pending'
    )
    db.session.add(notification)
    db.session.commit()
    socketio.emit("new_notification", room=f"user_{invitee.id}")

    return jsonify({"ok": True, "message": f"Invitation sent to {username_to_invite}."})


@app.post("/api/notification/<int:notification_id>/respond")
def respond_to_notification(notification_id):
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401
    
    notification = Notification.query.get(notification_id)
    if not notification or notification.user_id != user.id or notification.status != 'pending':
        return jsonify({"error": "Notification not found or action already taken."}), 404

    data = request.get_json(force=True)
    action = data.get("action")

    if action not in ["accept", "decline"]:
        return jsonify({"error": "Invalid action"}), 400

    if notification.event_type == 'lounge_invite':
        lounge_id = notification.reference_id
        if action == "accept":
            if not get_lounge_role(user.id, lounge_id):
                db.session.add(LoungeMember(user_id=user.id, lounge_id=lounge_id, role='member'))
                db.session.flush() # Ensure membership is saved before posting message
                _post_lounge_join_message(user.id, lounge_id) # Post "joined" message
        notification.status = 'accepted' if action == 'accept' else 'declined'

    elif notification.event_type == 'lounge_access_request':
        lounge_id = notification.reference_id
        requester_id = notification.actor_id
        lounge = Lounge.query.get(lounge_id)
        
        if not lounge or lounge.owner_id != user.id:
            return jsonify({"error": "Forbidden or lounge not found."}), 403

        if action == "accept":
            if not get_lounge_role(requester_id, lounge_id):
                db.session.add(LoungeMember(user_id=requester_id, lounge_id=lounge_id, role='member'))
                db.session.flush() # Ensure membership is saved
                _post_lounge_join_message(requester_id, lounge_id) # Post "joined" message

            # --- NEW: Notify the requester that they were accepted ---
            accepted_notification = Notification(
                user_id=requester_id,
                event_type='lounge_access_accepted',
                actor_id=user.id,
                reference_id=lounge_id,
                status='accepted'
            )
            db.session.add(accepted_notification)
            socketio.emit("new_notification", room=f"user_{requester_id}")
            # --- END NEW ---
        
        notification.status = 'accepted' if action == 'accept' else 'declined'

    notification.is_read = True
    db.session.commit()
    return jsonify({"ok": True})

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

@app.get("/api/lounge/message/<int:message_id>/reaction/<emoji>")
def get_lounge_reaction_users(message_id, emoji):
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401

    reactions = LoungeMessageReaction.query.filter_by(message_id=message_id, emoji=emoji).all()
    user_ids = [r.user_id for r in reactions]
    users = User.query.filter(User.id.in_(user_ids)).all()
    usernames = [u.username for u in users]
    return jsonify(usernames)

@app.route('/terms')
def terms_page():
    return serve_simple_page('page_template.html', 'terms.txt', 'Terms of Service')

def _reseed_assets_from_disk():
    """Reads all asset files from disk and updates them in the database."""
    assets_to_seed = [
        {'name': 'default-avatar.png', 'path': 'default-avatar.png', 'mimetype': 'image/png'},
        {'name': 'apex.png', 'path': 'apex.png', 'mimetype': 'image/png'},
        {'name': 'apex2.png', 'path': 'apex2.png', 'mimetype': 'image/png'},
        {'name': 'terms.txt', 'path': 'terms.txt', 'mimetype': 'text/plain'},
        {'name': 'about.txt', 'path': 'about.txt', 'mimetype': 'text/plain'},
        {'name': 'contact.txt', 'path': 'contact.txt', 'mimetype': 'text/plain'},
    ]
    updated_count = 0
    created_count = 0

    for asset_info in assets_to_seed:
        try:
            with open(asset_info['path'], 'rb') as f:
                file_bytes = f.read()
            # This part is simplified for brevity but assumes your image processing logic is here
            asset_mimetype = asset_info['mimetype']
            base64_data = base64.b64encode(file_bytes).decode('utf-8')
            processed_data = f"data:{asset_mimetype};base64,{base64_data}"
            
            existing_asset = StoredAsset.query.filter_by(name=asset_info['name']).first()
            if existing_asset:
                existing_asset.data = processed_data
                updated_count += 1
            else:
                new_asset = StoredAsset(name=asset_info['name'], mimetype=asset_mimetype, data=processed_data)
                db.session.add(new_asset)
                created_count += 1
        except Exception as e:
            print(f"WARNING: During reseed, failed to process {asset_info['name']}: {e}")

    db.session.commit()
    return {"message": f"Content refresh complete. Updated: {updated_count}, Created: {created_count}."}

@socketio.on('react_to_lounge_message')
def handle_lounge_reaction(data):
    # Use the correct authentication method for sockets
    token_str = socket_connections.get(request.sid)
    token_obj = APIToken.query.filter_by(token=token_str).first() if token_str else None
    user = token_obj.user if token_obj else None
    if not user:
        return

    message_id = data.get('message_id')
    emoji = data.get('emoji')

    message = LoungeMessage.query.get(message_id)
    if not message:
        return

    # Check if the user has already reacted with this emoji
    existing_reaction = LoungeMessageReaction.query.filter_by(
        message_id=message_id, user_id=user.id, emoji=emoji
    ).first()

    if existing_reaction:
        # If it exists, remove it (toggle off)
        db.session.delete(existing_reaction)
    else:
        # If it doesn't exist, add it (toggle on)
        new_reaction = LoungeMessageReaction(message_id=message_id, user_id=user.id, emoji=emoji)
        db.session.add(new_reaction)
    
    db.session.commit()

    # Get the new total counts for all reactions on this message
    reactions_agg = db.session.query(
        LoungeMessageReaction.emoji, func.count(LoungeMessageReaction.user_id)
    ).filter_by(message_id=message_id).group_by(LoungeMessageReaction.emoji).all()
    
    reactions_payload = {emoji: count for emoji, count in reactions_agg}

    # Broadcast the update to everyone in the channel's room
    emit('lounge_message_updated', {
        "message_id": message_id,
        "reactions": reactions_payload
    }, room=f"channel_{message.channel_id}")


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

@app.put("/api/lounge/channel/<int:channel_id>")
def edit_lounge_channel(channel_id):
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401

    channel = LoungeChannel.query.get(channel_id)
    if not channel: return jsonify({"error": "Channel not found"}), 404

    user_role = get_lounge_role(user.id, channel.lounge_id)
    if user_role not in ['owner', 'moderator']:
        return jsonify({"error": "Forbidden: You do not have permission to edit channels."}), 403

    data = request.get_json(force=True)
    new_name = data.get("name", "").strip()
    if not new_name or len(new_name) > 100:
        return jsonify({"error": "Invalid channel name"}), 400

    channel.name = new_name
    db.session.commit()
    return jsonify({"ok": True, "message": "Channel name updated."})


@app.post("/api/lounge/<int:lounge_id>/channels")
def create_lounge_channel(lounge_id):
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401

    # Check if the user has permission to create channels
    user_role = get_lounge_role(user.id, lounge_id)
    if user_role not in ['owner', 'moderator']:
        return jsonify({"error": "Forbidden: You do not have permission to create channels."}), 403

    data = request.get_json(force=True)
    name = data.get("name", "").strip().lower().replace(" ", "-") # Sanitize name
    permission_level = data.get("permission_level", "public")

    if not name or not re.match(r'^[a-z0-9-]{1,50}$', name):
        return jsonify({"error": "Invalid channel name. Use letters, numbers, and hyphens only."}), 400
    if permission_level not in ['public', 'mods_only_chat', 'mods_only_view']:
        return jsonify({"error": "Invalid permission level."}), 400

    new_channel = LoungeChannel(
        name=name,
        lounge_id=lounge_id,
        permission_level=permission_level
    )
    db.session.add(new_channel)
    db.session.commit()

    return jsonify({
        "id": new_channel.id,
        "name": new_channel.name,
        "permission_level": new_channel.permission_level
    }), 201

@app.delete("/api/lounge/channel/<int:channel_id>")
def delete_lounge_channel(channel_id):
    user = auth_user()
    if not user: return jsonify({"error": "unauthorized"}), 401

    channel = LoungeChannel.query.get(channel_id)
    if not channel: return jsonify({"error": "Channel not found"}), 404

    user_role = get_lounge_role(user.id, channel.lounge_id)
    if user_role not in ['owner', 'moderator']:
        return jsonify({"error": "Forbidden: You do not have permission to delete channels."}), 403
    
    # --- REMOVED ---
    # The special check preventing the deletion of '#general' is now gone.
    # if channel.name == 'general':
    #     return jsonify({"error": "The #general channel cannot be deleted."}), 400
        
    # --- NEW LOGIC: Handle deleting the main channel ---
    if channel.is_main:
        # Find another channel in the same lounge to promote.
        # We order by name to predictably get the "next" channel alphabetically.
        next_channel = LoungeChannel.query.filter(
            LoungeChannel.lounge_id == channel.lounge_id,
            LoungeChannel.id != channel.id
        ).order_by(LoungeChannel.name.asc()).first()

        # If another channel exists, make it the new main channel.
        if next_channel:
            next_channel.is_main = True
    # --- END OF NEW LOGIC ---
        
    # The cascade="all, delete-orphan" in your LoungeChannel model will 
    # automatically handle deleting all messages in this channel.
    db.session.delete(channel)
    db.session.commit()
    return jsonify({"ok": True, "message": "Channel deleted."})

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

    my_posts = CircuitPost.query.filter_by(user_id=user.id).order_by(CircuitPost.created_at.desc()).limit(10).all()
    my_liked_posts = CircuitPost.query.join(post_likes).filter(post_likes.c.user_id == user.id).order_by(CircuitPost.created_at.desc()).limit(10).all()
    my_circuits = Circuit.query.filter_by(user_id=user.id).order_by(Circuit.id.desc()).limit(10).all()
    my_owned_lounges = Lounge.query.filter_by(owner_id=user.id).order_by(Lounge.created_at.desc()).limit(10).all()

    # --- THIS IS THE FIX: Use .strftime() to ensure UTC 'Z' format ---
    results = {
        "posts": [{"text": p.text, "circuit_title": p.circuit.title, "circuit_id": p.circuit.id, "host_school": p.circuit.host_school, "timestamp": p.created_at.strftime('%Y-%m-%dT%H:%M:%S.%fZ')} for p in my_posts],
        "likes": [{"text": l.text, "original_author": l.author.full_name, "circuit_title": l.circuit.title, "circuit_id": l.circuit.id, "host_school": l.circuit.host_school, "timestamp": l.created_at.strftime('%Y-%m-%dT%H:%M:%S.%fZ')} for l in my_liked_posts],
        "circuits": [{"title": c.title, "host_school": c.host_school, "id": c.id} for c in my_circuits],
        "lounges": [{"name": l.name, "id": l.id, "timestamp": l.created_at.strftime('%Y-%m-%dT%H:%M:%S.%fZ')} for l in my_owned_lounges]
    }
    return jsonify(results)

@app.get("/api/trending")
def get_trending_items():
    limit = request.args.get('limit', 7, type=int)

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
        # This new part handles lounges
        elif item_data['type'] == 'lounge':
            item = Lounge.query.get(item_data['id'])
            if item:
                top_items.append({
                    "type": "lounge",
                    "id": item.id,
                    "name": item.name,
                    "description": item.description,
                    "cover_image": item.cover_image,
                    "privacy": item.privacy,
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

@app.post("/api/lounge/<int:lounge_id>/view")
def increment_lounge_view(lounge_id):
    if not Lounge.query.get(lounge_id):
        return jsonify({"error": "Lounge not found"}), 404
    # Re-use the existing helper function
    views = _increment_view(lounge_id, 'lounge')
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
        message=message_text, # <-- CORRECTED LINE
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

@app.put("/api/lounge/<int:lounge_id>/member/<username>/role")
def set_lounge_member_role(lounge_id, username):
    admin_user = auth_user()
    if not admin_user: return jsonify({"error": "unauthorized"}), 401

    target_user = User.query.filter_by(username=username).first()
    if not target_user: return jsonify({"error": "Target user not found"}), 404

    # Get the role of the user trying to make the change
    admin_role = get_lounge_role(admin_user.id, lounge_id)

    # Get the membership record of the user being changed
    target_membership = LoungeMember.query.filter_by(lounge_id=lounge_id, user_id=target_user.id).first()
    if not target_membership: return jsonify({"error": "User is not a member of this lounge"}), 404

    data = request.get_json(force=True)
    new_role = data.get("role")
    if new_role not in ['member', 'moderator']:
        return jsonify({"error": "Invalid role specified. Can only set to 'member' or 'moderator'."}), 400

    # --- PERMISSION CHECKS ---
    # Only the owner can promote/demote moderators.
    if target_membership.role == 'moderator' or new_role == 'moderator':
        if admin_role != 'owner':
            return jsonify({"error": "Forbidden: Only the lounge owner can manage moderators."}), 403

    # Moderators can only demote other members (this logic is implicitly handled by the check above).
    if admin_role not in ['owner', 'moderator']:
        return jsonify({"error": "Forbidden: You do not have permission to change roles."}), 403

    # An owner's role cannot be changed.
    if target_membership.role == 'owner':
        return jsonify({"error": "The lounge owner's role cannot be changed."}), 400
    
    # --- END PERMISSION CHECKS ---

    target_membership.role = new_role
    db.session.commit()

    return jsonify({"ok": True, "message": f"{username}'s role has been updated to {new_role}."})


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

@app.route('/')
def index():
    return render_template('index.html')


# -------------------------------------------------
# Socket.IO (실시간 DM)
# -------------------------------------------------


# -------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

        # --- THIS IS THE FIX ---
        # Seed initial assets like logos and default images
        seed_initial_assets()

        # Create ANNOUNCEMENTS user if it doesn't exist
        if not User.query.filter_by(username="ANNOUNCEMENTS").first():
            print("Creating ANNOUNCEMENTS user...")
            system_user = User(username="ANNOUNCEMENTS", full_name="ANNOUNCEMENTS", email="apex@announcements",
                               rank="admin")
            db.session.add(system_user)
            db.session.commit()
        # --- END OF FIX ---

        # Seeding logic for circuits
        if not Circuit.query.first():
            print("Seeding database with initial circuits...")
            db.session.commit()

    port = int(os.environ.get("PORT", 5000))
    socketio.run(app, host="0.0.0.0", port=port, debug=True)
