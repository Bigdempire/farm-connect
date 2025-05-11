import sqlite3
from flask import Flask, render_template, request, redirect, session, flash
from flask import url_for, jsonify
from flask_socketio import SocketIO
from functools import wraps, lru_cache
from datetime import datetime, timedelta
import os
import re
import json
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from limits.storage import MemoryStorage
from typing import List, Dict, Any
import threading
_file_lock = threading.Lock()
import logging

app = Flask(__name__)
# Use environment variable for secret key in production
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
DATABASE = 'users.db'

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://",
    storage_options={},
    strategy="fixed-window"
)
limiter.limit("200 per day;50 per hour")

# Secure session configuration
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=60)
)

# Basic SocketIO setup
socketio = SocketIO(app)

# Set up image upload settings
BASEDIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASEDIR, 'static', 'uploads')
PRODUCT_IMAGES = os.path.join(UPLOAD_FOLDER, 'products')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# File-based storage (simulating database)
PRODUCTS_FILE = os.path.join(BASEDIR, 'data', 'products.json')
ORDERS_FILE = os.path.join(BASEDIR, 'data', 'orders.json')
MESSAGES_FILE = os.path.join(BASEDIR, 'data', 'messages.json')
NOTIFICATIONS_FILE = os.path.join(BASEDIR, 'data', 'notifications.json')

# Ensure all required directories exist
os.makedirs(os.path.join(BASEDIR, 'data'), exist_ok=True)
os.makedirs(PRODUCT_IMAGES, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Helper functions for file-based storage
@lru_cache(maxsize=1)
def validate_product(product: Dict[str, Any]) -> bool:
    """Validate a product dictionary has all required fields."""
    required_fields = {'id', 'name', 'description', 'price', 'seller_id'}
    return all(field in product for field in required_fields)

@lru_cache(maxsize=1)
def load_products() -> List[Dict[str, Any]]:
    """Load products from file with error handling and file locking."""
    try:
        if not os.path.exists(PRODUCTS_FILE):
            return []
            
        with open(PRODUCTS_FILE, 'r') as f:
            # Acquire a shared lock for reading
            with _file_lock:
                try:
                    products = json.load(f)
                    # Validate each product
                    return [p for p in products if validate_product(p)]
                except json.JSONDecodeError as e:
                    logging.error(f"Error decoding products file: {e}")
                    return []
    except Exception as e:
        logging.error(f"Error loading products: {e}")
        return []

def save_products(products: List[Dict[str, Any]]) -> bool:
    os.makedirs(os.path.dirname(PRODUCTS_FILE), exist_ok=True)
    with _file_lock:
        with open(PRODUCTS_FILE, 'w') as f:
            json.dump(products, f, indent=4)
    return True

def load_orders():
    if os.path.exists(ORDERS_FILE):
        with open(ORDERS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_orders(orders):
    os.makedirs(os.path.dirname(ORDERS_FILE), exist_ok=True)
    with open(ORDERS_FILE, 'w') as f:
        json.dump(orders, f, indent=4)
        
def load_messages():
    if os.path.exists(MESSAGES_FILE):
        with open(MESSAGES_FILE, 'r') as f:
            return json.load(f)
    return []

def load_notifications():
    if os.path.exists(NOTIFICATIONS_FILE):
        with open(NOTIFICATIONS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_notifications(notifications):
    os.makedirs(os.path.dirname(NOTIFICATIONS_FILE), exist_ok=True)
    with open(NOTIFICATIONS_FILE, 'w') as f:
        json.dump(notifications, f, indent=4)

def save_messages(messages):
    os.makedirs(os.path.dirname(MESSAGES_FILE), exist_ok=True)
    with open(MESSAGES_FILE, 'w') as f:
        json.dump(messages, f, indent=4)

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    if not os.path.exists(DATABASE):
        with get_db() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                place TEXT NOT NULL,
                contact TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )''')
            db.commit()

# Initialize the database when the app starts
init_db()

def validate_email(email):
    pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
    return re.match(pattern, email) is not None

def validate_phone(phone):
    pattern = r'^\+?1?\d{9,15}$'
    return re.match(pattern, phone) is not None

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def signup():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        place = request.form.get('place', '').strip()
        contact = request.form.get('contact', '').strip()
        password = request.form.get('password', '')
        
        # Validation
        if not all([name, place, contact, password]):
            flash('All fields are required!', 'error')
            return render_template('signup.html')
            
        if len(password) < 6:
            flash('Password must be at least 6 characters long!', 'error')
            return render_template('signup.html')
            
        if not (validate_email(contact) or validate_phone(contact)):
            flash('Please enter a valid email or phone number!', 'error')
            return render_template('signup.html')
            
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        try:
            with get_db() as db:
                db.execute('INSERT INTO users (name, place, contact, password) VALUES (?, ?, ?, ?)',
                           (name, place, contact, hashed_password))
                db.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('This email/phone number is already registered!', 'error')
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = FlaskForm()
    if request.method == 'POST':
        contact = request.form.get('contact')
        password = request.form.get('password')
        
        if not all([contact, password]):
            flash('Please fill in all fields!', 'error')
            return render_template('login.html', form=form)
            
        try:
            with get_db() as db:
                user = db.execute('SELECT * FROM users WHERE contact = ?', (contact,)).fetchone()
                
            if user and check_password_hash(user['password'], password):
                session['user_id'] = user['id']
                session['name'] = user['name']
                flash('Login successful!', 'success')
                return redirect(url_for('home'))
            else:
                flash('Invalid credentials!', 'error')
                return render_template('login.html', form=form)
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')
            return render_template('login.html', form=form)
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first!', 'error')
        return redirect(url_for('login'))
    try:
        with get_db() as db:
            user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        return render_template('dashboard.html', user=user)
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/home')
@login_required
def home():
    return render_template('home.html', user_name=session.get('name'))

@app.route('/posts')
@login_required
def posts():
    products = load_products()
    return render_template('posts.html', user_name=session.get('name'), products=products)

@app.route('/add_post', methods=['POST'])
@login_required
def add_post():
    if 'product_image' not in request.files:
        flash('No file part', 'danger')
        return redirect(url_for('posts'))
    
    file = request.files['product_image']
    
    if file.filename == '':
        flash('No image selected', 'danger')
        return redirect(url_for('posts'))
    
    if file and allowed_file(file.filename):
        # Generate a unique product ID
        product_id = str(uuid.uuid4())
        
        # Save the image
        filename = secure_filename(file.filename)
        file_extension = filename.rsplit('.', 1)[1].lower()
        new_filename = f"{product_id}.{file_extension}"
        os.makedirs(PRODUCT_IMAGES, exist_ok=True)
        file_path = os.path.join(PRODUCT_IMAGES, new_filename)
        file.save(file_path)
        
        # Get product details from form
        title = request.form.get('title', '')
        price = request.form.get('price', '')
        location = request.form.get('location', '')
        description = request.form.get('description', '')
        
        # Create product object
        product = {
            'id': product_id,
            'title': title,
            'price': price,
            'location': location,
            'description': description,
            'image': url_for('static', filename=f'uploads/products/{new_filename}'),
            'seller_id': session.get('user_id'),
            'seller_name': session.get('name'),
            'seller_avatar': session.get('avatar', url_for('static', filename='uploads/default-profile.png')),
            'date_posted': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Save product to "database"
        products = load_products()
        products.append(product)
        save_products(products)
        
        flash('Your product has been posted successfully!', 'success')
    else:
        flash('Invalid file type. Please upload an image.', 'danger')
    
    return redirect(url_for('posts'))

@app.route('/chat/<seller_id>/<product_id>')
@login_required
def chat(seller_id, product_id):
    products = load_products()
    product = None
    for p in products:
        if p['id'] == product_id:
            product = p
            break
    
    if product is None:
        flash('Product not found', 'danger')
        return redirect(url_for('posts'))
    
    # Get existing messages or create new conversation
    messages_data = load_messages()
    chat_id = f"{session.get('user_id')}_{seller_id}_{product_id}"
    
    # Find conversation or create new one
    conversation = None
    for msg in messages_data:
        if msg['chat_id'] == chat_id:
            conversation = msg
            break
    
    if conversation is None:
        conversation = {
            'chat_id': chat_id,
            'buyer_id': session.get('user_id'),
            'buyer_name': session.get('name'),
            'seller_id': seller_id,
            'seller_name': product['seller_name'],
            'product_id': product_id,
            'product_name': product['title'],
            'messages': []
        }
        messages_data.append(conversation)
        save_messages(messages_data)
    
    return render_template('chat.html', 
                           user_name=session.get('name'),
                           user_id=session.get('user_id'),
                           farmer_name=product['seller_name'], 
                           farmer_id=product['seller_id'],
                           farmer_avatar=product['seller_avatar'],
                           product_name=product['title'], 
                           product_id=product['id'],
                           product_image=product['image'],
                           chat_id=chat_id,
                           conversation=conversation)

@app.route('/send_message', methods=['POST'])
@login_required
def send_message():
    if request.method == 'POST':
        message_text = request.form.get('message')
        chat_id = request.form.get('chat_id')
        seller_id = request.form.get('seller_id')
        product_id = request.form.get('product_id')
        
        if not message_text or not chat_id:
            return jsonify({'status': 'error', 'message': 'Invalid request'})
        
        # Add message to conversation
        messages_data = load_messages()
        
        for conversation in messages_data:
            if conversation['chat_id'] == chat_id:
                new_message = {
                    'id': str(uuid.uuid4()),
                    'sender_id': session.get('user_id'),
                    'sender_name': session.get('name'),
                    'message': message_text,
                    'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    'is_read': False
                }
                conversation['messages'].append(new_message)
                
                # Auto-reply for demo purposes
                if session.get('user_id') != seller_id:  # If user is not the seller
                    auto_replies = [
                        f"Thank you for your interest in {conversation['product_name']}. I have more in stock!",
                        "When would you like to pick up your order?",
                        "I can deliver to your location for a small fee. Would that be convenient?",
                        "Do you have any questions about how we grow our produce?",
                        "Thanks for supporting local farmers!"
                    ]
                    import random
                    auto_reply = {
                        'id': str(uuid.uuid4()),
                        'sender_id': seller_id,
                        'sender_name': conversation['seller_name'],
                        'message': random.choice(auto_replies),
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        'is_read': False
                    }
                    conversation['messages'].append(auto_reply)
                
                save_messages(messages_data)
                return jsonify({
                    'status': 'success', 
                    'message': 'Message sent',
                    'sent_message': new_message,
                    'auto_reply': auto_reply if session.get('user_id') != seller_id else None
                })
        
        return jsonify({'status': 'error', 'message': 'Conversation not found'})

@app.route('/place_order/<product_id>', methods=['GET', 'POST'])
@login_required
def place_order(product_id):
    products = load_products()
    product = next((p for p in products if p['id'] == product_id), None)
    
    if not product:
        flash('Product not found!', 'error')
        return redirect(url_for('posts'))
    
    if request.method == 'POST':
        delivery_address = request.form.get('delivery_address')
        payment_method = request.form.get('payment_method')
        
        if not delivery_address or not payment_method:
            flash('Please fill in all required fields!', 'error')
            return redirect(url_for('place_order', product_id=product_id))
        
        order = {
            'id': str(uuid.uuid4()),
            'product_id': product_id,
            'product_title': product['title'],  # Changed from product_name to match template
            'product_price': float(product['price']),
            'quantity': 1,
            'total_price': float(product['price']) + 2.0,  # Adding $2 delivery fee
            'buyer_id': session.get('user_id'),
            'buyer_name': session.get('name'),
            'seller_id': product['seller_id'],
            'seller_name': product['seller_name'],
            'delivery_address': delivery_address,
            'payment_method': payment_method,
            'status': 'pending',
            'date_ordered': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Save order
        orders = load_orders()
        orders.append(order)
        save_orders(orders)
        
        # Create notification for seller
        notification = {
            'id': str(uuid.uuid4()),
            'user_id': product['seller_id'],
            'buyer_id': session.get('user_id'),
            'buyer_name': session.get('name'),
            'product_id': product_id,
            'product_name': product['title'],
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'read': False,
            'chat_link': f'/chat/{session.get("user_id")}/{product_id}'
        }
        
        notifications = load_notifications()
        notifications.append(notification)
        save_notifications(notifications)
        
        # Emit notification to seller
        socketio.emit('new_order', notification, room=f'notifications_{product["seller_name"]}')
        
        flash('Your order has been placed successfully!', 'success')
        return redirect(url_for('my_orders'))
    
    return render_template('place_order.html', 
                           user_name=session.get('name'),
                           product=product)

@app.route('/my_orders')
@login_required
def my_orders():
    orders = load_orders()
    user_orders = [order for order in orders if order['buyer_id'] == session.get('user_id')]
    
    return render_template('my_orders.html', 
                           user_name=session.get('name'),
                           orders=user_orders)

@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)
    emit('status', {'msg': session.get('name') + ' has joined the room.'}, room=room)

@socketio.on('leave')
def on_leave(data):
    room = data['room']
    leave_room(room)
    emit('status', {'msg': session.get('name') + ' has left the room.'}, room=room)

@socketio.on('message')
def handle_message(data):
    if not session.get('name'):
        return
    room = data['room']
    message = {
        'id': str(uuid.uuid4()),
        'sender_id': session.get('user_id'),
        'sender_name': session.get('name'),
        'receiver_id': data.get('receiver_id'),
        'content': data['message'],
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'read': False
    }
    
    # Save message to file
    messages = load_messages()
    messages.append(message)
    save_messages(messages)
    
    emit('message', message, room=room, include_self=True)

@app.route('/messages')
@login_required
def messages_page():
    return render_template('messages.html',
                         user_name=session.get('name'),
                         user_id=session.get('user_id'))

@app.route('/get_chat_users')
@login_required
def get_chat_users():
    # Get all orders where the user is either buyer or seller
    orders = load_orders()
    messages = load_messages()
    user_id = session.get('user_id')
    
    # Get unique users from orders
    chat_users = set()
    users_data = {}
    
    for order in orders:
        if order['seller_id'] == user_id:
            chat_users.add(order['buyer_id'])
            users_data[order['buyer_id']] = {
                'id': order['buyer_id'],
                'name': order['buyer_name'],
                'product_name': order['product_name'],
                'order_id': order['id']
            }
        elif order['buyer_id'] == user_id:
            chat_users.add(order['seller_id'])
            users_data[order['seller_id']] = {
                'id': order['seller_id'],
                'name': order['seller_name'],
                'product_name': order['product_name'],
                'order_id': order['id']
            }
    
    # Add message data
    for user_id in users_data:
        user_messages = [m for m in messages if 
                        (m['sender_id'] == user_id and m['receiver_id'] == session.get('user_id')) or
                        (m['sender_id'] == session.get('user_id') and m['receiver_id'] == user_id)]
        if user_messages:
            latest_message = max(user_messages, key=lambda x: x['timestamp'])
            users_data[user_id]['last_message'] = latest_message['content']
            users_data[user_id]['unread_count'] = len([m for m in user_messages 
                if m['sender_id'] == user_id and not m.get('read', False)])
    
    return jsonify(list(users_data.values()))

@app.route('/get_chat_history/<user_id>')
@login_required
def get_chat_history(user_id):
    messages = load_messages()
    chat_messages = [m for m in messages if 
                    (m['sender_id'] == user_id and m['receiver_id'] == session.get('user_id')) or
                    (m['sender_id'] == session.get('user_id') and m['receiver_id'] == user_id)]
    
    # Mark messages as read
    for message in messages:
        if message['sender_id'] == user_id and message['receiver_id'] == session.get('user_id'):
            message['read'] = True
    save_messages(messages)
    
    return jsonify(chat_messages)

@app.route('/get_notifications')
@login_required
def get_notifications():
    notifications = load_notifications()
    user_notifications = [n for n in notifications if n['user_id'] == session.get('user_id')]
    return jsonify(user_notifications)

@socketio.on('mark_read')
def mark_notification_read(data):
    notification_id = data.get('notification_id')
    if not notification_id:
        return
    
    notifications = load_notifications()
    for notification in notifications:
        if notification['id'] == notification_id and notification['user_id'] == session.get('user_id'):
            notification['read'] = True
            break
    save_notifications(notifications)

# Ensure upload directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(os.path.join(BASEDIR, 'data'), exist_ok=True)

# Initialize empty data files if they don't exist
if not os.path.exists(PRODUCTS_FILE):
    save_products([])
if not os.path.exists(ORDERS_FILE):
    save_orders([])
if not os.path.exists(MESSAGES_FILE):
    save_messages([])
if not os.path.exists(NOTIFICATIONS_FILE):
    save_notifications([])

# Error handler for 500 errors
@app.errorhandler(500)
def internal_error(error):
    app.logger.error(f'Server Error: {error}')
    return jsonify(error='Internal Server Error'), 500

# Error handler for 404 errors
@app.errorhandler(404)
def not_found_error(error):
    app.logger.error(f'Not Found: {error}')
    return jsonify(error='Resource Not Found'), 404

if __name__ == '__main__':
    # Create directories if they don't exist
    if not os.path.exists('static/uploads'):
        os.makedirs('static/uploads')
    if not os.path.exists('data'):
        os.makedirs('data')
        
    # Run the app
    app.run(debug=True, port=5000)