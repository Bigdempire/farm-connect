# Farm Connect

A real-time web application for connecting farmers and buyers, featuring:
- Product listings with images
- Real-time chat
- Order management
- Instant notifications
- User authentication

## Features

1. **User Management**
   - User registration and login
   - Profile management
   - Role-based access (buyers and sellers)

2. **Product Management**
   - Add/edit/delete products
   - Upload product images
   - Product categorization
   - Search and filter products

3. **Order System**
   - Place orders
   - Track order status
   - Order history
   - Real-time order notifications

4. **Real-time Chat**
   - Direct messaging between buyers and sellers
   - Order-specific chat threads
   - Message notifications
   - Chat history

5. **Notifications**
   - Real-time order notifications
   - Message notifications
   - Read/unread status tracking

## Technology Stack

- **Backend**: Flask, Python
- **Real-time**: Flask-SocketIO
- **Frontend**: HTML, CSS, JavaScript
- **Database**: File-based JSON storage
- **Authentication**: Session-based
- **Deployment**: Gunicorn + Eventlet

## Local Development

1. Clone the repository
2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Run the development server:
   ```bash
   python app.py
   ```

5. Visit `http://localhost:5000` in your browser

## Production Deployment

1. Ensure all requirements are installed:
   ```bash
   pip install -r requirements.txt
   ```

2. Run with Gunicorn:
   ```bash
   gunicorn --worker-class eventlet -w 1 app:app
   ```

## Environment Variables

- `SECRET_KEY`: Application secret key
- `DATABASE`: SQLite database path
- `UPLOAD_FOLDER`: Path for file uploads
- `DEBUG`: Debug mode (True/False)

## File Structure

```
.
├── app.py              # Main application file
├── requirements.txt    # Python dependencies
├── Procfile           # Production server configuration
├── static/            # Static files (CSS, JS, images)
├── templates/         # HTML templates
├── data/             # JSON data storage
└── uploads/          # User uploaded files
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License.
