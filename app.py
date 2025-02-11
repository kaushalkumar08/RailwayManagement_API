from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from functools import wraps
import jwt
import datetime
from flask_bcrypt import Bcrypt
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:devil@localhost/railway_db'
app.config['SECRET_KEY'] = 'your_jwt_secret_key'
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Define Models (User, Train, Booking)
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # Role can be "admin" or "user"

class Train(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    source = db.Column(db.String(50), nullable=False)
    destination = db.Column(db.String(50), nullable=False)
    total_seats = db.Column(db.Integer, nullable=False)
    available_seats = db.Column(db.Integer, nullable=False)

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    train_id = db.Column(db.Integer, db.ForeignKey('train.id'), nullable=False)
    seats_booked = db.Column(db.Integer, nullable=False)

# Helper function to protect admin routes
# Modify the token_required decorator for user access as well
def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"message": "Token is missing!"}), 403
        try:
            token = token.split(" ")[1]  # Get the token part after 'Bearer'
            print(f"Decoded Token: {token}")  # Debugging line
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            user_id = data['user_id']
            user = User.query.get(user_id)
            if not user:
                return jsonify({"message": "User not found!"}), 403
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 403
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token is invalid!"}), 403
        except Exception as e:
            print(f"Error: {str(e)}")  # Debugging line
            return jsonify({"message": "Token is invalid!"}), 403
        return f(*args, **kwargs)
    return decorated_function



# User Registration Endpoint
@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    role = data.get('role', 'user')  # default role is 'user'

    # Check if username already exists
    existing_user = User.query.filter_by(username=username).first()
    if existing_user:
        return jsonify({"message": "Username already exists!"}), 400

    hashed_password = generate_password_hash(password, method='scrypt')
    new_user = User(username=username, password=hashed_password, role=role)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User created successfully!"}), 201

# User Login Endpoint
@app.route('/login', methods=['POST'])
def login_user():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):  # Check hashed password
        # Create JWT token if login is successful
        token = jwt.encode({
            'user_id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=3)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token})
    return jsonify({"message": "Invalid credentials!"}), 401

# Add New Train (Admin Only)
@app.route('/train', methods=['POST'])
@token_required
def add_train():
    data = request.get_json()
    new_train = Train(name=request.json['name'],
    source=request.json['source'],
    destination=request.json['destination'],
    total_seats=request.json['total_seats'],
    available_seats=data['total_seats'])
    db.session.add(new_train)
    db.session.commit()
    return jsonify({"message": "Train added successfully!"})

# Get Seat Availability
@app.route('/availability', methods=['GET'])
def get_availability():
    source = request.args.get('source')
    destination = request.args.get('destination')

    if not source or not destination:
        return jsonify({"message": "Both source and destination are required!"}), 400

    trains = Train.query.filter_by(source=source, destination=destination).all()
    if not trains:
        return jsonify({"message": "No trains found for the given route."}), 404

    available_trains = [{"train_id": train.id, "source": train.source, "destination": train.destination, "available_seats": train.available_seats} for train in trains]
    return jsonify(available_trains)

# Book a Seat
@app.route('/book', methods=['POST'])
def book_seat():
    token = request.headers.get('Authorization')
    print(f"Authorization Header: {token}")  # Debugging line to check the token
    if not token:
        return jsonify({"message": "Token is missing!"}), 403
    
    try:
        data_from_token = jwt.decode(token.split(" ")[1], app.config['SECRET_KEY'], algorithms=['HS256'])
        user_id = data_from_token['user_id']
        print(f"User ID: {user_id}")  # Debugging line
    except Exception as e:
        print(f"Error while decoding token: {str(e)}")  # Debugging line
        return jsonify({"message": "Token is invalid!"}), 403
    
    # Now, get the booking data
    booking_data = request.get_json()
    train_id = booking_data['train_id']
    seats_booked = booking_data['seats_booked']
    print(f"Booking Details - Train ID: {train_id}, Seats Booked: {seats_booked}")  # Debugging line

    train = Train.query.get(train_id)
    if train and train.available_seats >= seats_booked:
        train.available_seats -= seats_booked
        new_booking = Booking(user_id=user_id, train_id=train_id, seats_booked=seats_booked)
        db.session.add(new_booking)
        db.session.commit()
        return jsonify({"message": "Seats booked successfully!"})
    
    return jsonify({"message": "Not enough seats available!"}), 400


# Get Specific Booking Details
@app.route('/booking_details/<int:train_id>', methods=['GET'])
def booking_details(train_id):
    bookings = Booking.query.filter_by(train_id=train_id).all()
    
    if not bookings:
        return jsonify({"message": "No bookings found for this train."}), 404

    booking_details = []
    for booking in bookings:
        booking_info = {
            "user_id": booking.user_id,
            "train_id": booking.train_id,
            "seats_booked": booking.seats_booked
        }
        booking_details.append(booking_info)
    
    return jsonify(booking_details), 200

if __name__ == '__main__':
    app.run(debug=True)
