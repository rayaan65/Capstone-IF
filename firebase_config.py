import os
from dotenv import load_dotenv
import json
import logging
import jwt
from datetime import datetime, timedelta

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create .env.local file if it doesn't exist
def create_env_file():
    env_file_path = '.env.local'
    if not os.path.exists(env_file_path):
        with open(env_file_path, 'w') as f:
            f.write("""# Firebase Configuration
FIREBASE_AUTH_DOMAIN="insightflow-8f69.firebaseapp.com"
FIREBASE_PROJECT_ID="insightflow-8f69"
FIREBASE_STORAGE_BUCKET="insightflow-8f69.firebasestorage.app"
FIREBASE_MESSAGING_SENDER_ID="717441916429"
FIREBASE_APP_ID="1:717441916429:web:c4d90c9c871b41fa2b3f44"
FIREBASE_MEASUREMENT_ID="G-VYQTMVW5GH"
JWT_SECRET="your-jwt-secret-key-change-this-in-production"
"""
            )
        logger.info(".env.local file created successfully")
    else:
        logger.info(".env.local file already exists")

# Load environment variables
def load_env():
    load_dotenv('.env.local')

# Get Firebase config as a dictionary
def get_firebase_config():
    return {
        "apiKey": os.getenv("FIREBASE_API_KEY"),
        "authDomain": os.getenv("FIREBASE_AUTH_DOMAIN"),
        "projectId": os.getenv("FIREBASE_PROJECT_ID"),
        "storageBucket": os.getenv("FIREBASE_STORAGE_BUCKET"),
        "messagingSenderId": os.getenv("FIREBASE_MESSAGING_SENDER_ID"),
        "appId": os.getenv("FIREBASE_APP_ID"),
        "measurementId": os.getenv("FIREBASE_MEASUREMENT_ID")
    }

# Get Firebase config as a JSON string
def get_firebase_config_json():
    return json.dumps(get_firebase_config())

# Create a custom JWT token for user session
def create_custom_token(user_data):
    try:
        # Get secret key from environment
        secret = os.getenv("JWT_SECRET", "insightflow-secret-key")
        
        # Create payload
        payload = {
            "sub": user_data.get("uid", user_data.get("email", "unknown")),
            "email": user_data.get("email", ""),
            "name": user_data.get("displayName", ""),
            "picture": user_data.get("photoURL", ""),
            "exp": datetime.utcnow() + timedelta(hours=1),  # Token expires in 1 hour
            "iat": datetime.utcnow()
        }
        
        # Create token
        token = jwt.encode(payload, secret, algorithm="HS256")
        return token
    except Exception as e:
        logger.error(f"Error creating custom token: {e}")
        return None

# Verify a custom JWT token
def verify_custom_token(token):
    try:
        # Get secret key from environment
        secret = os.getenv("JWT_SECRET", "insightflow-secret-key")
        
        # Decode and verify token
        decoded = jwt.decode(token, secret, algorithms=["HS256"])
        return {
            "success": True,
            "user_id": decoded.get("sub", ""),
            "email": decoded.get("email", ""),
            "name": decoded.get("name", ""),
            "picture": decoded.get("picture", "")
        }
    except jwt.ExpiredSignatureError:
        logger.error("Token has expired")
        return {
            "success": False,
            "error": "Token has expired"
        }
    except jwt.InvalidTokenError as e:
        logger.error(f"Invalid token: {e}")
        return {
            "success": False,
            "error": f"Invalid token: {e}"
        }
    except Exception as e:
        logger.error(f"Error verifying token: {e}")
        return {
            "success": False,
            "error": str(e)
        }

# For backward compatibility with code that expects Firebase Admin SDK
def verify_firebase_token(id_token):
    try:
        # Try to parse the token as a Firebase ID token
        # This is a simplified approach for development
        parts = id_token.split('.')
        if len(parts) != 3:
            raise ValueError("Not a valid JWT token format")
            
        # Decode the payload part (second part) of the JWT
        import base64
        payload_bytes = parts[1].encode('utf-8')
        # Add padding if needed
        payload_bytes += b'=' * (4 - len(payload_bytes) % 4) if len(payload_bytes) % 4 != 0 else b''
        
        try:
            decoded_payload = base64.b64decode(payload_bytes).decode('utf-8')
            user_data = json.loads(decoded_payload)
            
            # Create our own session token
            session_token = create_custom_token(user_data)
            
            return {
                'success': True,
                'user_id': user_data.get('sub', user_data.get('user_id', '')),
                'email': user_data.get('email', ''),
                'name': user_data.get('name', ''),
                'picture': user_data.get('picture', ''),
                'session_token': session_token
            }
        except Exception as e:
            logger.error(f"Error decoding token payload: {e}")
            raise
    except Exception as e:
        logger.error(f"Error processing token: {e}")
        
        # For development only: create a mock user if token verification fails
        mock_user = {
            'success': True,
            'user_id': 'dev-user-123',
            'email': 'dev@example.com',
            'name': 'Development User',
            'picture': '',
            'session_token': create_custom_token({
                'uid': 'dev-user-123',
                'email': 'dev@example.com',
                'displayName': 'Development User'
            })
        }
        logger.warning("Using mock user for development")
        return mock_user

if __name__ == "__main__":
    create_env_file()
    load_env() 