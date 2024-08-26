from app import db, User, app
from werkzeug.security import generate_password_hash

def create_admin(username, password):
    with app.app_context():  # Create an application context
        admin = User.query.filter_by(username=username).first()
        if admin:
            print(f'User {username} already exists.')
            return
        
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_admin = User(username=username, password=hashed_password, is_admin=True)
        db.session.add(new_admin)
        db.session.commit()
        print(f'Admin user {username} created successfully.')

if __name__ == '__main__':
    import sys
    if len(sys.argv) != 3:
        print('Usage: python create_admin.py <username> <password>')
        sys.exit(1)
    
    username = sys.argv[1]
    password = sys.argv[2]
    create_admin(username, password)
