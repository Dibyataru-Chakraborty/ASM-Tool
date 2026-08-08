import sys
from app.utils.database import SessionLocal
from app.models import User
from app.security import PasswordUtils

def create_super_admin(email, password, full_name):
    db = SessionLocal()
    try:
        # Check if user already exists
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            print(f"User {email} already exists!")
            return
        
        # Hash the password
        pwd_hash = PasswordUtils.hash_password(password)
        
        # Create user with role='admin' and tenant_id=None
        user = User(
            email=email,
            password_hash=pwd_hash,
            full_name=full_name,
            role="super_admin",
            tenant_id=None,
            is_active=True,
            is_verified=True
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        print(f"Super admin user {email} created successfully with ID: {user.id}")
    except Exception as e:
        db.rollback()
        print(f"Error creating super admin: {str(e)}")
    finally:
        db.close()

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python create_super_admin.py <email> <password> <full_name>")
        sys.exit(1)
    create_super_admin(sys.argv[1], sys.argv[2], sys.argv[3])
