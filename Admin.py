import sqlite3
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app import User, db  

def update_user_role():
    engine = create_engine('sqlite:///users.db')  

    Session = sessionmaker(bind=engine)
    session = Session()

    try:
        user = session.query(User).filter_by(email='araj0259@gmail.com').first()

        if user:
            user.role = 'Creator'
            session.commit()
            print(f"User {user.email} role updated to Creator")
        else:
            print("User not found")

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        session.rollback()


if __name__ == '__main__':
    update_user_role()