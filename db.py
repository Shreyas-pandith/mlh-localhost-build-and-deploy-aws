from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column, BigInteger ,String ,ForeignKey
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

import config

database = create_engine(config.DATABASE_URL,max_overflow=-1)
base = declarative_base()


class Articles(base):
    __tablename__ = "Articles"

    id = Column(BigInteger, primary_key=True)
    title = Column(String(100), index=True)
    content = Column(String(100), index=True)
    user_id = Column(BigInteger, ForeignKey('users.id'))





class User(UserMixin, base):
    """Model for user accounts."""

    __tablename__ = 'users'

    id = Column(BigInteger,
                   primary_key=True)
    name = Column(String(50),
                     nullable=False,
                     unique=False)
    email = Column(String(40),
                      unique=True,
                      nullable=False)
    password = Column(String(200),
                         primary_key=False,
                         unique=False,
                         nullable=False)


    def set_password(self, password):
        """Create hashed password."""
        self.password = generate_password_hash(password, method='sha256')

    def check_password(self, password):
        """Check hashed password."""
        return check_password_hash(self.password, password)

    def __repr__(self):
        return '<User {}>'.format(self.name)


   
base.metadata.create_all(database)
Session = sessionmaker(database)

def get_session():
    return Session()
