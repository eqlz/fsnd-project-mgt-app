import os
import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)

class Project(Base):
    __tablename__ = "project"

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    task = relationship('Task', cascade='all, delete-orphan')

    @property
    def serialize(self):
        return {
            'name': self.name
        }

class Task(Base):
    __tablename__ = "task"

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    content = Column(String(500))
    project_id = Column(Integer, ForeignKey('project.id'))
    project = relationship(Project)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property 
    def serialize(self):
        return {
            'name': self.name,
            'content': self.content
        }

engine = create_engine('postgresql://catalog:DB-PASSWORD@localhost/catalog')

Base.metadata.create_all(engine)
