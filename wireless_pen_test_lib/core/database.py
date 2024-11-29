# wireless_pen_test_lib/core/database.py

from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import datetime

Base = declarative_base()

class Target(Base):
    __tablename__ = 'targets'

    id = Column(Integer, primary_key=True)
    ssid = Column(String, nullable=True)
    bssid = Column(String, unique=True, nullable=False)
    ip = Column(String, nullable=True)
    mac = Column(String, nullable=True)
    hostname = Column(String, nullable=True)
    signal = Column(Integer, nullable=True)
    channel = Column(Integer, nullable=True)
    security = Column(String, nullable=True)
    last_seen = Column(DateTime, default=datetime.datetime.utcnow)
    notes = Column(String, nullable=True)

    def __repr__(self):
        return f"<Target(ssid='{self.ssid}', bssid='{self.bssid}', ip='{self.ip}')>"

class DatabaseManager:
    def __init__(self, db_path='sqlite:///targets.db'):
        self.engine = create_engine(db_path, echo=False, connect_args={"check_same_thread": False})
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def add_target(self, target_data: dict):
        session = self.Session()
        try:
            target = Target(**target_data)
            session.add(target)
            session.commit()
            return target
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def get_all_targets(self) -> list:
        session = self.Session()
        try:
            return session.query(Target).all()
        finally:
            session.close()

    def find_target_by_bssid(self, bssid: str) -> Target:
        session = self.Session()
        try:
            return session.query(Target).filter_by(bssid=bssid).first()
        finally:
            session.close()

    def update_target(self, bssid: str, update_data: dict):
        session = self.Session()
        try:
            target = session.query(Target).filter_by(bssid=bssid).first()
            if target:
                for key, value in update_data.items():
                    setattr(target, key, value)
                target.last_seen = datetime.datetime.utcnow()
                session.commit()
            return target
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()

    def delete_target(self, bssid: str):
        session = self.Session()
        try:
            target = session.query(Target).filter_by(bssid=bssid).first()
            if target:
                session.delete(target)
                session.commit()
        except Exception as e:
            session.rollback()
            raise e
        finally:
            session.close()
