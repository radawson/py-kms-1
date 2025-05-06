#!/usr/bin/env python3

import os
import logging
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, TypeDecorator, TIMESTAMP, inspect
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import SQLAlchemyError
from pykms_Format import pretty_printer

loggersrv = logging.getLogger('logsrv')
Base = declarative_base()

class UnixTimestamp(TypeDecorator):
    """
    Custom type that stores Unix timestamps as TIMESTAMP in the database.
    Works consistently across SQLite, MySQL, and PostgreSQL.
    """
    impl = TIMESTAMP
    cache_ok = True

    def process_bind_param(self, value, dialect):
        """Convert input value to datetime before storing in database"""
        if value is not None:
            if isinstance(value, (int, float)):
                return datetime.fromtimestamp(value)
            elif isinstance(value, str):
                try:
                    return datetime.fromisoformat(value)
                except ValueError:
                    try:
                        return datetime.fromtimestamp(float(value))
                    except ValueError:
                        return None
            elif isinstance(value, datetime):
                return value
        return None

    def process_result_value(self, value, dialect):
        """Convert database value to datetime when retrieving"""
        if value is not None:
            if isinstance(value, str):
                try:
                    return datetime.fromisoformat(value)
                except ValueError:
                    return None
            return value
        return None

    def coerce_compared_value(self, op, value):
        """Handle comparison operations"""
        if value is None:
            return self.impl
        if isinstance(value, (int, float)):
            return self.impl
        return self

class Client(Base):
    __tablename__ = 'clients'
    
    id = Column(Integer, primary_key=True)
    clientMachineId = Column(String(255))  # Explicit length for MySQL compatibility
    machineName = Column(String(255))
    applicationId = Column(String(255))
    skuId = Column(String(255))
    licenseStatus = Column(String(50))
    lastRequestTime = Column(UnixTimestamp, nullable=False)
    kmsEpid = Column(String(255))
    requestCount = Column(Integer, default=1)
    ipAddress = Column(String(45))  # Support both IPv4 and IPv6 addresses

class DatabaseBackend:
    def __init__(self, connection_string):
        # Add connection settings for better compatibility
        if 'mysql' in connection_string:
            self.engine = create_engine(
                connection_string,
                pool_recycle=3600,  
                pool_pre_ping=True  
            )
        elif 'postgresql' in connection_string:
            self.engine = create_engine(
                connection_string,
                pool_size=5,
                max_overflow=10
            )
        else:  # SQLite
            self.engine = create_engine(
                connection_string,
                connect_args={'timeout': 30}  
            )
        
        # Check if we need to add the ipAddress column
        self._check_and_update_schema()
        
        Base.metadata.create_all(self.engine)
        Session = sessionmaker(bind=self.engine)
        self.session = Session()

    def _check_and_update_schema(self):
        """Check if ipAddress column exists and add it if it doesn't."""
        try:
            # Get database inspector
            inspector = inspect(self.engine)
            
            # Check if clients table exists and get its columns
            if 'clients' in inspector.get_table_names():
                columns = [col['name'] for col in inspector.get_columns('clients')]
                if 'ipAddress' not in columns:
                    # Add ipAddress column
                    with self.engine.connect() as connection:
                        if 'sqlite' in str(self.engine.url):
                            # SQLite syntax
                            connection.execute('ALTER TABLE clients ADD COLUMN ipAddress VARCHAR(45)')
                        elif 'mysql' in str(self.engine.url):
                            # MySQL syntax
                            connection.execute('ALTER TABLE clients ADD COLUMN ipAddress VARCHAR(45)')
                        elif 'postgresql' in str(self.engine.url):
                            # PostgreSQL syntax
                            connection.execute('ALTER TABLE clients ADD COLUMN ipAddress VARCHAR(45)')
                        connection.commit()
                    pretty_printer(log_obj=loggersrv.info,
                                 put_text="Added ipAddress column to clients table")
        except Exception as e:
            pretty_printer(log_obj=loggersrv.error, to_exit=False,
                         put_text="{reverse}{red}{bold}Schema update error: %s. Continuing...{end}" % str(e))

    def update_client(self, info_dict):
        try:
            client = self.session.query(Client).filter_by(
                clientMachineId=info_dict['clientMachineId'],
                applicationId=info_dict['appId']
            ).first()

            if not client:
                # Insert new client
                client = Client(
                    clientMachineId=info_dict['clientMachineId'],
                    machineName=info_dict['machineName'],
                    applicationId=info_dict['appId'],
                    skuId=info_dict['skuId'],
                    licenseStatus=info_dict['licenseStatus'],
                    lastRequestTime=info_dict['requestTime'],
                    ipAddress=info_dict.get('ipAddress')
                )
                self.session.add(client)
            else:
                # Update existing client
                client.machineName = info_dict['machineName']
                client.applicationId = info_dict['appId']
                client.skuId = info_dict['skuId']
                client.licenseStatus = info_dict['licenseStatus']
                client.lastRequestTime = info_dict['requestTime']
                client.ipAddress = info_dict.get('ipAddress')
                client.requestCount += 1

            self.session.commit()

        except SQLAlchemyError as e:
            self.session.rollback()
            pretty_printer(log_obj=loggersrv.error, to_exit=False,
                         put_text="{reverse}{red}{bold}Database Error: %s. Continuing...{end}" % str(e))

    def update_epid(self, kms_request, response, app_name):
        try:
            cmid = str(kms_request['clientMachineId'].get())
            client = self.session.query(Client).filter_by(
                clientMachineId=cmid,
                applicationId=app_name
            ).first()

            if client:
                client.kmsEpid = str(response["kmsEpid"].decode('utf-16le'))
                self.session.commit()

        except SQLAlchemyError as e:
            self.session.rollback()
            pretty_printer(log_obj=loggersrv.error, to_exit=False,
                         put_text="{reverse}{red}{bold}Database Error: %s. Continuing...{end}" % str(e))

    def get_all_clients(self):
        try:
            return self.session.query(Client).all()
        except SQLAlchemyError as e:
            pretty_printer(log_obj=loggersrv.error, to_exit=False,
                         put_text="{reverse}{red}{bold}Database Error: %s. Continuing...{end}" % str(e))
            return []

def create_backend(config):
    """Create database backend based on configuration"""
    if config.get('db_type') == 'mysql':
        connection_string = f"mysql+pymysql://{config['db_user']}:{config['db_password']}@{config['db_host']}/{config['db_name']}?charset=utf8mb4"
    elif config.get('db_type') == 'postgresql':
        connection_string = f"postgresql://{config['db_user']}:{config['db_password']}@{config['db_host']}/{config['db_name']}"
    else:  # Default to SQLite
        connection_string = config.get('db_name', 'sqlite:///pykms_database.db')

    return DatabaseBackend(connection_string) 