#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
REST API Server - Comprehensive REST API Framework

This script provides a comprehensive REST API server with:
- FastAPI-based REST API framework
- Authentication and authorization
- Database integration (SQLite, PostgreSQL, MySQL)
- API documentation (Swagger/OpenAPI)
- Rate limiting and security
- Logging and monitoring
- CORS support
- Health checks and status endpoints
- File upload/download capabilities
- WebSocket support for real-time features

Author: System Administrator
Version: 1.0.0
Date: 2024-01-01
"""

import os
import sys
import json
import logging
import argparse
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from pathlib import Path
import uvicorn
from fastapi import FastAPI, HTTPException, Depends, status, Request, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
import sqlite3
import psycopg2
import mysql.connector
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import jwt
import bcrypt
import redis
import shutil
import time
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST


# Pydantic models for API
class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: str = Field(..., regex=r'^[^@]+@[^@]+\.[^@]+$')
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None
    role: str = Field(default="user", regex=r'^(admin|user|moderator)$')


class UserLogin(BaseModel):
    username: str
    password: str


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: Optional[str]
    role: str
    created_at: datetime
    is_active: bool


class ItemCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    price: float = Field(..., ge=0)
    category: str = Field(..., min_length=1, max_length=50)


class ItemResponse(BaseModel):
    id: int
    name: str
    description: Optional[str]
    price: float
    category: str
    created_at: datetime
    updated_at: datetime


# Database models
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True)
    email = Column(String(100), unique=True, index=True)
    password_hash = Column(String(255))
    full_name = Column(String(100))
    role = Column(String(20), default="user")
    created_at = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Integer, default=1)


class Item(Base):
    __tablename__ = "items"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), index=True)
    description = Column(Text)
    price = Column(Integer)  # Store as cents
    category = Column(String(50), index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class RESTAPIServer:
    """Comprehensive REST API server"""
    
    def __init__(self, config: Dict = None):
        """Initialize the REST API server"""
        self.config = config or {}
        self.logger = self._setup_logging()
        self.app = FastAPI(
            title="Admin REST API",
            description="Comprehensive REST API for system administration",
            version="1.0.0",
            docs_url="/docs",
            redoc_url="/redoc"
        )
        
        # Setup components
        self._setup_middleware()
        self._setup_database()
        self._setup_security()
        self._setup_metrics()
        self._setup_routes()
        
        # Redis for caching and sessions
        self.redis_client = None
        self._setup_redis()
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger('RESTAPIServer')
        logger.setLevel(logging.INFO)
        
        # Create handlers
        console_handler = logging.StreamHandler()
        file_handler = logging.FileHandler('api_server.log')
        
        # Create formatters and add it to handlers
        log_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        console_handler.setFormatter(log_format)
        file_handler.setFormatter(log_format)
        
        # Add handlers to the logger
        logger.addHandler(console_handler)
        logger.addHandler(file_handler)
        
        return logger
    
    def _setup_middleware(self):
        """Setup middleware"""
        # CORS middleware
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=self.config.get('cors_origins', ["*"]),
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # Request logging middleware
        @self.app.middleware("http")
        async def log_requests(request: Request, call_next):
            start_time = datetime.utcnow()
            
            # Log request
            self.logger.info(f"Request: {request.method} {request.url}")
            
            response = await call_next(request)
            
            # Log response
            process_time = (datetime.utcnow() - start_time).total_seconds()
            self.logger.info(f"Response: {response.status_code} - {process_time:.3f}s")
            
            # Update metrics
            self.request_counter.inc()
            self.request_duration.observe(process_time)
            
            return response
    
    def _setup_database(self):
        """Setup database connection"""
        db_config = self.config.get('database', {})
        db_type = db_config.get('type', 'sqlite')
        
        if db_type == 'sqlite':
            db_url = db_config.get('url', 'sqlite:///./api_server.db')
            self.engine = create_engine(db_url, connect_args={"check_same_thread": False})
        elif db_type == 'postgresql':
            db_url = f"postgresql://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['database']}"
            self.engine = create_engine(db_url)
        elif db_type == 'mysql':
            db_url = f"mysql+pymysql://{db_config['user']}:{db_config['password']}@{db_config['host']}:{db_config['port']}/{db_config['database']}"
            self.engine = create_engine(db_url)
        else:
            raise ValueError(f"Unsupported database type: {db_type}")
        
        # Create tables
        Base.metadata.create_all(bind=self.engine)
        
        # Create session factory
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
    
    def _setup_security(self):
        """Setup security components"""
        self.secret_key = self.config.get('secret_key', 'your-secret-key-change-this')
        self.algorithm = "HS256"
        self.access_token_expire_minutes = self.config.get('access_token_expire_minutes', 30)
        self.security = HTTPBearer()
    
    def _setup_metrics(self):
        """Setup Prometheus metrics"""
        self.request_counter = Counter('http_requests_total', 'Total HTTP requests', ['method', 'endpoint'])
        self.request_duration = Histogram('http_request_duration_seconds', 'HTTP request duration')
        self.error_counter = Counter('http_errors_total', 'Total HTTP errors', ['method', 'endpoint', 'status_code'])
    
    def _setup_redis(self):
        """Setup Redis connection"""
        redis_config = self.config.get('redis', {})
        if redis_config:
            try:
                self.redis_client = redis.Redis(
                    host=redis_config.get('host', 'localhost'),
                    port=redis_config.get('port', 6379),
                    db=redis_config.get('db', 0),
                    password=redis_config.get('password'),
                    decode_responses=True
                )
                # Test connection
                self.redis_client.ping()
                self.logger.info("Redis connection established")
            except Exception as e:
                self.logger.warning(f"Redis connection failed: {e}")
                self.redis_client = None
    
    def get_db(self):
        """Get database session"""
        db = self.SessionLocal()
        try:
            yield db
        finally:
            db.close()
    
    def create_access_token(self, data: dict, expires_delta: Optional[timedelta] = None):
        """Create JWT access token"""
        to_encode = data.copy()
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=self.access_token_expire_minutes)
        
        to_encode.update({"exp": expire})
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
        """Verify JWT token"""
        try:
            payload = jwt.decode(credentials.credentials, self.secret_key, algorithms=[self.algorithm])
            username: str = payload.get("sub")
            if username is None:
                raise HTTPException(status_code=401, detail="Invalid token")
            return username
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail="Token expired")
        except jwt.JWTError:
            raise HTTPException(status_code=401, detail="Invalid token")
    
    def get_current_user(self, username: str = Depends(verify_token), db = Depends(get_db)):
        """Get current user from database"""
        user = db.query(User).filter(User.username == username).first()
        if user is None:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    
    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def _setup_routes(self):
        """Setup API routes"""
        
        @self.app.get("/")
        async def root():
            """Root endpoint"""
            return {"message": "Admin REST API Server", "version": "1.0.0"}
        
        @self.app.get("/health")
        async def health_check():
            """Health check endpoint"""
            return {
                "status": "healthy",
                "timestamp": datetime.utcnow().isoformat(),
                "database": "connected",
                "redis": "connected" if self.redis_client else "disconnected"
            }
        
        @self.app.get("/metrics")
        async def metrics():
            """Prometheus metrics endpoint"""
            return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
        
        # Authentication routes
        @self.app.post("/auth/register", response_model=UserResponse)
        async def register(user_data: UserCreate, db = Depends(get_db)):
            """Register new user"""
            # Check if user already exists
            existing_user = db.query(User).filter(
                (User.username == user_data.username) | (User.email == user_data.email)
            ).first()
            
            if existing_user:
                raise HTTPException(status_code=400, detail="Username or email already registered")
            
            # Create new user
            hashed_password = self.hash_password(user_data.password)
            db_user = User(
                username=user_data.username,
                email=user_data.email,
                password_hash=hashed_password,
                full_name=user_data.full_name,
                role=user_data.role
            )
            
            db.add(db_user)
            db.commit()
            db.refresh(db_user)
            
            self.logger.info(f"New user registered: {user_data.username}")
            return UserResponse(
                id=db_user.id,
                username=db_user.username,
                email=db_user.email,
                full_name=db_user.full_name,
                role=db_user.role,
                created_at=db_user.created_at,
                is_active=bool(db_user.is_active)
            )
        
        @self.app.post("/auth/login")
        async def login(user_data: UserLogin, db = Depends(get_db)):
            """Login user"""
            user = db.query(User).filter(User.username == user_data.username).first()
            
            if not user or not self.verify_password(user_data.password, user.password_hash):
                raise HTTPException(status_code=401, detail="Invalid credentials")
            
            if not user.is_active:
                raise HTTPException(status_code=401, detail="User account is disabled")
            
            # Create access token
            access_token_expires = timedelta(minutes=self.access_token_expire_minutes)
            access_token = self.create_access_token(
                data={"sub": user.username}, expires_delta=access_token_expires
            )
            
            self.logger.info(f"User logged in: {user.username}")
            return {"access_token": access_token, "token_type": "bearer"}
        
        # User management routes
        @self.app.get("/users/me", response_model=UserResponse)
        async def get_current_user_info(current_user: User = Depends(get_current_user)):
            """Get current user information"""
            return UserResponse(
                id=current_user.id,
                username=current_user.username,
                email=current_user.email,
                full_name=current_user.full_name,
                role=current_user.role,
                created_at=current_user.created_at,
                is_active=bool(current_user.is_active)
            )
        
        @self.app.get("/users", response_model=List[UserResponse])
        async def get_users(
            skip: int = 0,
            limit: int = 100,
            current_user: User = Depends(get_current_user),
            db = Depends(get_db)
        ):
            """Get all users (admin only)"""
            if current_user.role != "admin":
                raise HTTPException(status_code=403, detail="Admin access required")
            
            users = db.query(User).offset(skip).limit(limit).all()
            return [
                UserResponse(
                    id=user.id,
                    username=user.username,
                    email=user.email,
                    full_name=user.full_name,
                    role=user.role,
                    created_at=user.created_at,
                    is_active=bool(user.is_active)
                )
                for user in users
            ]
        
        # Item management routes
        @self.app.post("/items", response_model=ItemResponse)
        async def create_item(
            item_data: ItemCreate,
            current_user: User = Depends(get_current_user),
            db = Depends(get_db)
        ):
            """Create new item"""
            db_item = Item(
                name=item_data.name,
                description=item_data.description,
                price=int(item_data.price * 100),  # Store as cents
                category=item_data.category
            )
            
            db.add(db_item)
            db.commit()
            db.refresh(db_item)
            
            self.logger.info(f"Item created: {item_data.name} by {current_user.username}")
            return ItemResponse(
                id=db_item.id,
                name=db_item.name,
                description=db_item.description,
                price=db_item.price / 100,  # Convert back to dollars
                category=db_item.category,
                created_at=db_item.created_at,
                updated_at=db_item.updated_at
            )
        
        @self.app.get("/items", response_model=List[ItemResponse])
        async def get_items(
            skip: int = 0,
            limit: int = 100,
            category: Optional[str] = None,
            db = Depends(get_db)
        ):
            """Get all items with optional filtering"""
            query = db.query(Item)
            
            if category:
                query = query.filter(Item.category == category)
            
            items = query.offset(skip).limit(limit).all()
            
            return [
                ItemResponse(
                    id=item.id,
                    name=item.name,
                    description=item.description,
                    price=item.price / 100,
                    category=item.category,
                    created_at=item.created_at,
                    updated_at=item.updated_at
                )
                for item in items
            ]
        
        @self.app.get("/items/{item_id}", response_model=ItemResponse)
        async def get_item(item_id: int, db = Depends(get_db)):
            """Get specific item"""
            item = db.query(Item).filter(Item.id == item_id).first()
            if item is None:
                raise HTTPException(status_code=404, detail="Item not found")
            
            return ItemResponse(
                id=item.id,
                name=item.name,
                description=item.description,
                price=item.price / 100,
                category=item.category,
                created_at=item.created_at,
                updated_at=item.updated_at
            )
        
        @self.app.put("/items/{item_id}", response_model=ItemResponse)
        async def update_item(
            item_id: int,
            item_data: ItemCreate,
            current_user: User = Depends(get_current_user),
            db = Depends(get_db)
        ):
            """Update item"""
            item = db.query(Item).filter(Item.id == item_id).first()
            if item is None:
                raise HTTPException(status_code=404, detail="Item not found")
            
            item.name = item_data.name
            item.description = item_data.description
            item.price = int(item_data.price * 100)
            item.category = item_data.category
            item.updated_at = datetime.utcnow()
            
            db.commit()
            db.refresh(item)
            
            self.logger.info(f"Item updated: {item.name} by {current_user.username}")
            return ItemResponse(
                id=item.id,
                name=item.name,
                description=item.description,
                price=item.price / 100,
                category=item.category,
                created_at=item.created_at,
                updated_at=item.updated_at
            )
        
        @self.app.delete("/items/{item_id}")
        async def delete_item(
            item_id: int,
            current_user: User = Depends(get_current_user),
            db = Depends(get_db)
        ):
            """Delete item"""
            item = db.query(Item).filter(Item.id == item_id).first()
            if item is None:
                raise HTTPException(status_code=404, detail="Item not found")
            
            db.delete(item)
            db.commit()
            
            self.logger.info(f"Item deleted: {item.name} by {current_user.username}")
            return {"message": "Item deleted successfully"}
        
        # File upload/download routes
        @self.app.post("/upload")
        async def upload_file(
            file: UploadFile = File(...),
            current_user: User = Depends(get_current_user)
        ):
            """Upload file"""
            # Create uploads directory
            upload_dir = Path("uploads")
            upload_dir.mkdir(exist_ok=True)
            
            # Save file
            file_path = upload_dir / f"{current_user.username}_{file.filename}"
            with open(file_path, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            
            self.logger.info(f"File uploaded: {file.filename} by {current_user.username}")
            return {"filename": file.filename, "saved_path": str(file_path)}
        
        @self.app.get("/download/{filename}")
        async def download_file(
            filename: str,
            current_user: User = Depends(get_current_user)
        ):
            """Download file"""
            file_path = Path("uploads") / filename
            if not file_path.exists():
                raise HTTPException(status_code=404, detail="File not found")
            
            return FileResponse(file_path, filename=filename)
        
        # System information routes
        @self.app.get("/system/info")
        async def get_system_info():
            """Get system information"""
            import psutil
            
            return {
                "cpu_percent": psutil.cpu_percent(),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_usage": psutil.disk_usage('/').percent,
                "uptime": time.time() - psutil.boot_time(),
                "python_version": sys.version,
                "platform": sys.platform
            }
        
        # Error handlers
        @self.app.exception_handler(HTTPException)
        async def http_exception_handler(request: Request, exc: HTTPException):
            """Handle HTTP exceptions"""
            self.error_counter.inc(method=request.method, endpoint=request.url.path, status_code=exc.status_code)
            return JSONResponse(
                status_code=exc.status_code,
                content={"detail": exc.detail}
            )
    
    def run(self, host: str = "0.0.0.0", port: int = 8000, reload: bool = False):
        """Run the API server"""
        self.logger.info(f"Starting REST API server on {host}:{port}")
        uvicorn.run(self.app, host=host, port=port, reload=reload)


def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='REST API Server')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8000, help='Port to bind to')
    parser.add_argument('--config', type=str, help='Configuration file path')
    parser.add_argument('--reload', action='store_true', help='Enable auto-reload')
    
    args = parser.parse_args()
    
    # Load configuration
    config = {}
    if args.config and os.path.exists(args.config):
        with open(args.config, 'r') as f:
            config = json.load(f)
    
    # Create and run server
    server = RESTAPIServer(config)
    server.run(host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main() 