import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Any
from pymongo import MongoClient
import mongomock
from app.config import settings

logger = logging.getLogger("epa.database")

class DatabaseManager:
    _instance = None

    def __init__(self):
        self.client: Any = None
        self.db: Any = None
        self.is_mock: bool = False
        self._initialize()

    def _initialize(self):
        """Attempt connection to real MongoDB; fallback gracefully to mongomock."""
        try:
            logger.info(f"Connecting to MongoDB at {settings.MONGODB_URI}...")
            client = MongoClient(settings.MONGODB_URI, serverSelectionTimeoutMS=2000)
            # Test connection
            client.admin.command('ping')
            self.client = client
            self.db = client[settings.DATABASE_NAME]
            self.is_mock = False
            logger.info("Connected to MongoDB successfully.")
        except Exception as e:
            logger.warning(f"Could not connect to live MongoDB ({e}). Falling back to in-memory mongomock for development/testing.")
            self.client = mongomock.MongoClient()
            self.db = self.client[settings.DATABASE_NAME]
            self.is_mock = True
        
        self._ensure_indexes()

    def _ensure_indexes(self):
        """Create helpful indexes for performance and uniqueness."""
        try:
            self.db.users.create_index("email", unique=True)
            self.db.users.create_index("user_id", unique=True)
            self.db.reports.create_index("report_id", unique=True)
            self.db.reports.create_index([("user_id", 1), ("created_at", -1)])
            self.db.gmail_connections.create_index("user_id", unique=True)
            self.db.settings.create_index("user_id", unique=True)

            # Threat Intelligence Collections
            self.db.cyber_incidents.create_index("incident_id", unique=True)
            self.db.cyber_incidents.create_index([("date_reported", -1), ("category", 1)])
            self.db.cyber_incidents.create_index("company")
            self.db.threat_indicators.create_index("indicator_value", unique=True)
            self.db.threat_indicators.create_index([("indicator_type", 1), ("last_seen", -1)])
            self.db.vulnerabilities.create_index("cve_id", unique=True)
            self.db.vulnerabilities.create_index([("date_added", -1), ("vendor_project", 1)])
            self.db.intelligence_sources.create_index("source_id", unique=True)
            self.db.synchronization_logs.create_index([("timestamp", -1)])
        except Exception as e:
            logger.warning(f"Index creation notice: {e}")

    def apply_retention_policy(self, user_id: str, retention_days: int) -> int:
        """Purge reports older than the retention period for user data hygiene."""
        if retention_days <= 0:
            return 0  # Infinite retention
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        result = self.db.reports.delete_many({
            "user_id": user_id,
            "created_at": {"$lt": cutoff_date.isoformat()}
        })
        return result.deleted_count

db_manager = DatabaseManager()

def get_db():
    return db_manager.db

def get_users_col():
    return db_manager.db.users

def get_reports_col():
    return db_manager.db.reports

def get_connections_col():
    return db_manager.db.gmail_connections

def get_settings_col():
    return db_manager.db.settings

def get_incidents_col():
    return db_manager.db.cyber_incidents

def get_indicators_col():
    return db_manager.db.threat_indicators

def get_vulnerabilities_col():
    return db_manager.db.vulnerabilities

def get_sources_col():
    return db_manager.db.intelligence_sources

def get_sync_logs_col():
    return db_manager.db.synchronization_logs
