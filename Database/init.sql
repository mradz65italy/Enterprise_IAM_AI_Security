-- Database initialization script for Enterprise AI IAM System
-- This script will be run when the PostgreSQL container starts

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Create database (if not exists - handled by Docker environment)
-- The database is created by the POSTGRES_DB environment variable

-- Set timezone
SET timezone = 'UTC';

-- Create initial admin user after tables are created
-- This will be handled by the application startup process

-- Create indexes for better performance (these will be created by SQLAlchemy)
-- But we can add some additional ones here

-- Function to update the updated_at column
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- This function will be used to create triggers for updated_at columns
-- The triggers will be created by SQLAlchemy when tables are created