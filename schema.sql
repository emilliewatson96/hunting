-- Database Schema for C-Based Web Crawler
-- Run this script to create the necessary tables in MySQL

-- Create database (optional, uncomment if needed)
-- CREATE DATABASE IF NOT EXISTS crawler_db;
-- USE crawler_db;

-- Table: pages
-- Stores information about each crawled page
CREATE TABLE IF NOT EXISTS pages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_url VARCHAR(2048) NOT NULL,
    host VARCHAR(256) NOT NULL,
    path VARCHAR(1024) NOT NULL,
    query VARCHAR(1024) DEFAULT '',
    status_code INT NOT NULL,
    content_length BIGINT DEFAULT 0,
    content_type VARCHAR(128) DEFAULT '',
    http_date VARCHAR(64) DEFAULT '',
    depth INT DEFAULT 0,
    crawled_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    INDEX idx_host (host),
    INDEX idx_status (status_code),
    INDEX idx_depth (depth),
    INDEX idx_crawled_at (crawled_at),
    INDEX idx_host_depth (host, depth)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: url_params
-- Stores URL parameters extracted from crawled pages
CREATE TABLE IF NOT EXISTS url_params (
    id INT AUTO_INCREMENT PRIMARY KEY,
    page_id INT NOT NULL,
    param_name VARCHAR(256) NOT NULL,
    param_value VARCHAR(512) DEFAULT '',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE CASCADE,
    INDEX idx_page_id (page_id),
    INDEX idx_param_name (param_name),
    INDEX idx_param_value (param_value)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Table: assets
-- Stores asset URLs (images, scripts, stylesheets) found on pages
CREATE TABLE IF NOT EXISTS assets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    page_id INT NOT NULL,
    asset_url VARCHAR(2048) NOT NULL,
    asset_type VARCHAR(32) DEFAULT 'unknown',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (page_id) REFERENCES pages(id) ON DELETE CASCADE,
    INDEX idx_page_id (page_id),
    INDEX idx_asset_type (asset_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Useful Views

-- View: v_pages_by_status
-- Summary of pages by HTTP status code
CREATE OR REPLACE VIEW v_pages_by_status AS
SELECT 
    status_code,
    COUNT(*) as page_count,
    SUM(content_length) as total_size
FROM pages
GROUP BY status_code
ORDER BY status_code;

-- View: v_params_by_page
-- All parameters for each page
CREATE OR REPLACE VIEW v_params_by_page AS
SELECT 
    p.id as page_id,
    p.full_url,
    p.host,
    GROUP_CONCAT(CONCAT(param.param_name, '=', param.param_value) SEPARATOR '&') as all_params
FROM pages p
LEFT JOIN url_params param ON p.id = param.page_id
GROUP BY p.id, p.full_url, p.host;

-- View: v_assets_summary
-- Asset counts by type
CREATE OR REPLACE VIEW v_assets_summary AS
SELECT 
    asset_type,
    COUNT(*) as asset_count
FROM assets
GROUP BY asset_type
ORDER BY asset_count DESC;

-- Useful Queries (for reference)

-- Find all unique parameter names across the site
-- SELECT DISTINCT param_name FROM url_params ORDER BY param_name;

-- Find pages with specific parameter
-- SELECT p.* FROM pages p 
-- JOIN url_params param ON p.id = param.page_id 
-- WHERE param.param_name = 'session_id';

-- Find all assets for a specific page
-- SELECT * FROM assets WHERE page_id = 123;

-- Find deepest pages crawled
-- SELECT * FROM pages ORDER BY depth DESC LIMIT 10;

-- Find pages with errors (4xx, 5xx)
-- SELECT * FROM pages WHERE status_code >= 400 ORDER BY status_code;

-- Grant permissions (adjust as needed)
-- GRANT SELECT, INSERT, UPDATE ON crawler_db.* TO 'crawler_user'@'localhost' IDENTIFIED BY 'password';
-- FLUSH PRIVILEGES;
