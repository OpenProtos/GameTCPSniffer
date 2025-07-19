CREATE TABLE IF NOT EXISTS `tcp` (
  `client_ip` TEXT NOT NULL,
  `server_ip` TEXT NOT NULL,
  `request_data` TEXT NOT NULL,
  `acknowledgment` TEXT NOT NULL,
  `response_data` TEXT NOT NULL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);