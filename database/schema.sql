CREATE TABLE IF NOT EXISTS `tcp_client_server_messages` (
  `client_ip` TEXT NOT NULL,
  `server_ip` TEXT NOT NULL,
  `request_data` TEXT NOT NULL,
  `acknowledgment` TEXT NOT NULL,
  `response_data` TEXT NOT NULL,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS `tcp_proto_messages` (
  `client_ip` TEXT NOT NULL,
  `server_ip` TEXT NOT NULL,
  `proto` TEXT NOT NULL,
  `size` INT NOT NULL,
  `nb_packet` INT NOT NULL,
  `data` TEXT NOT NULL,
  `version` TEXT NOT NULL,
  `hash` TEXT NOT NULL,
  `session` INTEGER,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);