# TCP Game Protocol Analyzer

A powerful Python-based TUI (Text User Interface) tool for analyzing and reverse-engineering TCP-based game protocols. Built with Textual, this tool provides real-time network monitoring, protobuf message decoding, and interactive analysis capabilities.

## Features

- Real-time Network Monitoring: Automatic server discovery and TCP packet capture on configurable ports
- Protobuf Message Decoding: Intelligent parsing of protobuf `Any` messages using magic byte sequences
- Interactive TUI Interface: Multi-panel interface with real-time message display and filtering controls
- Flexible Protocol Filtering: Runtime configuration of message filtering and blacklisting
- Persistent Storage: SQLite database storage for captured communications with session tracking
- Runtime Commands: Interactive command system for dynamic configuration changes

## Use Cases

- Protocol reverse engineering: Analyze unknown game network protocols
- Network traffic analysis: Monitor and decode client-server communications
- Educational research: Learn about network protocols and message structures
- Game development: Understand existing protocol implementations

## Installation

```bash
make install
```

This will create a virtual environment, install all dependencies, and ensure protobuf compiler is available on your system. The Makefile handles both Windows and Linux environments.

## Quick Start

### Basic Usage

```bash
# Monitor default ports (5555, 1119, 8080)
python main.py

# Monitor specific ports with display enabled
python main.py -p 3000 4000 -d

# Use custom protobuf definitions and enable verbose mode
python main.py --proto-path ./my_protos -v
```

### Using Make

```bash
# Run with default settings
make run

# Run with custom arguments
make run VAR="-p 5555 -d -v"

# Show help
make run VAR="--help"
```

## Usage

### Command Line Options

```
usage: main.py [-h] [-p PORTS [PORTS ...]] [-pr [PROTOS ...]] [-bl [BLACKLIST ...]] 
               [-mb MAGIC_BYTES] [--db-path DB_PATH] [--sc-path SC_PATH] 
               [--proto-path PROTO_PATH] [-gv GAME_VERSION] [-d] [-v]

TCP Game Protocol Analyzer - Monitor client-server communication patterns

Options:
  -h, --help                    Show help message and exit
  -p, --ports PORTS             Target server ports to monitor (default: 5555, 1119, 8080)
  -pr, --protos [PROTOS ...]    List of proto packets to filter
  -bl, --blacklist [BLACKLIST ...] List of proto packets to blacklist
  -mb, --magic-bytes MAGIC_BYTES Magic bytes for identifying Any messages
  --db-path DB_PATH             Database path (default: database)
  --sc-path SC_PATH             SQL schema file path (default: database/schema.sql)
  --proto-path PROTO_PATH       Protobuf definitions folder (default: proto)
  -gv, --game-version GAME_VERSION Game version identifier (default: UNKNOWN)
  -d, --display                 Display packets in terminal (default: False)
  -v, --verbose                 Show all protobuf messages found (default: False)
```

### TUI Interface

The tool features a multi-panel interface:

- **Left Panel**: Lists all discovered type_url proto messages
- **Right Panel**: Displays decoded message content for subscribed protocols
- **Command Input**: Interactive command area for runtime configuration

### Runtime Commands

Access the command interface within the TUI to dynamically control the analyzer:

| Command | Description | Example |
|---------|-------------|---------|
| `add_proto <names>` | Add protocols to filter | `add_proto PlayerMove ChatMessage` |
| `remove_proto <names>` | Remove protocols from filter | `remove_proto PlayerMove` |
| `add_blacklist <names>` | Add protocols to blacklist | `add_blacklist HeartBeat` |
| `remove_blacklist <names>` | Remove protocols from blacklist | `remove_blacklist HeartBeat` |
| `verbose` | Toggle verbose mode | `verbose` |
| `show` | Display current configuration | `show` |
| `clear` | Clear display panels | `clear` |
| `restart --previous` | Restart with previous settings | `restart --previous` |
| `restart --current` | Restart with current settings | `restart --current` |
| `help` | Show command help | `help` |

## How It Works

1. Network Scanning: The tool scans specified ports for active game servers
2. Packet Capture: TCP packets are captured and analyzed in real-time
3. Message Parsing: Each message starts with a varint length prefix
4. Protobuf Decoding: Uses magic bytes to locate protobuf `Any` messages within packets
5. Type Resolution: The `type_url` field in `Any` messages points to specific protobuf definitions
6. Database Storage: Successfully decoded messages are stored in SQLite with session tracking

**Note**: Currently, only single-packet messages are handled due to technical limitations.

## Database Schema

The tool stores analyzed data in SQLite with session tracking and comprehensive message metadata:

```sql
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
```

Each record captures the complete context of a decoded message including network endpoints, protocol type, message size, version information, and session tracking.

## Contributing

Contributions are welcome! This project maintains an educational focus for network protocol analysis and reverse engineering learning.

## Troubleshooting

### Common Issues

**No packets captured**: Ensure the target ports are correct and the application is actively communicating.

**Protobuf decoding errors**: Verify that the correct `.proto` files are in the `proto/` directory and magic bytes are properly configured.

**Permission errors**: Network packet capture may require elevated permissions on some systems.

### Getting Help

- Use the `--help` flag for command-line options
- Use the `help` command within the TUI for runtime commands
- Check that all dependencies are properly installed

## 🔧 Advanced Configuration

### Custom Magic Bytes

```bash
python main.py --magic-bytes "\x08\x96\x01"
```

### Multiple Port Monitoring

```bash
python main.py -p 3000 4000 5000 6000
```

### Session Management

Each run creates a new session ID, allowing you to differentiate between analysis sessions in the database. Use the game version flag to add additional context:

```bash
python main.py --game-version "v1.2.3"
```

