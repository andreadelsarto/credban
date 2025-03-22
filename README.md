# CredBan

CredBan is a protection system against SSH brute force attacks for Linux systems.

## How It Works

CredBan monitors the SSH access log file and keeps track of failed login attempts. Each IP address starts with a certain number of "credits". When a failed login attempt occurs, the IP loses a credit. When credits drop to zero, the IP is temporarily banned using iptables.

Banned IPs are automatically unblocked after a certain period of time, and their credits are restored.

## Key Features

- Configurable credit system
- Temporary ban of IPs with too many failed attempts
- Progressive ban duration using Fibonacci sequence for repeat offenders
- Whitelist for trusted IPs
- Configuration via INI file
- Comprehensive activity logging
- Automatic restoration of banned IPs
- Secure firewall management with input validation
- Advanced logging system with severity levels and syslog support

## Progressive Ban System

CredBan implements a progressive ban system that increases the ban duration each time an IP address is banned:

- First ban: 1 hour (default)
- Second ban: 2 hours
- Third ban: 3 hours
- Fourth ban: 5 hours
- Fifth ban: 8 hours
- Sixth ban: 13 hours
- And so on...

This follows the Fibonacci sequence (1, 2, 3, 5, 8, 13, 21, ...) and provides an effective deterrent against persistent attackers. The ban count is maintained even after system restarts.

## Dependencies

- g++ (with C++17 support)
- iptables
- make

To install dependencies on Debian/Ubuntu systems:
```
sudo apt-get install g++ iptables make
```

## Installation

1. Compile the program:
   ```
   make
   ```

2. Install the program and configuration:
   ```
   sudo make install
   ```

3. Enable and start the service:
   ```
   sudo systemctl enable credban
   sudo systemctl start credban
   ```

## Configuration

The default configuration file `/etc/credban.config` is in INI format and contains the following sections:

### [General]
- `ProgramName`: Name of the program
- `PidFile`: Path to the PID file

### [Credits]
- `MaxCredits`: Maximum number of credits per IP (default: 10)
- `InitialCredits`: Initial credits for each new IP (default: 3)
- `BanDurationSeconds`: Ban duration in seconds (default: 3600, 1 hour) - This is the base duration for the first ban, which increases for repeat offenders

### [Files]
- `CreditsFile`: File to save IP credits
- `AuthLogFile`: Access log file to monitor
- `CredBanLogFile`: Log file for CredBan

### [Intervals]
- `PeriodicCleanupSeconds`: Interval for periodic data cleanup
- `LogCheckSeconds`: Interval for checking new log events

### [IP]
- `TrustedIPs`: List of trusted IPs separated by commas (will never be banned)

### [Logging]
- `MinLevel`: Minimum log level to record (DEBUG, INFO, WARNING, ERROR)
- `EnableConsole`: If true, also prints logs to the console
- `EnableSyslog`: If true, sends logs to syslog

## Usage

```
credban [options]
```

### Options
- `-c, --config FILE`: Specify an alternative configuration file
- `-h, --help`: Show the help message
- `-v, --version`: Show the program version

## Monitoring

To monitor CredBan activity:
```
sudo tail -f /var/log/credban.log
```

To view currently banned IPs:
```
sudo iptables -L INPUT -n | grep DROP
```

If you have enabled syslog support, you can also see the logs with:
```
sudo journalctl -t credban
```

## Logging Levels

CredBan uses an advanced logging system with the following levels:

- **DEBUG**: Detailed information, useful for program debugging
- **INFO**: General information about normal operation
- **WARNING**: Warnings that might require attention but are not critical
- **ERROR**: Errors that prevent proper functioning

You can configure the minimum level of messages to record via the `MinLevel` parameter in the `[Logging]` section of the configuration file.

## Uninstallation

To completely uninstall CredBan:
```
sudo make uninstall
```

## Security

CredBan version 1.2.0 offers significant improvements:

1. Secure firewall management with input validation
2. Advanced logging system for better diagnostics and monitoring
3. Syslog support for integration with centralized monitoring systems
4. Progressive ban duration for repeat offenders, providing stronger protection against persistent attackers

## Contributing

If you would like to contribute to the project, you are welcome! You can open a pull request or report issues in the "Issues" area on GitHub. 