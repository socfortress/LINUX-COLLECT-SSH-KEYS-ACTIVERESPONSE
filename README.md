## Collect-SSH-Keys.sh

This script collects and analyzes SSH configuration files and keys across user homes and system locations, providing a JSON-formatted output for integration with your SIEM.

### Overview

The `Collect-SSH-Keys.sh` script scans for SSH-related files, including authorized keys and configuration files, analyzing them for potential security issues. It outputs results in a standardized JSON format suitable for active response workflows.

### Script Details

#### Core Features

1. **Key File Collection**: Scans for SSH keys and configurations in user homes and system directories.
2. **Configuration Analysis**: Analyzes SSH configuration files for security issues.
3. **Weak Key Detection**: Identifies potentially weak SSH key types (e.g., ssh-rsa).
4. **JSON Output**: Generates a structured JSON report for integration with security tools.
5. **Logging Framework**: Provides detailed logs for script execution.
6. **Log Rotation**: Implements automatic log rotation to manage log file size.

### How the Script Works

#### Command Line Execution
```bash
./Collect-SSH-Keys.sh
```

#### Parameters

| Parameter | Type | Default Value | Description |
|-----------|------|---------------|-------------|
| `ARLog` | string | `/var/ossec/active-response/active-responses.log` | Path for active response JSON output |
| `LogPath` | string | `/tmp/Collect-SSH-Keys.sh-script.log` | Path for detailed execution logs |
| `LogMaxKB` | int | 100 | Maximum log file size in KB before rotation |
| `LogKeep` | int | 5 | Number of rotated log files to retain |

### Script Execution Flow

#### 1. Initialization Phase
- Clears the active response log file
- Rotates the detailed log file if it exceeds the size limit
- Logs the start of the script execution

#### 2. File Collection
- Identifies user home directories with UID >= 1000
- Scans `.ssh` directories in user homes
- Checks system-wide SSH configuration in `/etc/ssh`

#### 3. File Analysis
- Collects content of key files and configurations
- Checks for empty lines in authorized_keys
- Identifies potentially weak key types (ssh-rsa)

#### 4. JSON Output Generation
- Formats findings into a JSON array
- Writes the JSON result to the active response log

### JSON Output Format

#### Example Response
```json
{
  "timestamp": "2025-07-18T10:30:45.123Z",
  "host": "HOSTNAME",
  "action": "Collect-SSH-Keys.sh",
  "data": [
    {
      "file": "/home/user/.ssh/authorized_keys",
      "content": "ssh-rsa AAAA...",
      "flag": "Contains ssh-rsa key (considered weak)"
    },
    {
      "file": "/etc/ssh/sshd_config",
      "content": "..."
    }
  ],
  "copilot_soar": true
}
```

### Implementation Guidelines

#### Best Practices
- Run the script with appropriate permissions to access SSH files
- Handle sensitive data securely
- Test the script in isolated environments
- Review collected data for compliance requirements

#### Security Considerations
- Ensure minimal required privileges
- Protect collected key material
- Secure the output log files
- Consider data privacy implications

### Troubleshooting

#### Common Issues
1. **Permission Errors**: Ensure read access to SSH directories
2. **Missing Files**: Verify SSH file locations
3. **Log File Issues**: Check write permissions

#### Debugging
Enable verbose logging:
```bash
VERBOSE=1 ./Collect-SSH-Keys.sh
```

### Contributing

When modifying this script:
1. Maintain the secure handling of key material
2. Follow Shell scripting best practices
3. Document any additional functionality
4. Test thoroughly in isolated environments
