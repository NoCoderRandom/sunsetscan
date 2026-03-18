# NetWatch Usage Examples

## Interactive Mode (Recommended for Beginners)

Launch the interactive mode for guided network scanning:
```bash
python netwatch.py --interactive
# or
python netwatch.py -i
```

### Interactive Mode Features
- **Flexible target input**: 192.168.1.*, 192.168.1.1-100, 192.168.1.0/24
- **Discovery first**: Quickly find active hosts, then choose actions
- **Per-host operations**: Select specific hosts for deep scanning
- **Bulk operations**: Run actions on all discovered hosts
- **Settings on-the-fly**: Enable/disable features as needed

### Interactive Mode Workflow
```
1. Enter target range (e.g., 192.168.1.*)
2. Discovery scan finds active hosts
3. Choose action from menu:
   - Scan specific hosts in detail
   - Check default credentials
   - Grab banners/fingerprint devices
   - Check EOL status
   - Export results
4. View results and repeat as needed
```

## Command Line Mode

### Quick Examples

```bash
# Interactive mode (easiest)
python netwatch.py -i

# Scan entire network with all features
python netwatch.py --target 192.168.1.0/24 --profile QUICK --nse

# Scan specific host with full details
python netwatch.py --target 192.168.1.115 --profile FULL --nse

# Check for default passwords (your devices only!)
python netwatch.py --target 192.168.1.115 --check-defaults

# Quick ping sweep to find hosts
python netwatch.py --target 192.168.1.0/24 --profile PING
```

## Target Specification

### Supported Formats
```
192.168.1.0/24          # CIDR notation (256 addresses)
192.168.1.*             # Wildcard (same as /24)
192.168.1.*            # Any third octet
192.168.1.1-100         # Range in last octet
192.168.1.1,5,10        # Specific IPs
192.168.1.1-50,100-150  # Multiple ranges
router.local            # Hostname
```

## Scan Profiles

| Profile | Description | Time for /24 | Use Case |
|---------|-------------|--------------|----------|
| **PING** | Host discovery only | ~30 sec | Find active hosts |
| **QUICK** | Top 100 ports | ~2-3 min | Fast assessment |
| **FULL** | All ports + OS detection | ~10-15 min | Deep analysis |
| **STEALTH** | Slow SYN scan | ~20-30 min | Evade detection |

## Feature Flags

| Flag | Description | Impact |
|------|-------------|--------|
| `--nse` | Enable NSE scripts | Better device ID, +3-5 min |
| `--check-defaults` | Test default passwords | Security check, +2-3 min |
| `--verbose` | Debug logging | More output |
| `--no-color` | Plain text output | Terminal compatibility |

## Time Estimates

| Scan Type | /24 Network | Single Host |
|-----------|-------------|-------------|
| PING | 30 sec | 2 sec |
| QUICK | 2-3 min | 10 sec |
| QUICK + NSE | 5-8 min | 30 sec |
| FULL | 10-15 min | 1-2 min |
| FULL + NSE + Auth | 20-30 min | 2-3 min |

## Best Practices

1. **Start with Interactive Mode**
   ```bash
   python netwatch.py -i
   ```

2. **Or use PING first to find hosts**
   ```bash
   python netwatch.py --target 192.168.1.0/24 --profile PING
   ```

3. **Then scan specific hosts**
   ```bash
   python netwatch.py --target 192.168.1.115 --profile FULL --nse
   ```

4. **Test credentials only on your devices**
   ```bash
   python netwatch.py --target 192.168.1.115 --check-defaults
   ```

## Example Output

```
+------------------------------------------------------------------------------+
| IP Address     | Hostname       | Port | Service           | Version         |
|----------------+----------------+------+-------------------+-----------------+
| 192.168.1.1    | router         |   80 | TP-Link           | -               |
| 192.168.1.10   | desktop        |  445 | microsoft-ds      | Windows 10      |
| 192.168.1.115  | -              |   80 | TP-Link RE305     | FW:1.0.4        |
| 192.168.1.20   | -              |   22 | OpenSSH           | 8.2p1           |
+------------------------------------------------------------------------------+
```

## Security Warnings

- **Only scan networks you own or have permission to scan**
- **Credential testing (--check-defaults) should only be used on your own devices**
- **Stealth scans may still be detected by IDS/IPS systems**
