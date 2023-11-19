# Blueside: CTF Log Transfer Utility to Splunk

## Overview
This utility is designed to assist users in transferring logs from a CTF (Capture The Flag) box to a local Splunk instance for analysis. It automates the setup of a Docker-based Splunk instance with SSH access, enabling users to practice blue team skills by analyzing their own activities on the CTF box.

## Features
- Checks for necessary tools (Docker) and required Docker images (Splunk, Ubuntu).
- Automates the setup of a Splunk Docker container with SSH server.
- Generates a temporary user with a secure password for SCP access.
- Provides commands for transferring logs from the CTF box to the Splunk container. (Linux only at this time)
- Configures Splunk to monitor and index transferred logs.

## Prerequisites
- Docker installed on the host machine.
- User added to the `docker` group (to run Docker commands without `sudo`).
  - If you don't want to do this you can opt to run the whole program with `sudo` 
- VPN connection to the CTF environment (typically through `tun0` interface).

## Usage

### Setup
Run the utility script. It will perform the following actions:
1. Check for Docker and required Docker images.
2. Start the Splunk Docker container with SSH access enabled.
3. Create a temporary user for SCP access, generating a random password.

### Log Transfer
Once the setup is complete, follow these steps to gather and transfer logs to the Splunk container:

#### For Linux Hosts:
1. Run the following command on the Linux CTF box to aggregate and transfer logs:
   ```bash
   mkdir /tmp/$(hostname) && find /var/log -type f ! -name "*.[0-9]" -exec cp '{}' /tmp/$(hostname) \; && chmod 644 /tmp/$(hostname)/* && scp -r -P 22022 /tmp/$(hostname) blueside@<tun0_IP>:/tmp/ctflogs && rm -rf /tmp/$(hostname)
   ```
   Replace `<tun0_IP>` with the IP address assigned to your `tun0` interface.

#### For Windows Hosts:
Windows log transfer can vary based on your shell access. Start with log aggregation:

1. Run the following PowerShell command on the Windows CTF box to consolidate logs:
   ```powershell
   $hostName = [System.Net.Dns]::GetHostName(); $targetPath = "C:\Users\Administrator\Documents\$hostName"; New-Item -ItemType Directory -Force -Path $targetPath; Get-EventLog -LogName System | Export-Csv -Path "$targetPath\system_logs.csv"; Get-EventLog -LogName Application | Export-Csv -Path "$targetPath\application_logs.csv"; Get-EventLog -LogName Security | Export-Csv -Path "$targetPath\security_logs.csv"; If (Test-Path C:\inetpub) { New-Item -ItemType Directory -Force -Path "$targetPath\inetpub"; Copy-Item -Path C:\inetpub\logs\LogFiles\* -Destination "$targetPath\inetpub" }
   ```

2. Transfer the logs from the Windows host to the Splunk container:
   - If you have a meterpreter or evil-winrm session, download the logs to your local machine.
   - Then, use SCP (or `docker cp`) from your local host to transfer the logs to `/tmp/ctflogs` in the Splunk container.

### Notes and Troubleshooting
- The SCP command requires SSH access to the Splunk container. If SCP doesn't work, especially from Windows hosts, consider alternative file transfer methods.
- Ensure you have the necessary permissions and network access to perform these operations.
- When sending logs to the docker container as user blueside remeber that splunk needs to be able to read them so set perms to 644 for example

Remember: These commands may need to be adjusted based on the specific CTF environment and the available tools or access levels.


### Log Analysis in Splunk
After transferring the logs, access the Splunk Web UI on the host machine to analyze the logs:
- URL: `http://localhost:8999`
- Default login credentials are admin:bluesidepassword
- logs should be in index=main by default (Docker Splunk is set to monitor /tmp/ctflogs when its built)

## Important Notes
- This utility is intended for educational purposes in ethical and authorized contexts.
- Always ensure that you have the proper authorization before accessing and transferring logs from any system.
- Follow the rules and guidelines of the respective CTF platform.

## Contributing
Contributions to improve this utility are welcome.  

## License
MIT

## Acknowledgements
Special thanks to Byte for her support throughout the development of this project.
