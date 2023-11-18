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
Once the setup is complete, follow these steps:
1. Obtain an interactive root shell on the CTF box.
2. Run the provided SCP command to transfer desired logs to the Splunk container.
   Example SCP command:
   ```bash
   mkdir /tmp/$(hostname) && find /var/log -type f ! -name "*.[0-9]" -exec cp '{}' /tmp/$(hostname) \; && chmod 644 /tmp/$(hostname)/* && scp -r -P 22022 /tmp/$(hostname) blueside@tun0:/tmp/ctflogs && rm -rf /tmp/$(hostname)
   ```
   Replace `<tun0_IP>` with the IP address assigned to your `tun0` interface.

### Log Analysis in Splunk
After transferring the logs, access the Splunk Web UI on the host machine to analyze the logs:
- URL: `http://localhost:8999`
- Default login credentials are admin:bluesidepassword
- logs should be in index=main by default

## Important Notes
- This utility is intended for educational purposes in ethical and authorized contexts.
- Always ensure that you have the proper authorization before accessing and transferring logs from any system.
- Follow the rules and guidelines of the respective CTF platform.

## Contributing
Contributions to improve this utility are welcome.  

## License
MIT

## ToDo
Right now its set for getting logs from Linux and its grabbing everything.   
I will be working on a more dynamic scp command based on the target host.
