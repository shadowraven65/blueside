package main

import (
    "crypto/rand"
    "math/big"
    "bufio"
    "fmt"
    "net"
    "os"
    "os/exec"
    "strings"
	  "bytes"
)


func main() {
	    // Check for Docker installation
    if !isDockerInstalled() {
        fmt.Println("Docker is not installed. Docker is required to run a local Splunk instance.")
        return
    }

    if !canRunDockerWithoutSudo() {
        fmt.Println("Unable to run Docker commands without sudo. Please ensure you are in the 'docker' group or run this program with elevated privileges.")
        return
    }
    requiredImages := []string{"splunk/splunk"}
    // Check for needed docker images
    for _, imageName := range requiredImages {
        if !isDockerImagePresent(imageName) {
            fmt.Printf("%s Docker image is not found. Would you like to download it? (yes/no): ", imageName)
            reader := bufio.NewReader(os.Stdin)
            response, err := reader.ReadString('\n')
            if err != nil {
                fmt.Println("Error reading input:", err)
                return
            }
            if strings.TrimSpace(response) == "yes" {
                downloadDockerImage(imageName)
            } else {
                fmt.Printf("Operation aborted. %s Docker image is required to proceed.\n", imageName)
                return
            }
        }
    }
    // Generate Random Password for Splunk SSH user
    password, err := generateRandomPassword(12)
    if err != nil {
        fmt.Println("Failed to generate a random password:", err)
        os.Exit(1)
    }
    // Get the IP address of tun0
    tun0IP, err := getInterfaceIP("tun0")
    if err != nil {
        fmt.Println("Error retrieving IP address of tun0:", err)
        os.Exit(1) // Exit if tun0 IP not found
    }

    displayIntro(tun0IP)

    // Read the user's response and proceed accordingly
    reader := bufio.NewReader(os.Stdin)
    response, err := reader.ReadString('\n')
    if err != nil || strings.TrimSpace(response) != "yes" {
        fmt.Println("Operation aborted by the user.")
        return
    }
    sshPortMapping := fmt.Sprintf("%s:22022:22", tun0IP)
    cmd := exec.Command("docker", "run", "--rm", "-d", "-p", "127.0.0.1:8999:8000", "-p", sshPortMapping, "-e", "SPLUNK_START_ARGS=--accept-license", "-e", "SPLUNK_PASSWORD=bluesidepassword", "--name", "bluesidesplunk", "splunk/splunk:latest")
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    if err := cmd.Run(); err != nil {
        fmt.Println("Failed to start Splunk Docker container:", err)
        return
    }
    commands := []string{
        "microdnf update && microdnf install -y openssh openssh-server openssh-clients",
        "ssh-keygen -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''",
        "ssh-keygen -t ecdsa -b 521 -f /etc/ssh/ssh_host_ecdsa_key -N ''",
        "ssh-keygen -t rsa -b 4096 -f /etc/ssh/ssh_host_rsa_key -N ''",
        "/usr/sbin/sshd -D &",
    }
    
    for _, cmdStr := range commands {
        cmd := exec.Command("docker", "exec", "--user", "root", "bluesidesplunk", "/bin/bash", "-c", cmdStr)
        cmd.Stdout = os.Stdout
        cmd.Stderr = os.Stderr
        if err := cmd.Run(); err != nil {
            fmt.Printf("Failed to execute command '%s': %v\n", cmdStr, err)
            return
        }
    }

    // Create the user and set the password
    addUserCmd := fmt.Sprintf("useradd -G sudo -m blueside && echo 'blueside:%s' | chpasswd", password)
    cmd = exec.Command("docker", "exec", "--user", "root", "bluesidesplunk", "/bin/bash", "-c", addUserCmd)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    if err := cmd.Run(); err != nil {
        fmt.Println("Failed to add user 'blueside' for SSH:", err)
        return
    }

    cmd = exec.Command("docker", "exec", "--user", "root", "bluesidesplunk", "/bin/bash", "-c", "mkdir -p /tmp/ctflogs && chown blueside:blueside /tmp/ctflogs")
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    if err := cmd.Run(); err != nil {
        fmt.Println("Failed to create directory for logs:", err)
        return
    }
    
    monitorCmd := fmt.Sprintln("/opt/splunk/bin/splunk add monitor /tmp/ctflogs -auth admin:bluesidepassword")
    cmd = exec.Command("docker", "exec", "--user", "root", "bluesidesplunk", "/bin/bash", "-c", monitorCmd)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    if err := cmd.Run(); err != nil {
        fmt.Println("Failed to configure Splunk to monitor directory:", err)
        return
    }
    scpCommand := fmt.Sprintf("mkdir /tmp/$(hostname) && find /var/log -type f ! -name \"*.[0-9]\" -exec cp '{}' /tmp/$(hostname) \\; && chmod 644 /tmp/$(hostname)/* && scp -r -P 22022 /tmp/$(hostname) blueside@%s:/tmp/ctflogs && rm -rf /tmp/$(hostname)", tun0IP)

    displayComplete(password, scpCommand)

}

func getInterfaceIP(interfaceName string) (string, error) {
    iface, err := net.InterfaceByName(interfaceName)
    if err != nil {
        return "", err
    }

    addrs, err := iface.Addrs()
    if err != nil {
        return "", err
    }

    for _, addr := range addrs {
        var ip net.IP
        switch v := addr.(type) {
        case *net.IPNet:
            ip = v.IP
        case *net.IPAddr:
            ip = v.IP
        }

        if ip != nil && ip.To4() != nil { // To4 converts IPv4 address in IPv4-mapped IPv6 address to 4-byte representation
            return ip.String(), nil
        }
    }

    return "", fmt.Errorf("no IPv4 address found for interface %s", interfaceName)
}


func canRunDockerWithoutSudo() bool {
    cmd := exec.Command("docker", "info")
    err := cmd.Run()
    return err == nil
}

func isDockerInstalled() bool {
    _, err := exec.LookPath("docker")
    return err == nil
}

func isDockerImagePresent(imageName string) bool {
    cmd := exec.Command("docker", "images", "--format", "{{.Repository}}:{{.Tag}}")
    var out bytes.Buffer
    cmd.Stdout = &out
    err := cmd.Run()
    if err != nil {
        fmt.Println("Failed to execute docker command:", err)
        return false
    }

    images := strings.Split(out.String(), "\n")
    for _, image := range images {
        if strings.Contains(image, imageName) {
            return true
        }
    }
    return false
}

func generateRandomPassword(length int) (string, error) {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    var password []byte
    for i := 0; i < length; i++ {
        charIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
        if err != nil {
            return "", err
        }
        password = append(password, charset[charIndex.Int64()])
    }
    return string(password), nil
}

func downloadDockerImage(imageName string) {
    fmt.Printf("Downloading the %s Docker image. This might take a while depending on your internet connection...\n", imageName)

    cmd := exec.Command("docker", "pull", imageName)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr

    err := cmd.Run()
    if err != nil {
        fmt.Printf("Failed to download %s Docker image: %v\n", imageName, err)
        return
    }

    fmt.Printf("%s Docker image downloaded successfully.\n", imageName)
}


func displayIntro(tun0IP string) {
    fmt.Println("Welcome to the Blueside CTF Log Transfer Utility")
    fmt.Println("-------------------------------------------------")
    fmt.Println("This utility will assist you in transferring logs from a CTF box to a local Splunk instance for analysis.")
    fmt.Println("\nProcess Overview:")
    fmt.Println("1. A Splunk Docker container will be started with SSH access enabled.")
    fmt.Println("2. You will need an interactive root shell on the CTF box for the next steps.")
    fmt.Println("3. Once you confirm you have root access, this utility will provide you with an SCP command.")
    fmt.Println("4. Use the provided SCP command to transfer the logs from the CTF box to the Splunk container.")
    fmt.Println("5. Analyze the logs in Splunk to practice your blue team skills.")
    fmt.Println("-------------------------------------------------")
    fmt.Printf("Note: Ensure you are connected to the CTF environment (VPN) and have the IP address %s assigned to your tun0 interface.\n", tun0IP)
    fmt.Println("-------------------------------------------------")
    fmt.Println("Are you ready to proceed? (yes/no):")
}
func displayComplete(password string, scpCommand string) {
    fmt.Println("Splunk Container started with SSH enabled")
    fmt.Println("-------------------------------------------------")
    fmt.Println("The Splunk instance is up and running and will accept SCP file transfers to load logs into Splunk")
    fmt.Println("\nNotes:")
    fmt.Println("1. Go to 127.0.0.1:8999 and login with admin:bluesidepassword to access splunk")
    fmt.Println("2. Run the following command on the target host to grab logs to send to Splunk.")
    fmt.Println("=============== SCP COMMAND ===============")
    fmt.Println(scpCommand)
    fmt.Println("===========================================")
    fmt.Printf("4. Password for blueside user is: %s\n", password)
    fmt.Println("5. Logs should show up automatically in index=main.")
    fmt.Println("-------------------------------------------------")
    fmt.Println("Note: When you are done you can just 'docker stop' the splunk container and it will nuke itself" )
    fmt.Println("-------------------------------------------------")
    fmt.Println("Have fun Hunting!!")
}
