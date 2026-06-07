import random

ips = ["192.168.1.50", "185.220.101.5", "45.142.120.9", "10.0.0.15"]
users = ["admin", "root", "user1", "ftpuser", "test"]

print("[*] Generating 10,000 mock security events...")
with open("bulk_auth.log", "w") as f:
    # Generate 10,000 failed attempts to simulate a massive brute-force attack
    for i in range(10000):
        ip = random.choice(ips)
        user = random.choice(users)
        f.write(f"Jun  7 08:00:{i%60:02d} ubuntu-server sshd[1234]: Failed password for invalid user {user} from {ip} port {random.randint(1024, 65535)} ssh2\n")
    
    # Generate a few successful ones
    f.write("Jun  7 08:05:00 ubuntu-server sshd[1235]: Accepted password for root from 10.0.0.15 port 53221 ssh2\n")

print("[+] Successfully created 'bulk_auth.log' with 10,001 events.")