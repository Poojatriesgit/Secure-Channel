"""
Enhanced CLI Banking System with Digital Signatures
Login, Register, Send Encrypted Messages to Bank
With Network Latency, Location Tracking, Hash Computation, and Digital Signatures
"""

import os
import sys
import time
import json
import hashlib
import getpass
import requests
import subprocess
import platform
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
import base64
import sqlite3

# Storage configuration
STORAGE_PATH = r"C:\Users\pooja\OneDrive\Desktop\HSBC\hybrid-banking-hackathon\data"
DATABASE_PATH = os.path.join(STORAGE_PATH, "banking_system.db")
MESSAGES_PATH = os.path.join(STORAGE_PATH, "user_messages")

class EnhancedBankingCLI:
    def __init__(self):
        self.current_user = None
        self.setup_storage()
    
    def setup_storage(self):
        """Setup storage directories and database with enhanced schema including digital signatures"""
        try:
            # Create directories
            os.makedirs(STORAGE_PATH, exist_ok=True)
            os.makedirs(MESSAGES_PATH, exist_ok=True)
            
            # Setup database
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            # Enhanced Users table with digital signature keys
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE,
                password_hash TEXT,
                full_name TEXT,
                registration_date TEXT,
                encryption_key TEXT,
                private_key TEXT,
                public_key TEXT,
                registration_location TEXT,
                registration_latency REAL,
                registration_hash TEXT
            )
            ''')
            
            # Enhanced Messages table with digital signatures
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                message_id TEXT,
                encrypted_file_path TEXT,
                timestamp TEXT,
                network_latency REAL,
                location_data TEXT,
                message_hash TEXT,
                metadata_hash TEXT,
                digital_signature TEXT,
                signature_verified BOOLEAN,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
            ''')
            
            conn.commit()
            conn.close()
            
            print(f"✅ System initialized successfully at: {STORAGE_PATH}")
            
        except Exception as e:
            print(f"❌ System initialization failed: {e}")
            exit(1)

    def clear_screen(self):
        """Clear the console screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_header(self):
        """Print application header"""
        self.clear_screen()
        print("="*70)
        print("🏦 SECURE BANKING SYSTEM")
        print("="*70)
        print("🔐 Encrypted | 🔏 Digital Signatures | 📍 Location Tracking")
        print("="*70)

    def generate_rsa_keypair(self):
        """Generate RSA key pair for digital signatures"""
        try:
            print("🔐 Generating security keys...")
            
            # Generate private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            
            # Get public key
            public_key = private_key.public_key()
            
            # Serialize private key
            private_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Serialize public key
            public_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            return private_pem, public_pem
            
        except Exception as e:
            print(f"❌ Key generation failed: {e}")
            return None, None

    def create_digital_signature(self, message_data, private_key_pem):
        """Create digital signature for message"""
        try:
            # Load private key
            private_key = serialization.load_pem_private_key(
                private_key_pem,
                password=None,
            )
            
            # Create message hash for signing
            message_json = json.dumps(message_data, sort_keys=True)
            message_bytes = message_json.encode('utf-8')
            
            # Create digital signature
            signature = private_key.sign(
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Encode signature as base64 for storage
            signature_b64 = base64.b64encode(signature).decode('utf-8')
            
            return signature_b64
            
        except Exception as e:
            print(f"❌ Digital signature creation failed: {e}")
            return None

    def verify_digital_signature(self, message_data, signature_b64, public_key_pem):
        """Verify digital signature"""
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(public_key_pem)
            
            # Decode signature
            signature = base64.b64decode(signature_b64.encode('utf-8'))
            
            # Create message hash for verification
            message_json = json.dumps(message_data, sort_keys=True)
            message_bytes = message_json.encode('utf-8')
            
            # Verify signature
            public_key.verify(
                signature,
                message_bytes,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except InvalidSignature:
            return False
        except Exception as e:
            print(f"❌ Signature verification error: {e}")
            return False

    def get_network_latency(self, host="8.8.8.8", count=3):
        """Check network latency by pinging a host"""
        try:
            print("🌐 Checking network connection...")
            
            # Determine ping command based on OS
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", str(count), host]
            else:
                cmd = ["ping", "-c", str(count), host]
            
            # Execute ping command
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                # Parse ping output to extract latency
                output_lines = result.stdout.split('\n')
                latencies = []
                
                for line in output_lines:
                    if "time=" in line.lower():
                        # Extract time value
                        try:
                            time_part = line.split("time=")[1].split()[0]
                            latency = float(time_part.replace("ms", ""))
                            latencies.append(latency)
                        except:
                            continue
                
                if latencies:
                    avg_latency = sum(latencies) / len(latencies)
                    return round(avg_latency, 2)
            
            # Fallback method using requests
            start_time = time.time()
            response = requests.get("https://www.google.com", timeout=5)
            latency = (time.time() - start_time) * 1000
            return round(latency, 2)
            
        except Exception as e:
            return 0.0
    
    def get_location_data(self):
        """Get location information based on IP address"""
        try:
            print("📍 Getting location information...")
            
            # Try multiple location services
            location_services = [
                "http://ip-api.com/json/",
                "https://ipapi.co/json/",
                "https://api.ipify.org?format=json"
            ]
            
            for service_url in location_services:
                try:
                    response = requests.get(service_url, timeout=5)
                    if response.status_code == 200:
                        location_data = response.json()
                        
                        # Standardize location format
                        if "ip-api.com" in service_url:
                            standardized_location = {
                                "ip": location_data.get("query", "Unknown"),
                                "country": location_data.get("country", "Unknown"),
                                "region": location_data.get("regionName", "Unknown"),
                                "city": location_data.get("city", "Unknown"),
                                "isp": location_data.get("isp", "Unknown"),
                                "timezone": location_data.get("timezone", "Unknown"),
                                "latitude": location_data.get("lat", 0),
                                "longitude": location_data.get("lon", 0)
                            }
                        elif "ipapi.co" in service_url:
                            standardized_location = {
                                "ip": location_data.get("ip", "Unknown"),
                                "country": location_data.get("country_name", "Unknown"),
                                "region": location_data.get("region", "Unknown"),
                                "city": location_data.get("city", "Unknown"),
                                "isp": location_data.get("org", "Unknown"),
                                "timezone": location_data.get("timezone", "Unknown"),
                                "latitude": location_data.get("latitude", 0),
                                "longitude": location_data.get("longitude", 0)
                            }
                        else:
                            # Basic IP-only service
                            ip_address = location_data.get("ip", "Unknown")
                            standardized_location = {
                                "ip": ip_address,
                                "country": "Unknown",
                                "region": "Unknown",
                                "city": "Unknown",
                                "isp": "Unknown",
                                "timezone": "Unknown",
                                "latitude": 0,
                                "longitude": 0
                            }
                        
                        return standardized_location
                        
                except Exception as e:
                    continue
            
            # Fallback location data
            return {
                "ip": "Unknown",
                "country": "Unknown",
                "region": "Unknown", 
                "city": "Unknown",
                "isp": "Unknown",
                "timezone": "Unknown",
                "latitude": 0,
                "longitude": 0
            }
            
        except Exception as e:
            return {"error": str(e)}
    
    def compute_hash(self, data):
        """Compute SHA-256 hash of data"""
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)
        elif not isinstance(data, str):
            data = str(data)
        
        return hashlib.sha256(data.encode()).hexdigest()
    
    def generate_user_id(self, username):
        """Generate unique user ID"""
        timestamp = str(int(time.time()))
        combined = f"{username}_{timestamp}"
        return f"USER_{hashlib.md5(combined.encode()).hexdigest()[:8].upper()}"
    
    def hash_password(self, password):
        """Hash password with SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def generate_encryption_key(self):
        """Generate Fernet encryption key"""
        return Fernet.generate_key()
    
    def encrypt_and_save_message(self, user_id, message_data, network_latency, location_data):
        """Encrypt message and save with enhanced metadata and digital signatures"""
        try:        
            # Get user's encryption key and private key
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT encryption_key, private_key FROM users WHERE user_id = ?", (user_id,))
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                return None, "User not found", None, None, None
            
            # Decrypt the stored encryption key and get private key
            user_key = base64.b64decode(result[0].encode())
            private_key_pem = base64.b64decode(result[1].encode())
            fernet = Fernet(user_key)
            
            # Create digital signature BEFORE encryption
            print("🔏 Creating digital signature...")
            digital_signature = self.create_digital_signature(message_data, private_key_pem)
            
            if not digital_signature:
                return None, "Digital signature creation failed", None, None, None
            
            # Create enhanced message data with metadata and signature
            enhanced_message_data = {
                **message_data,
                "network_latency": network_latency,
                "location_data": location_data,
                "enhanced_timestamp": datetime.now().isoformat(),
                "digital_signature": digital_signature,
                "system_info": {
                    "platform": platform.system(),
                    "python_version": platform.python_version()
                }
            }
            
            # Compute hashes
            message_hash = self.compute_hash(message_data)
            metadata_hash = self.compute_hash({
                "network_latency": network_latency,
                "location_data": location_data,
                "timestamp": enhanced_message_data["enhanced_timestamp"]
            })
            
            enhanced_message_data["message_hash"] = message_hash
            enhanced_message_data["metadata_hash"] = metadata_hash
            
            # Encrypt enhanced message data (including signature)
            message_json = json.dumps(enhanced_message_data, indent=2)
            encrypted_message = fernet.encrypt(message_json.encode())
            
            # Create user-specific message directory
            user_message_dir = os.path.join(MESSAGES_PATH, user_id)
            os.makedirs(user_message_dir, exist_ok=True)
            
            # Generate filename
            timestamp = int(time.time())
            message_id = f"MSG_{timestamp}_{hash(message_data['content']) % 10000:04d}"
            filename = f"{message_id}.enc"
            file_path = os.path.join(user_message_dir, filename)
            
            # Save encrypted message
            with open(file_path, 'wb') as f:
                f.write(encrypted_message)
            
            return file_path, message_id, message_hash, metadata_hash, digital_signature
            
        except Exception as e:
            return None, str(e), None, None, None
    
    def register_user(self):
        """Register new user with enhanced tracking and digital signatures"""
        self.print_header()
        print("\n👤 NEW USER REGISTRATION")
        print("-" * 50)
        
        # Get user input
        username = input("👤 Username: ").strip()
        if not username:
            print("❌ Username cannot be empty!")
            input("\nPress Enter to continue...")
            return
        
        password = getpass.getpass("🔒 Password: ")
        if not password:
            print("❌ Password cannot be empty!")
            input("\nPress Enter to continue...")
            return
        
        full_name = input("📝 Full Name: ").strip()
        if not full_name:
            print("❌ Full name cannot be empty!")
            input("\nPress Enter to continue...")
            return
        
        try:
            # Check if username already exists
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                print("❌ Username already exists!")
                input("\nPress Enter to continue...")
                conn.close()
                return
            
            print("\n🔐 Setting up your secure account...")
            
            # Generate user ID, encryption key, and RSA key pair
            user_id = self.generate_user_id(username)
            encryption_key = self.generate_encryption_key()
            private_key_pem, public_key_pem = self.generate_rsa_keypair()
            
            if not private_key_pem or not public_key_pem:
                print("❌ Failed to generate security keys!")
                input("\nPress Enter to continue...")
                conn.close()
                return
            
            # Get network and location data
            network_latency = self.get_network_latency()
            location_data = self.get_location_data()
            
            # Compute registration hash
            registration_data = {
                "user_id": user_id,
                "username": username,
                "full_name": full_name,
                "registration_date": datetime.now().isoformat(),
                "network_latency": network_latency,
                "location_data": location_data
            }
            registration_hash = self.compute_hash(registration_data)
            
            # Insert user into database
            cursor.execute('''
            INSERT INTO users (user_id, username, password_hash, full_name, 
                             registration_date, encryption_key, private_key, public_key,
                             registration_location, registration_latency, registration_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (user_id, username, self.hash_password(password), full_name,
                  datetime.now().isoformat(), 
                  base64.b64encode(encryption_key).decode(),
                  base64.b64encode(private_key_pem).decode(),
                  base64.b64encode(public_key_pem).decode(),
                  json.dumps(location_data), network_latency, registration_hash))
            
            conn.commit()
            conn.close()
            
            print("\n✅ Registration successful!")
            print(f"🆔 Your User ID: {user_id}")
            print(f"🌍 Registered from: {location_data.get('city', 'Unknown')}, {location_data.get('country', 'Unknown')}")
            print("\n🔐 Your account is secured with:")
            print("   • AES Encryption")
            print("   • RSA Digital Signatures")
            print("   • Location Tracking")
            print("   • Network Analysis")
            
            input("\nPress Enter to continue...")
            
        except Exception as e:
            print(f"❌ Registration failed: {e}")
            input("\nPress Enter to continue...")
    
    def login_user(self):
        """User login with enhanced tracking"""
        self.print_header()
        print("\n🔐 USER LOGIN")
        print("-" * 50)
        
        username = input("👤 Username: ").strip()
        password = getpass.getpass("🔒 Password: ")
        
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT user_id, username, full_name, registration_location, registration_latency,
                   public_key, private_key
            FROM users 
            WHERE username = ? AND password_hash = ?
            ''', (username, self.hash_password(password)))
            
            user = cursor.fetchone()
            conn.close()
            
            if user:
                self.current_user = {
                    "user_id": user[0],
                    "username": user[1],
                    "full_name": user[2],
                    "registration_location": json.loads(user[3]) if user[3] else {},
                    "registration_latency": user[4],
                    "public_key": base64.b64decode(user[5].encode()) if user[5] else None,
                    "private_key": base64.b64decode(user[6].encode()) if user[6] else None
                }
                
                print(f"\n✅ Login successful!")
                print(f"👋 Welcome back, {self.current_user['full_name']}")
                
                # Show user menu
                self.show_user_menu()
                
            else:
                print("\n❌ Invalid username or password!")
                input("Press Enter to continue...")
                
        except Exception as e:
            print(f"❌ Login failed: {e}")
            input("Press Enter to continue...")
    
    def show_user_menu(self):
        """Show user menu after successful login"""
        while self.current_user:
            self.print_header()
            print(f"\n👋 Welcome, {self.current_user['full_name']}")
            print(f"🆔 User ID: {self.current_user['user_id']}")
            print("-" * 50)
            print("\n📋 BANKING MENU:")
            print("1. 💬 Send Message to Bank")
            print("2. 🚪 Logout")
            
            choice = input("\n➤ Select option (1-2): ").strip()
            
            if choice == "1":
                self.send_message_to_bank()
            elif choice == "2":
                self.view_my_messages()
            elif choice == "3":
                self.verify_specific_message()
            elif choice == "4":
                print(f"\n👋 Goodbye, {self.current_user['full_name']}!")
                self.current_user = None
                input("Press Enter to continue...")
                break
            else:
                print("❌ Invalid option! Please select 1-4.")
                input("Press Enter to continue...")
    
    def send_message_to_bank(self):
        """Send encrypted message with digital signatures to bank"""
        self.print_header()
        print(f"\n💬 SEND MESSAGE TO BANK")
        print(f"👤 From: {self.current_user['full_name']}")
        print("-" * 50)
        
        print("\n📝 Enter your message (press Enter twice when finished):")
        print("-" * 30)
        
        lines = []
        empty_lines = 0
        
        while True:
            line = input()
            if line == "":
                empty_lines += 1
                if empty_lines >= 2 or (lines and empty_lines >= 1):
                    break
            else:
                empty_lines = 0
                lines.append(line)
        
        message_content = "\n".join(lines).strip()
        
        if not message_content:
            print("❌ Message cannot be empty!")
            input("\nPress Enter to continue...")
            return
        
        try:
            print("\n🔐 Processing your message...")
            start_time = time.time()
            
            # Get current network and location data
            network_latency = self.get_network_latency()
            location_data = self.get_location_data()
            
            print("🔒 Encrypting and signing message...")
            
            # Create message data
            message_data = {
                "sender_user_id": self.current_user["user_id"],
                "sender_name": self.current_user["full_name"],
                "recipient": "BANK",
                "content": message_content,
                "timestamp": datetime.now().isoformat(),
                "message_type": "customer_to_bank"
            }
            
            # Encrypt and save message with digital signature
            file_path, message_id, message_hash, metadata_hash, signature = self.encrypt_and_save_message(
                self.current_user["user_id"], 
                message_data,
                network_latency,
                location_data
            )
            
            if file_path and signature:
                # Store message reference in database
                conn = sqlite3.connect(DATABASE_PATH)
                cursor = conn.cursor()
                cursor.execute('''
                INSERT INTO messages (user_id, message_id, encrypted_file_path, timestamp,
                                    network_latency, location_data, message_hash, metadata_hash,
                                    digital_signature, signature_verified)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (self.current_user["user_id"], message_id, 
                      os.path.basename(file_path), datetime.now().isoformat(),
                      network_latency, json.dumps(location_data), message_hash, metadata_hash,
                      signature, True))
                conn.commit()
                conn.close()
                
                process_time = time.time() - start_time
                
                print(f"\n✅ Message sent successfully!")
                print(f"📧 Message ID: {message_id}")
                print(f"📡 Network Latency: {network_latency}ms")
                print(f"🌍 Location: {location_data.get('city', 'Unknown')}, {location_data.get('country', 'Unknown')}")
                print(f"⚡ Process Time: {process_time:.2f}s")
                print(f"🔐 Security: Encrypted + Digitally Signed")
                
            else:
                print("❌ Failed to send message!")
                
        except Exception as e:
            print(f"❌ Message sending failed: {e}")
        
        input("\nPress Enter to continue...")

    def view_my_messages(self):
        """View user's encrypted messages"""
        self.print_header()
        print(f"\n📨 YOUR MESSAGES")
        print(f"👤 User: {self.current_user['full_name']}")
        print("-" * 50)
        
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT message_id, timestamp, network_latency, location_data, digital_signature
            FROM messages 
            WHERE user_id = ? 
            ORDER BY timestamp DESC
            ''', (self.current_user["user_id"],))
            
            messages = cursor.fetchall()
            conn.close()
            
            if messages:
                print(f"\n📊 Found {len(messages)} messages:")
                print("-" * 60)
                
                for i, msg in enumerate(messages, 1):
                    message_id, timestamp, latency, location_json, signature = msg
                    formatted_time = datetime.fromisoformat(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                    
                    try:
                        location = json.loads(location_json) if location_json else {}
                    except:
                        location = {}
                    
                    print(f"{i}. 📧 {message_id}")
                    print(f"   🕐 {formatted_time}")
                    print(f"   📡 {latency}ms | 🌍 {location.get('city', 'Unknown')}")
                    print(f"   🔏 {'✅ Signed' if signature else '❌ No Signature'}")
                    print("-" * 60)
                
            else:
                print("\n📝 No messages found.")
                
        except Exception as e:
            print(f"❌ Error retrieving messages: {e}")
            
        input("\nPress Enter to continue...")

    def verify_specific_message(self):
        """Verify digital signature of a specific message"""
        self.print_header()
        print(f"\n🔍 VERIFY MESSAGE SIGNATURE")
        print(f"👤 User: {self.current_user['full_name']}")
        print("-" * 50)
        
        try:
            # Get user's messages
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT message_id, digital_signature, encrypted_file_path
            FROM messages 
            WHERE user_id = ? 
            ORDER BY timestamp DESC
            ''', (self.current_user["user_id"],))
            
            messages = cursor.fetchall()
            conn.close()
            
            if not messages:
                print("\n📝 No messages found.")
                input("\nPress Enter to continue...")
                return
            
            print("\n📋 Available messages:")
            for i, (msg_id, _, _) in enumerate(messages, 1):
                print(f"{i}. {msg_id}")
            
            choice = input("\n➤ Select message number to verify: ").strip()
            
            try:
                msg_index = int(choice) - 1
                if 0 <= msg_index < len(messages):
                    message_id, signature, file_path = messages[msg_index]
                    
                    if not signature:
                        print("\n❌ No digital signature found for this message!")
                        input("\nPress Enter to continue...")
                        return
                    
                    print(f"\n🔍 Verifying signature for {message_id}...")
                    
                    # Load and decrypt the message to get original data
                    full_file_path = os.path.join(MESSAGES_PATH, self.current_user["user_id"], file_path)
                    
                    if not os.path.exists(full_file_path):
                        print("❌ Message file not found!")
                        input("\nPress Enter to continue...")
                        return
                    
                    # Get user's encryption key
                    conn = sqlite3.connect(DATABASE_PATH)
                    cursor = conn.cursor()
                    cursor.execute("SELECT encryption_key FROM users WHERE user_id = ?", (self.current_user["user_id"],))
                    result = cursor.fetchone()
                    conn.close()
                    
                    if not result:
                        print("❌ User encryption key not found!")
                        input("\nPress Enter to continue...")
                        return
                    
                    # Decrypt message
                    user_key = base64.b64decode(result[0].encode())
                    fernet = Fernet(user_key)
                    
                    with open(full_file_path, 'rb') as f:
                        encrypted_data = f.read()
                    
                    decrypted_data = fernet.decrypt(encrypted_data)
                    message_content = json.loads(decrypted_data.decode())
                    
                    # Extract original message data for verification
                    original_message_data = {
                        "sender_user_id": message_content.get("sender_user_id"),
                        "sender_name": message_content.get("sender_name"),
                        "recipient": message_content.get("recipient"),
                        "content": message_content.get("content"),
                        "timestamp": message_content.get("timestamp"),
                        "message_type": message_content.get("message_type")
                    }
                    
                    # Verify signature
                    verification_result = self.verify_digital_signature(
                        original_message_data,
                        signature,
                        self.current_user["public_key"]
                    )
                    
                    if verification_result:
                        print(f"\n✅ Signature verification SUCCESSFUL!")
                        print("🔒 Message is authentic and has not been tampered with.")
                    else:
                        print(f"\n❌ Signature verification FAILED!")
                        print("⚠️  Message may have been tampered with or is not authentic!")
                    
                else:
                    print("❌ Invalid message selection!")
                    
            except ValueError:
                print("❌ Please enter a valid number!")
                
        except Exception as e:
            print(f"❌ Signature verification failed: {e}")
            
        input("\nPress Enter to continue...")
    
    def main_menu(self):
        """Main application menu"""
        while True:
            self.print_header()
            print("\n🏠 MAIN MENU")
            print("-" * 30)
            print("1. 🔐 Login")
            print("2. 👤 New User")
            print("3. 🚪 Exit")
            
            choice = input("\n➤ Select option (1-3): ").strip()
            
            if choice == "1":
                self.login_user()
            elif choice == "2":
                self.register_user()
            elif choice == "3":
                print("\n👋 Thank you for using Secure Banking System!")
                print("🔐 Your data remains encrypted and secure.")
                break
            else:
                print("\n❌ Invalid option! Please select 1, 2, or 3.")
                input("Press Enter to continue...")

def main():
    """Main application entry point"""
    try:
        banking_cli = EnhancedBankingCLI()
        banking_cli.main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Session terminated. Your data remains secure.")
    except Exception as e:
        print(f"\n❌ System error: {e}")

if __name__ == "__main__":
    main()
