"""
Bank-Side Enhanced CLI Banking System
Receive, Decrypt, Verify Customer Messages with Digital Signatures
Send Digitally Signed Responses to Customers
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

# Storage configuration (same as customer side)
STORAGE_PATH = r"your\data"
DATABASE_PATH = os.path.join(STORAGE_PATH, "banking_system.db")
MESSAGES_PATH = os.path.join(STORAGE_PATH, "user_messages")
BANK_RESPONSES_PATH = os.path.join(STORAGE_PATH, "bank_responses")

class BankEnhancedCLI:
    def __init__(self):
        self.current_bank_admin = None
        self.bank_keys = None
        self.setup_bank_storage()
        self.initialize_bank_keys()
    
    def setup_bank_storage(self):
        """Setup bank-side storage and database tables"""
        try:
            # Create directories
            os.makedirs(STORAGE_PATH, exist_ok=True)
            os.makedirs(MESSAGES_PATH, exist_ok=True)
            os.makedirs(BANK_RESPONSES_PATH, exist_ok=True)
            
            # Setup database
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            # Bank administrators table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS bank_admins (
                admin_id TEXT PRIMARY KEY,
                username TEXT UNIQUE,
                password_hash TEXT,
                full_name TEXT,
                department TEXT,
                created_date TEXT,
                last_login TEXT
            )
            ''')
            
            # Bank keys table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS bank_keys (
                id INTEGER PRIMARY KEY,
                private_key TEXT,
                public_key TEXT,
                created_date TEXT,
                key_type TEXT
            )
            ''')
            
            # Bank responses table
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS bank_responses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                response_id TEXT,
                customer_user_id TEXT,
                original_message_id TEXT,
                response_content TEXT,
                admin_id TEXT,
                encrypted_file_path TEXT,
                timestamp TEXT,
                digital_signature TEXT,
                response_hash TEXT,
                FOREIGN KEY (admin_id) REFERENCES bank_admins (admin_id)
            )
            ''')
            
            conn.commit()
            conn.close()
            
            print(f"✅ Bank-side storage initialized at: {STORAGE_PATH}")
            
        except Exception as e:
            print(f"❌ Bank storage setup failed: {e}")
            exit(1)

    def initialize_bank_keys(self):
        """Initialize or load bank's RSA key pair"""
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            # Check if bank keys exist
            cursor.execute("SELECT private_key, public_key FROM bank_keys WHERE key_type = 'primary' ORDER BY id DESC LIMIT 1")
            result = cursor.fetchone()
            
            if result:
                # Load existing keys
                self.bank_keys = {
                    'private_key': base64.b64decode(result[0].encode()),
                    'public_key': base64.b64decode(result[1].encode())
                }
                print("🔐 Bank RSA keys loaded successfully")
            else:
                # Generate new keys
                print("🔐 Generating new bank RSA key pair...")
                private_key_pem, public_key_pem = self.generate_rsa_keypair()
                
                if private_key_pem and public_key_pem:
                    # Store keys in database
                    cursor.execute('''
                    INSERT INTO bank_keys (private_key, public_key, created_date, key_type)
                    VALUES (?, ?, ?, ?)
                    ''', (base64.b64encode(private_key_pem).decode(),
                          base64.b64encode(public_key_pem).decode(),
                          datetime.now().isoformat(),
                          'primary'))
                    
                    self.bank_keys = {
                        'private_key': private_key_pem,
                        'public_key': public_key_pem
                    }
                    
                    conn.commit()
                    print("✅ New bank RSA keys generated and stored")
                else:
                    print("❌ Failed to generate bank keys")
                    
            conn.close()
            
        except Exception as e:
            print(f"❌ Bank key initialization failed: {e}")

    def generate_rsa_keypair(self):
        """Generate RSA key pair for bank digital signatures"""
        try:
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
            print(f"❌ RSA key generation failed: {e}")
            return None, None

    def create_digital_signature(self, message_data, private_key_pem):
        """Create digital signature for bank response"""
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
            print(f"❌ Bank digital signature creation failed: {e}")
            return None

    def verify_customer_signature(self, message_data, signature_b64, customer_public_key_pem):
        """Verify customer's digital signature"""
        try:
            # Load public key
            public_key = serialization.load_pem_public_key(customer_public_key_pem)
            
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
            print(f"❌ Customer signature verification error: {e}")
            return False

    def compute_hash(self, data):
        """Compute SHA-256 hash of data"""
        if isinstance(data, dict):
            data = json.dumps(data, sort_keys=True)
        elif not isinstance(data, str):
            data = str(data)
        
        return hashlib.sha256(data.encode()).hexdigest()

    def hash_password(self, password):
        """Hash password with SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()

    def create_bank_admin(self):
        """Create new bank administrator account"""
        print("\n" + "="*60)
        print("🏦 CREATE NEW BANK ADMINISTRATOR")
        print("="*60)
        
        username = input("Enter admin username: ").strip()
        if not username:
            print("❌ Username cannot be empty!")
            return
        
        password = getpass.getpass("Enter admin password: ")
        if not password:
            print("❌ Password cannot be empty!")
            return
        
        full_name = input("Enter full name: ").strip()
        department = input("Enter department: ").strip()
        
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            # Check if username exists
            cursor.execute("SELECT username FROM bank_admins WHERE username = ?", (username,))
            if cursor.fetchone():
                print("❌ Admin username already exists!")
                conn.close()
                return
            
            # Generate admin ID
            admin_id = f"ADMIN_{hashlib.md5(f'{username}_{int(time.time())}'.encode()).hexdigest()[:8].upper()}"
            
            # Insert admin
            cursor.execute('''
            INSERT INTO bank_admins (admin_id, username, password_hash, full_name, department, created_date)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (admin_id, username, self.hash_password(password), full_name, department, datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
            print(f"✅ Bank administrator created successfully!")
            print(f"🆔 Admin ID: {admin_id}")
            print(f"👤 Username: {username}")
            print(f"🏢 Department: {department}")
            
        except Exception as e:
            print(f"❌ Admin creation failed: {e}")

    def bank_admin_login(self):
        """Bank administrator login"""
        print("\n" + "="*50)
        print("🏦 BANK ADMINISTRATOR LOGIN")
        print("="*50)
        
        username = input("Enter admin username: ").strip()
        password = getpass.getpass("Enter admin password: ")
        
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT admin_id, username, full_name, department 
            FROM bank_admins 
            WHERE username = ? AND password_hash = ?
            ''', (username, self.hash_password(password)))
            
            admin = cursor.fetchone()
            
            if admin:
                # Update last login
                cursor.execute("UPDATE bank_admins SET last_login = ? WHERE admin_id = ?", 
                             (datetime.now().isoformat(), admin[0]))
                conn.commit()
                
                self.current_bank_admin = {
                    "admin_id": admin[0],
                    "username": admin[1],
                    "full_name": admin[2],
                    "department": admin[3]
                }
                
                print(f"✅ Bank admin login successful!")
                print(f"👋 Welcome, {self.current_bank_admin['full_name']}")
                print(f"🏢 Department: {self.current_bank_admin['department']}")
                print(f"🆔 Admin ID: {self.current_bank_admin['admin_id']}")
                
                self.show_bank_menu()
                
            else:
                print("❌ Invalid admin credentials!")
                
            conn.close()
                
        except Exception as e:
            print(f"❌ Bank admin login failed: {e}")

    def show_bank_menu(self):
        """Show bank administrator menu"""
        while self.current_bank_admin:
            print(f"\n" + "="*60)
            print(f"🏦 BANK ADMINISTRATION PANEL - {self.current_bank_admin['full_name']}")
            print("="*60)
            print("1. 📨 View customer messages")
            print("2. 🔍 Decrypt and verify specific customer message")
            print("3. 💬 Send digitally signed response to customer")
            print("4. 📋 View sent responses")
            print("5. 🔐 View bank public key")
            print("6. 👥 View all customers")
            print("7. 📊 Banking statistics")
            print("8. 🚪 Logout")
            
            choice = input("\n➤ Select option (1-8): ").strip()
            
            if choice == "1":
                self.view_customer_messages()
            elif choice == "2":
                self.decrypt_and_verify_message()
            elif choice == "3":
                self.send_response_to_customer()
            elif choice == "4":
                self.view_sent_responses()
            elif choice == "5":
                self.view_bank_public_key()
            elif choice == "6":
                self.view_all_customers()
            elif choice == "7":
                self.show_banking_statistics()
            elif choice == "8":
                print(f"👋 Goodbye, {self.current_bank_admin['full_name']}!")
                self.current_bank_admin = None
            else:
                print("❌ Invalid option! Please select 1-8.")

    def view_customer_messages(self):
        """View all customer messages"""
        print("\n" + "="*60)
        print("📨 CUSTOMER MESSAGES OVERVIEW")
        print("="*60)
        
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT m.message_id, m.user_id, u.username, u.full_name, m.timestamp, 
                   m.network_latency, m.location_data, m.digital_signature
            FROM messages m
            JOIN users u ON m.user_id = u.user_id
            ORDER BY m.timestamp DESC
            ''')
            
            messages = cursor.fetchall()
            conn.close()
            
            if messages:
                print(f"Found {len(messages)} customer messages:")
                print("-" * 80)
                
                for i, msg in enumerate(messages, 1):
                    msg_id, user_id, username, full_name, timestamp, latency, location_json, signature = msg
                    formatted_time = datetime.fromisoformat(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                    
                    try:
                        location = json.loads(location_json) if location_json else {}
                    except:
                        location = {}
                    
                    print(f"{i}. 📧 Message ID: {msg_id}")
                    print(f"   👤 From: {full_name} (@{username})")
                    print(f"   🆔 User ID: {user_id}")
                    print(f"   🕐 Time: {formatted_time}")
                    print(f"   📡 Latency: {latency}ms")
                    print(f"   🌍 Location: {location.get('city', 'Unknown')}, {location.get('country', 'Unknown')}")
                    print(f"   ✍️  Signature: {'✅ Present' if signature else '❌ Missing'}")
                    print("-" * 80)
                
            else:
                print("📝 No customer messages found.")
                
        except Exception as e:
            print(f"❌ Error retrieving customer messages: {e}")

    def decrypt_and_verify_message(self):
        """Decrypt and verify a specific customer message"""
        print("\n" + "="*60)
        print("🔍 DECRYPT & VERIFY CUSTOMER MESSAGE")
        print("="*60)
        
        try:
            # Get all messages
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT m.message_id, m.user_id, u.username, u.full_name, m.encrypted_file_path,
                   m.digital_signature, u.public_key, u.encryption_key
            FROM messages m
            JOIN users u ON m.user_id = u.user_id
            ORDER BY m.timestamp DESC
            ''')
            
            messages = cursor.fetchall()
            conn.close()
            
            if not messages:
                print("📝 No customer messages found.")
                return
            
            print("Available messages:")
            for i, (msg_id, user_id, username, full_name, _, _, _, _) in enumerate(messages, 1):
                print(f"{i}. {msg_id} - From: {full_name} (@{username})")
            
            choice = input("\nSelect message number to decrypt: ").strip()
            
            try:
                msg_index = int(choice) - 1
                if 0 <= msg_index < len(messages):
                    msg_id, user_id, username, full_name, file_path, signature, public_key_b64, encryption_key_b64 = messages[msg_index]
                    
                    print(f"\n🔍 Processing message {msg_id} from {full_name}...")
                    
                    # Load encrypted message file
                    full_file_path = os.path.join(MESSAGES_PATH, user_id, file_path)
                    
                    if not os.path.exists(full_file_path):
                        print("❌ Message file not found!")
                        return
                    
                    # Decrypt message
                    user_key = base64.b64decode(encryption_key_b64.encode())
                    fernet = Fernet(user_key)
                    
                    with open(full_file_path, 'rb') as f:
                        encrypted_data = f.read()
                    
                    decrypted_data = fernet.decrypt(encrypted_data)
                    message_content = json.loads(decrypted_data.decode())
                    
                    print("✅ Message decrypted successfully!")
                    print("\n" + "="*50)
                    print("📄 DECRYPTED MESSAGE CONTENT")
                    print("="*50)
                    
                    print(f"👤 Sender: {message_content.get('sender_name', 'Unknown')}")
                    print(f"🆔 Sender ID: {message_content.get('sender_user_id', 'Unknown')}")
                    print(f"🎯 Recipient: {message_content.get('recipient', 'Unknown')}")
                    print(f"🕐 Timestamp: {message_content.get('timestamp', 'Unknown')}")
                    print(f"📧 Message Type: {message_content.get('message_type', 'Unknown')}")
                    print(f"📡 Network Latency: {message_content.get('network_latency', 'Unknown')}ms")
                    
                    location_data = message_content.get('location_data', {})
                    if location_data:
                        print(f"🌍 Location: {location_data.get('city', 'Unknown')}, {location_data.get('country', 'Unknown')}")
                        print(f"🌐 IP Address: {location_data.get('ip', 'Unknown')}")
                    
                    print("\n📝 MESSAGE CONTENT:")
                    print("-" * 30)
                    print(message_content.get('content', 'No content'))
                    print("-" * 30)
                    
                    # Verify digital signature if present
                    if signature and public_key_b64:
                        print("\n🔍 Verifying digital signature...")
                        
                        # Extract original message data for verification
                        original_message_data = {
                            "sender_user_id": message_content.get("sender_user_id"),
                            "sender_name": message_content.get("sender_name"),
                            "recipient": message_content.get("recipient"),
                            "content": message_content.get("content"),
                            "timestamp": message_content.get("timestamp"),
                            "message_type": message_content.get("message_type")
                        }
                        
                        customer_public_key = base64.b64decode(public_key_b64.encode())
                        verification_result = self.verify_customer_signature(
                            original_message_data, signature, customer_public_key
                        )
                        
                        if verification_result:
                            print("✅ Digital signature VERIFIED - Message is authentic!")
                        else:
                            print("❌ Digital signature VERIFICATION FAILED - Message may be tampered!")
                    else:
                        print("⚠️  No digital signature to verify")
                        
                else:
                    print("❌ Invalid message selection!")
                    
            except ValueError:
                print("❌ Please enter a valid number!")
                
        except Exception as e:
            print(f"❌ Message decryption failed: {e}")

    def send_response_to_customer(self):
        """Send digitally signed response to customer"""
        print("\n" + "="*60)
        print("💬 SEND RESPONSE TO CUSTOMER")
        print("="*60)
        
        try:
            # Get all customers
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute("SELECT user_id, username, full_name FROM users ORDER BY full_name")
            customers = cursor.fetchall()
            conn.close()
            
            if not customers:
                print("👥 No customers found.")
                return
            
            print("Available customers:")
            for i, (user_id, username, full_name) in enumerate(customers, 1):
                print(f"{i}. {full_name} (@{username}) - ID: {user_id}")
            
            choice = input("\nSelect customer number: ").strip()
            
            try:
                cust_index = int(choice) - 1
                if 0 <= cust_index < len(customers):
                    customer_user_id, customer_username, customer_full_name = customers[cust_index]
                    
                    print(f"\n💬 Sending response to: {customer_full_name} (@{customer_username})")
                    
                    # Get message reference (optional)
                    original_msg_id = input("Original message ID (press Enter to skip): ").strip()
                    
                    # Get response content
                    print("\nEnter your response (press Enter twice to finish):")
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
                    
                    response_content = "\n".join(lines).strip()
                    
                    if not response_content:
                        print("❌ Response cannot be empty!")
                        return
                    
                    # Create response data
                    response_data = {
                        "sender": "BANK",
                        "sender_admin_id": self.current_bank_admin["admin_id"],
                        "sender_admin_name": self.current_bank_admin["full_name"],
                        "sender_department": self.current_bank_admin["department"],
                        "recipient_user_id": customer_user_id,
                        "recipient_name": customer_full_name,
                        "content": response_content,
                        "timestamp": datetime.now().isoformat(),
                        "message_type": "bank_to_customer",
                        "original_message_id": original_msg_id if original_msg_id else None
                    }
                    
                    print("\n🔐 Creating digital signature...")
                    
                    # Create digital signature
                    signature = self.create_digital_signature(response_data, self.bank_keys['private_key'])
                    
                    if not signature:
                        print("❌ Failed to create digital signature!")
                        return
                    
                    # Generate response ID
                    response_id = f"RESP_{int(time.time())}_{hash(response_content) % 10000:04d}"
                    
                    # Create response with signature
                    signed_response_data = {
                        **response_data,
                        "response_id": response_id,
                        "digital_signature": signature
                    }
                    
                    # Compute response hash
                    response_hash = self.compute_hash(response_data)
                    
                    # Save response to bank responses directory
                    bank_response_dir = os.path.join(BANK_RESPONSES_PATH, customer_user_id)
                    os.makedirs(bank_response_dir, exist_ok=True)
                    
                    response_filename = f"{response_id}.json"
                    response_file_path = os.path.join(bank_response_dir, response_filename)
                    
                    with open(response_file_path, 'w') as f:
                        json.dump(signed_response_data, f, indent=2)
                    
                    # Store response reference in database
                    conn = sqlite3.connect(DATABASE_PATH)
                    cursor = conn.cursor()
                    cursor.execute('''
                    INSERT INTO bank_responses (response_id, customer_user_id, original_message_id,
                                              response_content, admin_id, encrypted_file_path,
                                              timestamp, digital_signature, response_hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (response_id, customer_user_id, original_msg_id, response_content,
                          self.current_bank_admin["admin_id"], response_filename,
                          datetime.now().isoformat(), signature, response_hash))
                    conn.commit()
                    conn.close()
                    
                    print(f"✅ Digitally signed response sent successfully!")
                    print(f"📧 Response ID: {response_id}")
                    print(f"👤 To: {customer_full_name}")
                    print(f"✍️  Digital Signature: {signature[:32]}...")
                    print(f"🔐 Response Hash: {response_hash[:16]}...")
                    print(f"💾 Saved to: {response_file_path}")
                    
                else:
                    print("❌ Invalid customer selection!")
                    
            except ValueError:
                print("❌ Please enter a valid number!")
                
        except Exception as e:
            print(f"❌ Response sending failed: {e}")

    def view_sent_responses(self):
        """View all responses sent by bank"""
        print("\n" + "="*60)
        print("📋 BANK RESPONSES SENT")
        print("="*60)
        
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT br.response_id, br.customer_user_id, u.full_name, br.original_message_id,
                   br.timestamp, br.admin_id, ba.full_name, br.digital_signature
            FROM bank_responses br
            JOIN users u ON br.customer_user_id = u.user_id
            JOIN bank_admins ba ON br.admin_id = ba.admin_id
            ORDER BY br.timestamp DESC
            ''')
            
            responses = cursor.fetchall()
            conn.close()
            
            if responses:
                print(f"Found {len(responses)} bank responses:")
                print("-" * 80)
                
                for i, resp in enumerate(responses, 1):
                    resp_id, cust_id, cust_name, orig_msg_id, timestamp, admin_id, admin_name, signature = resp
                    formatted_time = datetime.fromisoformat(timestamp).strftime('%Y-%m-%d %H:%M:%S')
                    
                    print(f"{i}. 📧 Response ID: {resp_id}")
                    print(f"   👤 To Customer: {cust_name}")
                    print(f"   🔗 Original Message: {orig_msg_id if orig_msg_id else 'New conversation'}")
                    print(f"   🕐 Sent: {formatted_time}")
                    print(f"   👨‍💼 By Admin: {admin_name}")
                    print(f"   ✍️  Signature: {'✅ Present' if signature else '❌ Missing'}")
                    print("-" * 80)
                
            else:
                print("📝 No responses sent yet.")
                
        except Exception as e:
            print(f"❌ Error retrieving responses: {e}")

    def view_bank_public_key(self):
        """Display bank's public key for customers"""
        print("\n" + "="*60)
        print("🔐 BANK PUBLIC KEY")
        print("="*60)
        
        if self.bank_keys and 'public_key' in self.bank_keys:
            public_key_pem = self.bank_keys['public_key']
            public_key_b64 = base64.b64encode(public_key_pem).decode()
            
            print("📋 Bank's Public Key (for customer verification):")
            print("-" * 60)
            print(public_key_pem.decode())
            print("-" * 60)
            print(f"\n🔗 Base64 Encoded (for integration):")
            print(f"{public_key_b64}")
            print(f"\n📏 Key Length: {len(public_key_pem)} bytes")
            print(f"🔐 Key Type: RSA-2048")
            print("\n💡 Customers can use this key to verify bank responses!")
            
        else:
            print("❌ Bank public key not available!")

    def view_all_customers(self):
        """View all registered customers"""
        print("\n" + "="*60)
        print("👥 ALL REGISTERED CUSTOMERS")
        print("="*60)
        
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT user_id, username, full_name, registration_date, registration_location
            FROM users 
            ORDER BY registration_date DESC
            ''')
            
            customers = cursor.fetchall()
            conn.close()
            
            if customers:
                print(f"Found {len(customers)} registered customers:")
                print("-" * 80)
                
                for i, cust in enumerate(customers, 1):
                    user_id, username, full_name, reg_date, reg_location = cust
                    formatted_date = datetime.fromisoformat(reg_date).strftime('%Y-%m-%d %H:%M:%S')
                    
                    try:
                        location = json.loads(reg_location) if reg_location else {}
                    except:
                        location = {}
                    
                    print(f"{i}. 👤 {full_name} (@{username})")
                    print(f"   🆔 User ID: {user_id}")
                    print(f"   📅 Registered: {formatted_date}")
                    print(f"   🌍 Location: {location.get('city', 'Unknown')}, {location.get('country', 'Unknown')}")
                    print("-" * 80)
                
            else:
                print("👥 No customers registered yet.")
                
        except Exception as e:
            print(f"❌ Error retrieving customers: {e}")

    def show_banking_statistics(self):
        """Show banking system statistics"""
        print("\n" + "="*60)
        print("📊 BANKING SYSTEM STATISTICS")
        print("="*60)
        
        try:
            conn = sqlite3.connect(DATABASE_PATH)
            cursor = conn.cursor()
            
            # Count customers
            cursor.execute("SELECT COUNT(*) FROM users")
            total_customers = cursor.fetchone()[0]
            
            # Count messages
            cursor.execute("SELECT COUNT(*) FROM messages")
            total_messages = cursor.fetchone()[0]
            
            # Count messages with signatures
            cursor.execute("SELECT COUNT(*) FROM messages WHERE digital_signature IS NOT NULL")
            signed_messages = cursor.fetchone()[0]
            
            # Count bank responses
            cursor.execute("SELECT COUNT(*) FROM bank_responses")
            total_responses = cursor.fetchone()[0]
            
            # Count bank admins
            cursor.execute("SELECT COUNT(*) FROM bank_admins")
            total_admins = cursor.fetchone()[0]
            
            # Recent activity (last 7 days)
            seven_days_ago = (datetime.now() - datetime.timedelta(days=7)).isoformat()
            cursor.execute("SELECT COUNT(*) FROM messages WHERE timestamp > ?", (seven_days_ago,))
            recent_messages = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(*) FROM bank_responses WHERE timestamp > ?", (seven_days_ago,))
            recent_responses = cursor.fetchone()[0]
            
            conn.close()
            
            print(f"👥 Total Customers: {total_customers}")
            print(f"📨 Total Messages Received: {total_messages}")
            print(f"✍️  Digitally Signed Messages: {signed_messages}")
            print(f"📋 Total Responses Sent: {total_responses}")
            print(f"👨‍💼 Bank Administrators: {total_admins}")
            print("-" * 40)
            print("📈 RECENT ACTIVITY (Last 7 days):")
            print(f"📨 New Messages: {recent_messages}")
            print(f"📋 Responses Sent: {recent_responses}")
            print("-" * 40)
            
            if total_messages > 0:
                signature_percentage = (signed_messages / total_messages) * 100
                print(f"🔐 Signature Coverage: {signature_percentage:.1f}%")
            
            print(f"🔐 Bank Key Status: {'✅ Active' if self.bank_keys else '❌ Missing'}")
            
        except Exception as e:
            print(f"❌ Error retrieving statistics: {e}")

    def main_menu(self):
        """Main bank application menu"""
        print("="*70)
        print("🏦 BANK-SIDE ENHANCED SECURE BANKING SYSTEM")
        print("="*70)
        print("🔐 Message Decryption | 🔍 Signature Verification | 💬 Digital Response System")
        print("="*70)
        
        while True:
            print("\n🏠 BANK MAIN MENU:")
            print("1. 🔐 Bank Administrator Login")
            print("2. 👨‍💼 Create New Bank Administrator") 
            print("3. 🚪 Exit")
            
            choice = input("\n➤ Select option (1-3): ").strip()
            
            if choice == "1":
                self.bank_admin_login()
            elif choice == "2":
                self.create_bank_admin()
            elif choice == "3":
                print("\n👋 Thank you for using Bank-Side Enhanced Secure Banking System!")
                print("🔐 All customer data remains securely encrypted.")
                break
            else:
                print("❌ Invalid option! Please select 1, 2, or 3.")


def main():
    """Main bank application entry point"""
    try:
        bank_cli = BankEnhancedCLI()
        bank_cli.main_menu()
    except KeyboardInterrupt:
        print("\n\n👋 Bank session terminated. Customer data remains secure.")
    except Exception as e:
        print(f"\n❌ Bank system error: {e}")


if __name__ == "__main__":
    main()

