from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List
import random
import string
import secrets
import hashlib
import requests
import time
import asyncio
from collections import defaultdict
import math
import re
import os
from datetime import datetime, timedelta

app = FastAPI(title="Secure Password Generator API", version="1.0.0")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting for HaveIBeenPwned API
class RateLimiter:
    def __init__(self):
        self.requests = defaultdict(list)
        self.max_requests = 1  # 1 request per 1.5 seconds for free tier
        self.time_window = 1.5
    
    def can_make_request(self):
        now = time.time()
        # Clean old requests
        self.requests['hibp'] = [req_time for req_time in self.requests['hibp'] if now - req_time < self.time_window]
        
        if len(self.requests['hibp']) < self.max_requests:
            self.requests['hibp'].append(now)
            return True
        return False

rate_limiter = RateLimiter()

# Password generation models
class PasswordRequest(BaseModel):
    length: int = Field(default=16, ge=8, le=128, description="Password length (8-128)")
    include_uppercase: bool = Field(default=True, description="Include uppercase letters")
    include_lowercase: bool = Field(default=True, description="Include lowercase letters")
    include_numbers: bool = Field(default=True, description="Include numbers")
    include_symbols: bool = Field(default=True, description="Include symbols")
    exclude_ambiguous: bool = Field(default=True, description="Exclude ambiguous characters (1, l, 0, O, etc.)")
    security_standard: str = Field(default="NIST", description="Security standard (NIST, OWASP)")
    check_compromised: bool = Field(default=False, description="Check if password has been compromised")

class BulkPasswordRequest(BaseModel):
    count: int = Field(default=1, ge=1, le=100, description="Number of passwords to generate")
    length: int = Field(default=16, ge=8, le=128, description="Password length (8-128)")
    include_uppercase: bool = Field(default=True, description="Include uppercase letters")
    include_lowercase: bool = Field(default=True, description="Include lowercase letters")
    include_numbers: bool = Field(default=True, description="Include numbers")
    include_symbols: bool = Field(default=True, description="Include symbols")
    exclude_ambiguous: bool = Field(default=True, description="Exclude ambiguous characters")
    security_standard: str = Field(default="NIST", description="Security standard (NIST, OWASP)")
    check_compromised: bool = Field(default=False, description="Check if passwords have been compromised")

class ReadablePasswordRequest(BaseModel):
    word_count: int = Field(default=4, ge=2, le=8, description="Number of words")
    separator: str = Field(default="-", description="Word separator")
    include_numbers: bool = Field(default=True, description="Include numbers")
    capitalize: bool = Field(default=True, description="Capitalize first letter of each word")
    check_compromised: bool = Field(default=False, description="Check if password has been compromised")

class PassphraseRequest(BaseModel):
    length: int = Field(default=32, ge=16, le=128, description="Passphrase length")
    include_spaces: bool = Field(default=True, description="Include spaces")
    check_compromised: bool = Field(default=False, description="Check if password has been compromised")

# Character sets
AMBIGUOUS_CHARS = "1l0OiI"
LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
NUMBERS = "0123456789"
SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"

# Common words for readable passwords
COMMON_WORDS = [
    "correct", "horse", "battery", "staple", "apple", "banana", "orange", "grape",
    "table", "chair", "house", "window", "door", "book", "paper", "pencil",
    "computer", "keyboard", "mouse", "screen", "phone", "camera", "music", "video",
    "garden", "flower", "tree", "grass", "water", "fire", "earth", "wind",
    "mountain", "ocean", "river", "forest", "desert", "island", "bridge", "road",
    "happy", "brave", "quick", "smart", "strong", "gentle", "bright", "calm",
    "magic", "wonder", "dream", "smile", "laugh", "peace", "hope", "love",
    "cloud", "storm", "rainbow", "sunshine", "moonlight", "starlight", "crystal", "diamond"
]

def get_character_set(include_uppercase: bool, include_lowercase: bool, include_numbers: bool, 
                      include_symbols: bool, exclude_ambiguous: bool, security_standard: str) -> str:
    """Generate character set based on requirements"""
    charset = ""
    
    if include_lowercase:
        charset += LOWERCASE
    if include_uppercase:
        charset += UPPERCASE
    if include_numbers:
        charset += NUMBERS
    if include_symbols:
        if security_standard == "OWASP":
            # OWASP recommends more conservative symbol set
            charset += "!@#$%^&*"
        else:
            charset += SYMBOLS
    
    if exclude_ambiguous:
        charset = "".join(char for char in charset if char not in AMBIGUOUS_CHARS)
    
    return charset

def calculate_entropy(password: str, charset_size: int) -> float:
    """Calculate password entropy in bits"""
    return len(password) * math.log2(charset_size)

def evaluate_strength(password: str, entropy: float) -> str:
    """Evaluate password strength"""
    if entropy < 40:
        return "weak"
    elif entropy < 60:
        return "medium"
    elif entropy < 80:
        return "strong"
    else:
        return "very_strong"

async def check_hibp_compromised(password: str) -> tuple[bool, int]:
    """Check if password has been compromised using HaveIBeenPwned API"""
    if not rate_limiter.can_make_request():
        return False, -1  # Rate limited, return safe assumption
    
    try:
        # Hash the password
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        
        # Make request to HaveIBeenPwned API
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        headers = {"User-Agent": "SecurePasswordGenerator/1.0"}
        
        response = requests.get(url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            # Parse response
            for line in response.text.split('\n'):
                if line.startswith(suffix):
                    count = int(line.split(':')[1].strip())
                    return True, count
            return False, 0
        else:
            return False, -1  # API error, return safe assumption
            
    except Exception:
        return False, -1  # Error, return safe assumption

@app.get("/")
async def root():
    return {"message": "Secure Password Generator API", "version": "1.0.0"}

@app.post("/api/generate")
async def generate_password(request: PasswordRequest):
    """Generate a single secure password"""
    # Validate at least one character type is selected
    if not any([request.include_uppercase, request.include_lowercase, request.include_numbers, request.include_symbols]):
        raise HTTPException(status_code=400, detail="At least one character type must be selected")
    
    # Get character set
    charset = get_character_set(
        request.include_uppercase, request.include_lowercase, request.include_numbers,
        request.include_symbols, request.exclude_ambiguous, request.security_standard
    )
    
    if not charset:
        raise HTTPException(status_code=400, detail="No valid characters available with current settings")
    
    # Generate password
    password = ''.join(secrets.choice(charset) for _ in range(request.length))
    
    # Calculate entropy
    entropy = calculate_entropy(password, len(charset))
    
    # Evaluate strength
    strength = evaluate_strength(password, entropy)
    
    # Check if compromised (if requested)
    is_compromised = False
    compromise_count = 0
    
    if request.check_compromised:
        is_compromised, compromise_count = await check_hibp_compromised(password)
    
    return {
        "password": password,
        "length": len(password),
        "entropy_bits": round(entropy, 2),
        "strength": strength,
        "charset_size": len(charset),
        "is_compromised": is_compromised,
        "compromise_count": compromise_count if compromise_count > 0 else None,
        "security_standard": request.security_standard
    }

@app.post("/api/generate/bulk")
async def generate_bulk_passwords(request: BulkPasswordRequest):
    """Generate multiple secure passwords"""
    if not any([request.include_uppercase, request.include_lowercase, request.include_numbers, request.include_symbols]):
        raise HTTPException(status_code=400, detail="At least one character type must be selected")
    
    charset = get_character_set(
        request.include_uppercase, request.include_lowercase, request.include_numbers,
        request.include_symbols, request.exclude_ambiguous, request.security_standard
    )
    
    if not charset:
        raise HTTPException(status_code=400, detail="No valid characters available with current settings")
    
    passwords = []
    
    for _ in range(request.count):
        # Generate password
        password = ''.join(secrets.choice(charset) for _ in range(request.length))
        
        # Calculate entropy
        entropy = calculate_entropy(password, len(charset))
        
        # Evaluate strength
        strength = evaluate_strength(password, entropy)
        
        # Check if compromised (if requested)
        is_compromised = False
        compromise_count = 0
        
        if request.check_compromised:
            is_compromised, compromise_count = await check_hibp_compromised(password)
        
        passwords.append({
            "password": password,
            "length": len(password),
            "entropy_bits": round(entropy, 2),
            "strength": strength,
            "is_compromised": is_compromised,
            "compromise_count": compromise_count if compromise_count > 0 else None
        })
    
    return {
        "passwords": passwords,
        "count": len(passwords),
        "charset_size": len(charset),
        "security_standard": request.security_standard
    }

@app.post("/api/generate/readable")
async def generate_readable_password(request: ReadablePasswordRequest):
    """Generate readable password (correct-horse-battery-staple style)"""
    # Select random words
    selected_words = random.sample(COMMON_WORDS, request.word_count)
    
    if request.capitalize:
        selected_words = [word.capitalize() for word in selected_words]
    
    # Join words with separator
    password = request.separator.join(selected_words)
    
    # Add numbers if requested
    if request.include_numbers:
        password += str(random.randint(10, 99))
    
    # Calculate approximate entropy (word list size + numbers)
    word_entropy = request.word_count * math.log2(len(COMMON_WORDS))
    if request.include_numbers:
        word_entropy += math.log2(90)  # 10-99 range
    
    strength = evaluate_strength(password, word_entropy)
    
    # Check if compromised (if requested)
    is_compromised = False
    compromise_count = 0
    
    if request.check_compromised:
        is_compromised, compromise_count = await check_hibp_compromised(password)
    
    return {
        "password": password,
        "length": len(password),
        "word_count": request.word_count,
        "entropy_bits": round(word_entropy, 2),
        "strength": strength,
        "is_compromised": is_compromised,
        "compromise_count": compromise_count if compromise_count > 0 else None,
        "type": "readable"
    }

@app.post("/api/generate/pronounceable")
async def generate_pronounceable_password(request: PasswordRequest):
    """Generate pronounceable password"""
    # Consonants and vowels for pronounceable passwords
    consonants = "bcdfghjklmnpqrstvwxyz"
    vowels = "aeiou"
    
    if request.exclude_ambiguous:
        consonants = "".join(char for char in consonants if char not in AMBIGUOUS_CHARS)
        vowels = "".join(char for char in vowels if char not in AMBIGUOUS_CHARS)
    
    password = ""
    
    # Generate consonant-vowel pattern
    for i in range(request.length):
        if i % 2 == 0:  # Even positions: consonants
            char = secrets.choice(consonants)
            if request.include_uppercase and random.random() < 0.3:
                char = char.upper()
            password += char
        else:  # Odd positions: vowels
            char = secrets.choice(vowels)
            if request.include_uppercase and random.random() < 0.3:
                char = char.upper()
            password += char
    
    # Add numbers and symbols if requested
    if request.include_numbers:
        # Replace some characters with numbers
        num_replacements = min(2, request.length // 4)
        for _ in range(num_replacements):
            pos = random.randint(0, len(password) - 1)
            password = password[:pos] + secrets.choice(NUMBERS) + password[pos+1:]
    
    if request.include_symbols:
        # Add symbols at the end
        symbols = "!@#$%^&*"
        if request.exclude_ambiguous:
            symbols = "".join(char for char in symbols if char not in AMBIGUOUS_CHARS)
        password += secrets.choice(symbols)
    
    # Calculate entropy
    charset_size = len(consonants) + len(vowels)
    if request.include_numbers:
        charset_size += 10
    if request.include_symbols:
        charset_size += 8
    
    entropy = calculate_entropy(password, charset_size)
    strength = evaluate_strength(password, entropy)
    
    # Check if compromised (if requested)
    is_compromised = False
    compromise_count = 0
    
    if request.check_compromised:
        is_compromised, compromise_count = await check_hibp_compromised(password)
    
    return {
        "password": password,
        "length": len(password),
        "entropy_bits": round(entropy, 2),
        "strength": strength,
        "is_compromised": is_compromised,
        "compromise_count": compromise_count if compromise_count > 0 else None,
        "type": "pronounceable"
    }

@app.post("/api/generate/passphrase")
async def generate_passphrase(request: PassphraseRequest):
    """Generate passphrase for MFA/SSH"""
    # Use a mix of words, numbers, and symbols
    words = random.sample(COMMON_WORDS, 3)
    
    # Create passphrase with specific pattern
    passphrase = ""
    
    for i, word in enumerate(words):
        passphrase += word.capitalize()
        if i < len(words) - 1:
            if request.include_spaces:
                passphrase += " "
            else:
                passphrase += "-"
    
    # Add numbers and symbols
    passphrase += str(random.randint(100, 999))
    passphrase += secrets.choice("!@#$%^&*")
    
    # Pad to requested length if needed
    while len(passphrase) < request.length:
        passphrase += secrets.choice("abcdefghijklmnopqrstuvwxyz")
    
    # Truncate if too long
    if len(passphrase) > request.length:
        passphrase = passphrase[:request.length]
    
    # Calculate entropy
    entropy = 3 * math.log2(len(COMMON_WORDS)) + math.log2(900) + math.log2(8)
    strength = evaluate_strength(passphrase, entropy)
    
    # Check if compromised (if requested)
    is_compromised = False
    compromise_count = 0
    
    if request.check_compromised:
        is_compromised, compromise_count = await check_hibp_compromised(passphrase)
    
    return {
        "passphrase": passphrase,
        "length": len(passphrase),
        "entropy_bits": round(entropy, 2),
        "strength": strength,
        "is_compromised": is_compromised,
        "compromise_count": compromise_count if compromise_count > 0 else None,
        "type": "passphrase"
    }

@app.post("/api/check-compromised")
async def check_password_compromised(password: dict):
    """Check if a password has been compromised"""
    pwd = password.get("password", "")
    if not pwd:
        raise HTTPException(status_code=400, detail="Password is required")
    
    is_compromised, compromise_count = await check_hibp_compromised(pwd)
    
    return {
        "is_compromised": is_compromised,
        "compromise_count": compromise_count if compromise_count > 0 else None,
        "checked_at": datetime.now().isoformat()
    }

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)