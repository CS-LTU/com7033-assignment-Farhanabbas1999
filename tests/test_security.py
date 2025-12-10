"""
Security Testing Suite
Comprehensive tests for security features
Run with: python -m pytest tests/test_security.py -v
"""
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.security.validators import InputValidator, sanitize_input, sanitize_filename, validate_file_upload
from app.security.encryption import DataEncryption
from app.security.rate_limiter import RateLimiter
from app.security.audit_logger import AuditLogger


class TestInputValidation:
    """Test input validation functions"""
    
    def test_username_validation(self):
        """Test username validation"""
        # Valid usernames
        assert InputValidator.validate_username("user123")[0] == True
        assert InputValidator.validate_username("john_doe")[0] == True
        
        # Invalid usernames
        assert InputValidator.validate_username("ab")[0] == False  # Too short
        assert InputValidator.validate_username("a" * 31)[0] == False  # Too long
        assert InputValidator.validate_username("user@123")[0] == False  # Invalid char
        assert InputValidator.validate_username("user 123")[0] == False  # Space
        assert InputValidator.validate_username("")[0] == False  # Empty
        assert InputValidator.validate_username(None)[0] == False  # None
    
    def test_email_validation(self):
        """Test email validation"""
        # Valid emails
        assert InputValidator.validate_email("user@example.com")[0] == True
        assert InputValidator.validate_email("john.doe@company.co.uk")[0] == True
        
        # Invalid emails
        assert InputValidator.validate_email("invalid")[0] == False
        assert InputValidator.validate_email("@example.com")[0] == False
        assert InputValidator.validate_email("user@")[0] == False
        assert InputValidator.validate_email("")[0] == False
        assert InputValidator.validate_email(None)[0] == False
    
    def test_password_validation(self):
        """Test strong password validation"""
        # Valid passwords
        assert InputValidator.validate_password("StrongP@ss123")[0] == True
        assert InputValidator.validate_password("MyP@ssw0rd!")[0] == True
        
        # Invalid passwords
        assert InputValidator.validate_password("short")[0] == False  # Too short
        assert InputValidator.validate_password("alllowercase1!")[0] == False  # No uppercase
        assert InputValidator.validate_password("ALLUPPERCASE1!")[0] == False  # No lowercase
        assert InputValidator.validate_password("NoNumbers!")[0] == False  # No number
        assert InputValidator.validate_password("NoSpecial123")[0] == False  # No special char
        assert InputValidator.validate_password("")[0] == False  # Empty
    
    def test_phone_validation(self):
        """Test phone number validation"""
        # Valid phones
        assert InputValidator.validate_phone("1234567890")[0] == True
        assert InputValidator.validate_phone("+1 (555) 123-4567")[0] == True
        assert InputValidator.validate_phone("")[0] == True  # Optional field
        
        # Invalid phones
        assert InputValidator.validate_phone("123-ABC-4567")[0] == False  # Letters
        assert InputValidator.validate_phone("123@456")[0] == False  # Invalid char
    
    def test_name_validation(self):
        """Test name validation"""
        # Valid names
        assert InputValidator.validate_name("John Doe")[0] == True
        assert InputValidator.validate_name("Mary-Jane")[0] == True
        assert InputValidator.validate_name("O'Brien")[0] == True
        
        # Invalid names
        assert InputValidator.validate_name("J")[0] == False  # Too short
        assert InputValidator.validate_name("John123")[0] == False  # Numbers
        assert InputValidator.validate_name("John@Doe")[0] == False  # Special chars
    
    def test_numeric_validation(self):
        """Test numeric validation"""
        # Valid numbers
        assert InputValidator.validate_numeric(25, min_val=0, max_val=100)[0] == True
        assert InputValidator.validate_numeric(0, min_val=0)[0] == True
        
        # Invalid numbers
        assert InputValidator.validate_numeric(-1, min_val=0)[0] == False
        assert InputValidator.validate_numeric(101, max_val=100)[0] == False
        assert InputValidator.validate_numeric("abc")[0] == False
    
    def test_sanitize_input(self):
        """Test input sanitization"""
        # XSS prevention
        assert "&lt;script&gt;" in sanitize_input("<script>alert('xss')</script>")
        assert "<script>" not in sanitize_input("<script>alert('xss')</script>")
        
        # HTML entities
        assert "&amp;" in sanitize_input("Tom & Jerry")
    
    def test_sanitize_filename(self):
        """Test filename sanitization"""
        # Valid filenames
        assert sanitize_filename("document.pdf") == "document.pdf"
        assert sanitize_filename("my-file_2024.txt") == "my-file_2024.txt"
        
        # Dangerous filenames
        assert ".." not in sanitize_filename("../../etc/passwd")
        assert "/" not in sanitize_filename("path/to/file.txt")
        assert "\\" not in sanitize_filename("C:\\Windows\\system32")


class TestEncryption:
    """Test data encryption"""
    
    def test_encryption_decryption(self):
        """Test basic encryption and decryption"""
        encryptor = DataEncryption()
        
        plaintext = "Sensitive medical data"
        encrypted = encryptor.encrypt(plaintext)
        
        # Encrypted should be different from plaintext
        assert encrypted != plaintext
        
        # Decryption should return original
        decrypted = encryptor.decrypt(encrypted)
        assert decrypted == plaintext
    
    def test_encrypt_none(self):
        """Test encrypting None values"""
        encryptor = DataEncryption()
        assert encryptor.encrypt(None) is None
        assert encryptor.decrypt(None) is None
    
    def test_different_instances_same_key(self):
        """Test that different instances with same key can decrypt"""
        key = "test-key-12345"
        
        encryptor1 = DataEncryption(key)
        encryptor2 = DataEncryption(key)
        
        plaintext = "Test data"
        encrypted = encryptor1.encrypt(plaintext)
        decrypted = encryptor2.decrypt(encrypted)
        
        assert decrypted == plaintext


class TestRateLimiter:
    """Test rate limiting"""
    
    def test_rate_limit_allows_within_limit(self):
        """Test that requests within limit are allowed"""
        limiter = RateLimiter()
        identifier = "test_user_1"
        
        # Should allow first 5 attempts
        for i in range(5):
            allowed, remaining, wait = limiter.record_attempt(identifier, max_attempts=5)
            assert allowed == True
    
    def test_rate_limit_blocks_after_limit(self):
        """Test that requests are blocked after exceeding limit"""
        limiter = RateLimiter()
        identifier = "test_user_2"
        
        # Use up all attempts
        for i in range(5):
            limiter.record_attempt(identifier, max_attempts=5)
        
        # Next attempt should be blocked
        allowed, remaining, wait = limiter.record_attempt(identifier, max_attempts=5)
        assert allowed == False
        assert remaining == 0
    
    def test_rate_limit_reset(self):
        """Test that reset clears attempts"""
        limiter = RateLimiter()
        identifier = "test_user_3"
        
        # Use up attempts
        for i in range(6):
            limiter.record_attempt(identifier, max_attempts=5)
        
        # Should be blocked
        assert limiter.is_blocked(identifier)[0] == True
        
        # Reset
        limiter.reset_attempts(identifier)
        
        # Should be allowed again
        allowed, remaining, wait = limiter.record_attempt(identifier, max_attempts=5)
        assert allowed == True


class TestAuditLogging:
    """Test audit logging"""
    
    def test_log_event(self):
        """Test logging an event"""
        AuditLogger.log_event(
            event_type=AuditLogger.LOGIN_SUCCESS,
            description="Test login",
            username="test_user",
            severity=AuditLogger.INFO,
            success='success'
        )
        
        # Query logs
        logs = AuditLogger.get_logs(limit=1)
        assert len(logs) > 0
        assert logs[0].event_type == AuditLogger.LOGIN_SUCCESS
    
    def test_get_failed_logins(self):
        """Test querying failed logins"""
        username = "failed_user"
        
        # Log some failures
        for i in range(3):
            AuditLogger.log_event(
                event_type=AuditLogger.LOGIN_FAILURE,
                description=f"Failed login attempt {i}",
                username=username,
                success='failure'
            )
        
        # Query
        failures = AuditLogger.get_failed_logins(username=username)
        assert len(failures) >= 3


# Pytest fixtures
@pytest.fixture
def app():
    """Create test Flask app"""
    from app import create_app
    from config import Config
    
    class TestConfig(Config):
        TESTING = True
        SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
        WTF_CSRF_ENABLED = False
    
    app = create_app(TestConfig)
    return app


@pytest.fixture
def client(app):
    """Create test client"""
    return app.test_client()


def test_app_runs(client):
    """Test that app runs"""
    response = client.get('/')
    assert response.status_code in [200, 302]


if __name__ == '__main__':
    print("🧪 Running Security Tests...\n")
    pytest.main([__file__, '-v', '--tb=short'])
