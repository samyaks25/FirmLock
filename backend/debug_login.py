from fastapi.testclient import TestClient
from app.main import app
from app.core.login_protection import get_login_protection

client = TestClient(app)
protection = get_login_protection()
protection.reset('testserver', 'test@example.com')

print(f'Before: {protection.get_failure_count("testserver", "test@example.com")}')

# Make failed login attempts
for i in range(3):
    resp = client.post('/api/auth/login', json={
        'email': 'test@example.com',
        'password': 'wrongpassword123',
    })
    print(f'Attempt {i+1}: status={resp.status_code}')

print(f'After: {protection.get_failure_count("testserver", "test@example.com")}')
print(f'Attempts dict: {protection._attempts}')