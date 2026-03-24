content = """2026-03-10 10:00:01 INFO User login attempt from 192.168.1.105
2026-03-10 10:00:02 INFO email=admin@company.com
2026-03-10 10:00:03 DEBUG password=admin123
2026-03-10 10:00:04 INFO api_key=sk-prod-xyz123456789abc
2026-03-10 10:00:05 ERROR NullPointerException at com.service.UserService.java:45
2026-03-10 10:00:06 INFO login failed for user admin from 192.168.1.105
2026-03-10 10:00:07 INFO login failed for user admin from 192.168.1.105
2026-03-10 10:00:08 INFO login failed for user admin from 192.168.1.105
2026-03-10 10:00:09 INFO login failed for user admin from 192.168.1.105
2026-03-10 10:00:10 INFO login failed for user admin from 192.168.1.105
2026-03-10 10:00:11 INFO login success for user admin from 192.168.1.105
2026-03-10 10:00:12 INFO GET /api/users from 192.168.1.105
"""

with open("test.log", "w", encoding="utf-8") as f:
    f.write(content)

print("test.log created with UTF-8 encoding")