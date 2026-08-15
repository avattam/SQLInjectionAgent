from typing import Dict, List, Any

# Untrusted user input sources across Python and JavaScript/TypeScript
UNTRUSTED_SOURCES = {
    "javascript": [
        r'req\.query(\.[a-zA-Z0-9_]+|\[.+?\])',
        r'req\.body(\.[a-zA-Z0-9_]+|\[.+?\])',
        r'req\.params(\.[a-zA-Z0-9_]+|\[.+?\])',
        r'req\.headers(\.[a-zA-Z0-9_]+|\[.+?\])',
        r'req\.cookies(\.[a-zA-Z0-9_]+|\[.+?\])',
        r'request\.query(\.[a-zA-Z0-9_]+|\[.+?\])',
        r'request\.body(\.[a-zA-Z0-9_]+|\[.+?\])',
        r'args\.[a-zA-Z0-9_]+',
        r'process\.env\.[a-zA-Z0-9_]+'
    ],
    "python": [
        r'request\.args\.get\(.+?\)',
        r'request\.args\[.+?\]',
        r'request\.form\.get\(.+?\)',
        r'request\.form\[.+?\]',
        r'request\.json\.get\(.+?\)',
        r'request\.json\[.+?\]',
        r'request\.GET\.get\(.+?\)',
        r'request\.POST\.get\(.+?\)',
        r'request\.headers\.get\(.+?\)',
        r'sys\.argv\[.+?\]',
        r'os\.environ\.get\(.+?\)',
        r'os\.getenv\(.+?\)'
    ]
}

# Database query execution sinks
SQL_SINKS = {
    "javascript": [
        {"pattern": r'db\.query\s*\(', "framework": "Node.js (pg / mysql)"},
        {"pattern": r'client\.query\s*\(', "framework": "Node.js (pg)"},
        {"pattern": r'pool\.query\s*\(', "framework": "Node.js (pg)"},
        {"pattern": r'sequelize\.query\s*\(', "framework": "Node.js (Sequelize)"},
        {"pattern": r'knex\.raw\s*\(', "framework": "Node.js (Knex)"},
        {"pattern": r'prisma\.\$queryRawUnsafe\s*\(', "framework": "Node.js (Prisma)"},
        {"pattern": r'sqlite3\.(all|get|run|each)\s*\(', "framework": "Node.js (sqlite3)"},
        {"pattern": r'db\.(all|get|run|each)\s*\(', "framework": "Node.js (sqlite3)"}
    ],
    "python": [
        {"pattern": r'cursor\.execute\s*\(', "framework": "Python (sqlite3 / psycopg2)"},
        {"pattern": r'connection\.execute\s*\(', "framework": "Python (DB-API / sqlite3)"},
        {"pattern": r'conn\.execute\s*\(', "framework": "Python (DB-API / sqlite3)"},
        {"pattern": r'db\.engine\.execute\s*\(', "framework": "Python (SQLAlchemy)"},
        {"pattern": r'session\.execute\s*\(\s*text\s*\(', "framework": "Python (SQLAlchemy text)"},
        {"pattern": r'sqlalchemy\.text\s*\(', "framework": "Python (SQLAlchemy text)"},
        {"pattern": r'\.raw\s*\(', "framework": "Python (Django RawSQL)"}
    ]
}

# Sanitizers and approved parameterized patterns
SAFE_SANITIZERS = [
    r'parseInt\s*\(',
    r'Number\s*\(',
    r'int\s*\(',
    r'float\s*\(',
    r'Math\.abs\s*\('
]

SAFE_PARAMETERIZED_PATTERNS = [
    r'db\.query\s*\(\s*["\'].*?\$[1-9].*?["\']\s*,\s*\[',
    r'client\.query\s*\(\s*["\'].*?\$[1-9].*?["\']\s*,\s*\[',
    r'cursor\.execute\s*\(\s*["\'].*?%s.*?["\']\s*,\s*\(',
    r'cursor\.execute\s*\(\s*["\'].*?\?.*?["\']\s*,\s*\(',
    r'cursor\.execute\s*\(\s*["\'].*?\?.*?["\']\s*,\s*\[',
    r'session\.execute\s*\(\s*text\s*\(["\'].*?:[a-zA-Z0-9_]+.*?["\']\)'
]
