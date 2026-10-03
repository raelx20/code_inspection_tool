"""
Python Resource Leaks & Efficiency Issues
"""
import os
import sqlite3
import threading
import requests
from collections import defaultdict

# ============ FILE HANDLING WITHOUT WITH ============

def read_file_bad(filename):
    # Resource Leak: no 'with' statement
    f = open(filename, 'r')  # VULNERABLE
    content = f.read()
    return content
    # f.close() never called on exception

def write_file_bad(filename, data):
    # Resource Leak: manual close without finally
    f = open(filename, 'w')
    f.write(data)
    f.close()  # VULNERABLE - not called if write fails

def read_multiple_files(files):
    # Resource Leak: multiple files without with
    contents = []
    for file in files:
        f = open(file, 'r')  # VULNERABLE
        contents.append(f.read())
    return contents

def process_files():
    # Resource Leak: exception skips close
    f = open('data.txt', 'r')  # VULNERABLE
    data = f.read()
    result = int(data)  # May raise ValueError
    f.close()
    return result

# ============ DATABASE CONNECTIONS ============

def get_user_bad(user_id):
    # Resource Leak: connection not closed on error
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
    result = cursor.fetchone()
    conn.close()  # VULNERABLE - not called if query fails
    return result

def get_users_bulk():
    # Resource Leak: connection pool exhaustion
    connections = []
    for i in range(100):
        conn = sqlite3.connect('users.db')  # VULNERABLE - creates many connections
        connections.append(conn)
    return connections

class UserRepository:
    def __init__(self):
        self.conn = sqlite3.connect('users.db')
        # Connection never closed

    def find(self, user_id):
        return self.conn.execute(
            "SELECT * FROM users WHERE id=?", (user_id,)
        ).fetchone()

# ============ MEMORY LEAKS ============

class DataCache:
    def __init__(self):
        self.cache = {}  # VULNERABLE - no size limit, no eviction

    def set(self, key, value):
        self.cache[key] = value

    def get(self, key):
        return self.cache.get(key)

class EventTracker:
    def __init__(self):
        self.events = []  # VULNERABLE - grows indefinitely

    def track(self, event):
        self.events.append({
            'type': event,
            'timestamp': __import__('time').time()
        })

    def get_events(self):
        return self.events

# Global cache that grows unbounded
_global_cache = defaultdict(list)

def add_to_cache(key, value):
    _global_cache[key].append(value)  # VULNERABLE - never cleaned

# ============ THREAD SAFETY ISSUES ============

counter = 0

def increment_counter():
    global counter
    for _ in range(1000):
        counter += 1  # VULNERABLE - race condition

class UnsafeCounter:
    def __init__(self):
        self.count = 0

    def increment(self):
        self.count += 1  # VULNERABLE - not thread-safe

class ThreadSafeCounter:
    def __init__(self):
        self.count = 0
        self.lock = threading.Lock()

    def increment(self):
        with self.lock:
            self.count += 1  # SAFE

# ============ HTTP WITHOUT TIMEOUT ============

def fetch_data(url):
    # Timeout issue: hangs forever
    response = requests.get(url)  # VULNERABLE - no timeout
    return response.json()

def fetch_with_timeout(url):
    # Better: explicit timeout
    response = requests.get(url, timeout=30)
    return response.json()

def fetch_multiple(urls):
    # Resource leak: connections not properly managed
    results = []
    for url in urls:
        resp = requests.get(url)  # VULNERABLE
        results.append(resp.json())
    return results

# ============ REGEX ISSUES ============

import re

# Compiled regex in loop (inefficient)
def validate_emails(emails):
    valid = []
    for email in emails:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(pattern, email):  # VULNERABLE - recompiles each iteration
            valid.append(email)
    return valid

# ReDoS vulnerable pattern
def validate_complex_input(text):
    # Vulnerable regex: catastrophic backtracking
    pattern = r'^([a-zA-Z0-9]+)*$'  # VULNERABLE
    return bool(re.match(pattern, text))

# Better: compile once
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

def validate_emails_optimized(emails):
    return [e for e in emails if EMAIL_REGEX.match(e)]

# ============ STRING CONCATENATION IN LOOP ============

def build_log_bad(entries):
    log = ''
    for entry in entries:
        log += str(entry) + '\n'  # VULNERABLE - creates new string each iteration
    return log

def build_log_good(entries):
    # Better: use list and join
    parts = []
    for entry in entries:
        parts.append(str(entry))
    return '\n'.join(parts)

# ============ SYNC IN ASYNC CONTEXT ============

import json

def load_config_sync():
    # Blocking I/O in potentially async context
    with open('config.json', 'r') as f:
        return json.load(f)  # VULNERABLE - blocks event loop if async

def process_files_sync(files):
    results = []
    for f in files:
        with open(f, 'r') as fh:
            results.append(json.load(fh))  # VULNERABLE - sync I/O in loop
    return results

# ============ UNNECESSARY OBJECT CREATION ============

def process_data(data):
    results = []
    for item in data:
        # Creates new regex each iteration
        if re.match(r'^\d+$', str(item)):  # VULNERABLE
            results.append(int(item))
    return results

# ============ LARGE OBJECT IN MEMORY ============

def read_large_file(filename):
    # Loads entire file into memory
    with open(filename, 'r') as f:
        return f.read()  # VULNERABLE - for large files

def process_large_file(filename):
    # Better: stream processing
    with open(filename, 'r') as f:
        for line in f:
            yield line.strip()

if __name__ == '__main__':
    # Test cases
    print("Testing resource leak fixtures...")
    try:
        read_file_bad('nonexistent.txt')
    except FileNotFoundError:
        print("Expected error caught")
