"""
Python Efficiency & Performance Issues
"""
import os
import json
import time
import re
import sqlite3
from typing import List, Dict, Any

# ============ O(n²) PATTERNS ============

def find_common_elements_slow(list1: List, list2: List) -> List:
    """O(n²) - nested loops for finding common elements"""
    common = []
    for item in list1:  # O(n)
        for other in list2:  # O(n) = O(n²)
            if item == other:
                common.append(item)
    return common

def find_duplicates_slow(items: List) -> List:
    """O(n²) - checking membership in list"""
    duplicates = []
    for i, item in enumerate(items):
        for j, other in enumerate(items):
            if i != j and item == other:
                if item not in duplicates:
                    duplicates.append(item)
    return duplicates

def remove_duplicates_slow(items: List) -> List:
    """O(n²) - using 'in' on list"""
    result = []
    for item in items:
        if item not in result:  # O(n) check each time
            result.append(item)
    return result

# Better: O(n) with set
def find_common_elements_fast(list1: List, list2: List) -> List:
    set2 = set(list2)
    return [item for item in list1 if item in set2]

def remove_duplicates_fast(items: List) -> List:
    return list(dict.fromkeys(items))  # Preserves order, O(n)

# ============ STRING CONCATENATION IN LOOP ============

def build_csv_slow(rows: List[List]) -> str:
    """Inefficient string concatenation"""
    csv = ''
    for row in rows:
        csv += ','.join(row) + '\n'  # Creates new string each iteration
    return csv

def build_html_slow(items: List[Dict]) -> str:
    """Inefficient string concatenation"""
    html = '<ul>'
    for item in items:
        html += f'<li>{item["name"]}</li>'  # O(n²) time
    html += '</ul>'
    return html

# Better: join or io.StringIO
def build_csv_fast(rows: List[List]) -> str:
    return '\n'.join(','.join(row) for row in rows)

def build_html_fast(items: List[Dict]) -> str:
    parts = ['<ul>']
    parts.extend(f'<li>{item["name"]}</li>' for item in items)
    parts.append('</ul>')
    return ''.join(parts)

# ============ UNNECESSARY OPERATIONS IN LOOP ============

def validate_emails_slow(emails: List[str]) -> List[str]:
    """Regex compiled inside loop"""
    valid = []
    for email in emails:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if re.match(pattern, email):  # Recompiles each iteration
            valid.append(email)
    return valid

def process_data_slow(data: List[Dict]) -> List:
    """Unnecessary operations repeated"""
    results = []
    for item in data:
        # Repeatedly creates same object
        timestamp = time.time()  # Called for every item
        item['processed_at'] = timestamp
        results.append(item)
    return results

# Better: compile once, optimize
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')

def validate_emails_fast(emails: List[str]) -> List[str]:
    return [email for email in emails if EMAIL_REGEX.match(email)]

# ============ UNNECESSARY LIST COPIES ============

def get_active_users_slow(users: List[Dict]) -> List[Dict]:
    """Creates unnecessary intermediate list"""
    return [u for u in users if u['active'] == True]  # Redundant == True

def process_items_slow(items: List) -> List:
    """Unnecessary list copy"""
    return [item for item in items]  # Just copies the list

# Better: filter or direct access
def get_active_users_fast(users: List[Dict]) -> List[Dict]:
    return [u for u in users if u['active']]  # Direct boolean check

# ============ REPEATED ARRAY TRAVERSALS ============

def analyze_data_slow(data: List[Dict]) -> Dict:
    """Multiple traversals of same data"""
    total = sum(d['amount'] for d in data)       # Traversal 1
    avg = total / len(data)                        # Traversal 2 (len is fast)
    max_val = max(d['amount'] for d in data)      # Traversal 3
    min_val = min(d['amount'] for d in data)      # Traversal 4
    count = len([d for d in data if d['amount'] > avg])  # Traversal 5

    return {'avg': avg, 'max': max_val, 'min': min_val, 'count_above_avg': count}

# Better: single pass
def analyze_data_fast(data: List[Dict]) -> Dict:
    total = 0
    max_val = float('-inf')
    min_val = float('inf')
    count_above_avg = 0

    for d in data:
        amount = d['amount']
        total += amount
        max_val = max(max_val, amount)
        min_val = min(min_val, amount)

    avg = total / len(data)

    for d in data:
        if d['amount'] > avg:
            count_above_avg += 1

    return {'avg': avg, 'max': max_val, 'min': min_val, 'count_above_avg': count_above_avg}

# ============ INEFFICIENT DATA STRUCTURES ============

class SlowQueue:
    """Inefficient queue using list"""
    def __init__(self):
        self.items = []

    def enqueue(self, item):
        self.items.append(item)

    def dequeue(self):
        return self.items.pop(0)  # O(n) - shifts all elements

class FastQueue:
    """Efficient queue using deque"""
    from collections import deque

    def __init__(self):
        self.items = self.deque()

    def enqueue(self, item):
        self.items.append(item)

    def dequeue(self):
        return self.items.popleft()  # O(1)

def lookup_in_list(items: List, target) -> bool:
    """O(n) lookup in list"""
    return target in items  # O(n)

def lookup_in_set(items: set, target) -> bool:
    """O(1) lookup in set"""
    return target in items  # O(1)

# ============ BLOCKING I/O IN LOOP ============

def read_files_slow(file_paths: List[str]) -> List[str]:
    """Synchronous file reading in loop"""
    contents = []
    for path in file_paths:
        with open(path, 'r') as f:
            contents.append(f.read())  # Blocks for each file
    return contents

# Better: async or batch processing
async def read_files_fast(file_paths: List[str]) -> List[str]:
    """Async file reading"""
    import aiofiles
    contents = []
    for path in file_paths:
        async with aiofiles.open(path, 'r') as f:
            contents.append(await f.read())
    return contents

# ============ UNNECESSARY FUNCTION CALLS ============

def process_items_with_function_call(items: List) -> List:
    """Calling len() repeatedly"""
    results = []
    i = 0
    while i < len(items):  # len() called each iteration
        results.append(items[i] * 2)
        i += 1
    return results

# Better: cache length
def process_items_optimized(items: List) -> List:
    results = []
    length = len(items)  # Calculate once
    i = 0
    while i < length:
        results.append(items[i] * 2)
        i += 1
    return results

# ============ INEFFICIENT DICTIONARY ACCESS ============

def count_words_slow(text: str) -> Dict[str, int]:
    """Using dict.get() in loop"""
    words = text.lower().split()
    counts = {}
    for word in words:
        counts[word] = counts.get(word, 0) + 1  # dict.get() is slower
    return counts

# Better: use collections.Counter
from collections import Counter

def count_words_fast(text: str) -> Dict[str, int]:
    return dict(Counter(text.lower().split()))

# ============ REGEX IN LOOP ============

def find_patterns_slow(texts: List[str], pattern: str) -> List[str]:
    """Compiling regex each iteration"""
    matches = []
    for text in texts:
        if re.match(pattern, text):  # Recompiles each time
            matches.append(text)
    return matches

def find_patterns_fast(texts: List[str], pattern: str) -> List[str]:
    compiled = re.compile(pattern)  # Compile once
    return [text for text in texts if compiled.match(text)]

# ============ UNNECESSARY OBJECT CREATION ============

def create_objects_slow(n: int) -> List[Dict]:
    """Creating objects in loop"""
    objects = []
    for i in range(n):
        obj = {  # New dict created each iteration
            'id': i,
            'value': i * 2
        }
        objects.append(obj)
    return objects

def create_objects_fast(n: int) -> List[Dict]:
    """Using list comprehension"""
    return [{'id': i, 'value': i * 2} for i in range(n)]

# ============ BLOCKING OPERATIONS ============

def fibonacci_slow(n: int) -> int:
    """Recursive without memoization - exponential time"""
    if n <= 1:
        return n
    return fibonacci_slow(n - 1) + fibonacci_slow(n - 2)

# Better: memoized
from functools import lru_cache

@lru_cache(maxsize=None)
def fibonacci_fast(n: int) -> int:
    if n <= 1:
        return n
    return fibonacci_fast(n - 1) + fibonacci_fast(n - 2)

if __name__ == '__main__':
    # Benchmark demonstrations
    print("Testing inefficiency fixtures...")

    import random
    data = [{'amount': random.randint(1, 1000)} for _ in range(10000)]
    items = list(range(1000))

    start = time.time()
    find_common_elements_slow(items, items)
    slow_time = time.time() - start

    start = time.time()
    find_common_elements_fast(items, items)
    fast_time = time.time() - start

    print(f"Slow: {slow_time:.4f}s, Fast: {fast_time:.4f}s")
