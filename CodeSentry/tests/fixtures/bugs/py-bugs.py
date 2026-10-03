"""
Python Bug & Code Quality Issues
"""
import sys
from typing import List, Optional, Dict, Any

# ============ MUTABLE DEFAULT ARGUMENTS ============

def add_item(item, items=[]):  # VULNERABLE - mutable default
    items.append(item)
    return items

def add_to_dict(key, value, data={}):  # VULNERABLE - mutable default
    data[key] = value
    return data

def process_users(users, cache={}):  # VULNERABLE
    if users[0]['id'] in cache:
        return cache[users[0]['id']]
    cache[users[0]['id']] = users[0]
    return users[0]

# Better:
def add_item_safe(item, items=None):
    if items is None:
        items = []
    items.append(item)
    return items

# ============ BARE EXCEPT / SWALLOWED ERRORS ============

def risky_operation():
    try:
        return int("not a number")
    except:  # VULNERABLE - catches SystemExit, KeyboardInterrupt
        pass

def process_data(data):
    try:
        return data['key']
    except:  # VULNERABLE
        return None

def fetch_resource(url):
    try:
        import requests
        return requests.get(url).json()
    except Exception:  # Too broad
        return {}

# Better:
def fetch_resource_safe(url):
    try:
        import requests
        return requests.get(url).json()
    except requests.RequestException as e:
        print(f"Request failed: {e}")
        return {}
    except ValueError as e:
        print(f"JSON decode failed: {e}")
        return {}

# ============ UNINITIALIZED VARIABLES ============

def get_value(condition):
    if condition:
        result = "yes"
    # VULNERABLE - result may not be defined
    return result

def process_list(items):
    for item in items:
        if item > 10:
            found = item
    # VULNERABLE - found may not be defined
    return found

def calculate(x):
    if x > 0:
        return x
    elif x < 0:
        return -x
    # VULNERABLE - no return for x == 0

# ============ WRONG COMPARISON ============

def check_status(status):
    if status = "active":  # VULNERABLE - assignment instead of comparison
        return True
    return False

def compare_values(a, b):
    if a = b:  # VULNERABLE
        return True
    return False

# ============ OFF-BY-ONE ERRORS ============

def get_element(arr, index):
    # VULNERABLE - no bounds check
    return arr[index]

def sum_list(items):
    total = 0
    for i in range(len(items) + 1):  # VULNERABLE - index out of bounds
        total += items[i]
    return total

def process_array(data):
    results = []
    for i in range(len(data)):
        results.append(data[i + 1])  # VULNERABLE - i+1 may be out of bounds
    return results

# ============ IMPERFECT HASHING / COMPARISON ============

def compare_passwords(pwd1, pwd2):
    # VULNERABLE - not constant-time comparison
    return pwd1 == pwd2

def verify_token(token, expected):
    # VULNERABLE - timing attack
    if len(token) != len(expected):
        return False
    for i in range(len(token)):
        if token[i] != expected[i]:
            return False
    return True

# ============ RACE CONDITIONS ============

import threading

class UnsafeBankAccount:
    def __init__(self):
        self.balance = 0

    def deposit(self, amount):
        # VULNERABLE - race condition
        current = self.balance
        new_balance = current + amount
        self.balance = new_balance

    def withdraw(self, amount):
        # VULNERABLE - race condition
        if self.balance >= amount:
            self.balance -= amount
            return True
        return False

# ============ INCORRECT BOOLEAN LOGIC ============

def is_valid(age, name):
    # VULNERABLE - should be 'and' not 'or'
    if age > 18 or name:  # Always True if name is not empty
        return True
    return False

def check_permissions(user):
    # VULNERABLE - logic error
    if not user.is_admin or user.is_active:  # Allows non-admins
        return True
    return False

# ============ MISSING RETURN VALUE ============

def divide(a, b):
    if b != 0:
        result = a / b
    # VULNERABLE - no return when b == 0

def process_items(items):
    results = []
    for item in items:
        if item.is_valid():
            results.append(item.process())
    # VULNERABLE - no return statement

# ============ TYPE ERRORS ============

def concatenate(a, b):
    return a + b  # VULNERABLE - may fail if types don't match

def safe_concatenate(a: Any, b: Any) -> str:
    return str(a) + str(b)

def divide_numbers(a, b):
    return a / b  # VULNERABLE - ZeroDivisionError, TypeError

def safe_divide(a: float, b: float) -> Optional[float]:
    try:
        return a / b
    except (ZeroDivisionError, TypeError):
        return None

# ============ UNREACHABLE CODE ============

def get_status(code):
    if code == 200:
        return "OK"
    elif code == 404:
        return "Not Found"
    return "Unknown"
    print("This never executes")  # VULNERABLE

def process(data):
    return data
    x = expensive_computation(data)  # VULNERABLE - dead code

# ============ INCORRECT EXCEPTION HANDLING ============

def risky_function():
    try:
        return int("not a number")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error: {e}")
        raise  # Re-raises, may mask original

# ============ GLOBAL STATE MUTATION ============

counter = 0

def increment():
    global counter
    counter += 1  # VULNERABLE - not thread-safe

def get_counter():
    return counter

# ============ SHALLOW COPY ISSUES ============

def update_record(record, updates):
    # VULNERABLE - mutates original
    record.update(updates)
    return record

def safe_update_record(record: Dict, updates: Dict) -> Dict:
    # Better: return new dict
    return {**record, **updates}

if __name__ == '__main__':
    # Demonstrate mutable default argument bug
    list1 = add_item(1)
    list2 = add_item(2)
    print(f"list1: {list1}")  # [1, 2] - unexpected!
    print(f"list2: {list2}")  # [1, 2] - shares same list
