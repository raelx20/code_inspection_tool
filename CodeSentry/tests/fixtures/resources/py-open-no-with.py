def read_file(path):
    # File opened without 'with' statement
    f = open(path, 'r')
    content = f.read()
    return content
    # f.close() never called

def write_file(path, data):
    # Another file without 'with'
    f = open(path, 'w')
    f.write(data)
    # No close

def process_files(paths):
    results = []
    for p in paths:
        f = open(p, 'r')
        results.append(f.read())
    return results
