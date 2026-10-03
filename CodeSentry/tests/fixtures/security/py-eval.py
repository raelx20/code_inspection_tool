from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/eval', methods=['POST'])
def eval_expression():
    expr = request.json.get('expr')
    # Unsafe eval: executes arbitrary user code
    result = eval(expr)
    return jsonify({"result": result})

@app.route('/exec', methods=['POST'])
def exec_code():
    code = request.json.get('code')
    # Unsafe exec: executes arbitrary code
    exec(code)
    return jsonify({"success": True})

@app.route('/compile', methods=['POST'])
def compile_code():
    expression = request.json.get('expression')
    # Compile with eval
    compiled = compile(expression, '<string>', 'eval')
    result = eval(compiled)
    return jsonify({"result": result})
