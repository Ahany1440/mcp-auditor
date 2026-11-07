import ast

SAFE_BUILTINS = {"len": len, "min": min, "max": max}


def validate(expr):
    for node in ast.walk(ast.parse(expr)):
        if not isinstance(node, (ast.Module, ast.Expr, ast.Assign, ast.Name, ast.Load, ast.Store, ast.Constant)):
            return False, f"{type(node).__name__} is not allowed"
    return True, ""


def run_transform(expr, data):
    ok, error = validate(expr)
    if not ok:
        raise ValueError(error)
    env = {"__builtins__": SAFE_BUILTINS}
    exec(expr, env, {"data": data})


def run_unchecked(expr, data):
    exec(expr, {"__builtins__": SAFE_BUILTINS}, {"data": data})


def run_checked_real_builtins(expr, data):
    if not validate(expr)[0]:
        raise ValueError("rejected")
    exec(expr, {"__builtins__": __builtins__}, {"data": data})


def run_length_only(expr):
    if len(expr) > 200:
        return None
    return eval(expr, {"__builtins__": {}})


def run_in_try(expr, data):
    valid, error = validate(expr)
    if not valid:
        raise ValueError(error)
    safe_globals = {"__builtins__": dict(SAFE_BUILTINS)}
    try:
        exec(expr, safe_globals, {"data": data})
    except Exception as e:
        raise ValueError(str(e)) from e


def run_other_checked(expr, data, other):
    ok, error = validate(other)
    if not ok:
        raise ValueError(error)
    exec(expr, {"__builtins__": SAFE_BUILTINS}, {"data": data})


def run_check_after(expr, data):
    exec(expr, {"__builtins__": SAFE_BUILTINS}, {"data": data})
    if not validate(expr)[0]:
        raise ValueError("rejected")


def run_check_in_branch(expr, data, strict):
    if strict:
        if not validate(expr)[0]:
            raise ValueError("rejected")
    exec(expr, {"__builtins__": SAFE_BUILTINS}, {"data": data})


def run_reassigned(expr, data, extra):
    if not validate(expr)[0]:
        raise ValueError("rejected")
    expr = expr + extra
    exec(expr, {"__builtins__": SAFE_BUILTINS}, {"data": data})


def run_result_overwritten(expr, data):
    ok, error = validate(expr)
    ok = True
    if not ok:
        raise ValueError(error)
    exec(expr, {"__builtins__": SAFE_BUILTINS}, {"data": data})


def run_check_does_not_stop(expr, data):
    if not validate(expr)[0]:
        print("rejected")
    exec(expr, {"__builtins__": SAFE_BUILTINS}, {"data": data})


def run_check_in_nested_def(expr, data):
    def guard():
        if not validate(expr)[0]:
            raise ValueError("rejected")
    exec(expr, {"__builtins__": SAFE_BUILTINS}, {"data": data})


def run_builtins_restored(expr, data):
    if not validate(expr)[0]:
        raise ValueError("rejected")
    env = {"__builtins__": SAFE_BUILTINS}
    env["__builtins__"] = __builtins__
    exec(expr, env, {"data": data})


def run_check_in_handler(expr, data):
    try:
        pass
    except ValueError:
        if not validate(expr)[0]:
            raise
    exec(expr, {"__builtins__": SAFE_BUILTINS}, {"data": data})
