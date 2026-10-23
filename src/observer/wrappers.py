"""Conservative static recognition of one exec wrapper grammar; never evaluate JS."""
import json
import re

def visible_wrapper(code, redactor=None):
    # Only one literal exec_command call, optional binding, and a text sink.
    direct = re.fullmatch(r"\s*text\(await tools\.exec_command\((\{.*\})\)\);?\s*", code, re.S)
    bound = re.fullmatch(r"\s*(?:const|let) ([A-Za-z_][A-Za-z0-9_]*) = await tools\.exec_command\((\{.*\})\);\s*text\(\1(?:\.output)?\);?\s*", code, re.S)
    literal = direct[1] if direct else bound[2] if bound else None
    if literal is None:
        return None
    # Lexically quote bare object keys; JSON string tokens are left intact.
    tokens, index = [], 0
    pattern = re.compile(r'\s*("(?:\\.|[^"\\])*"|[A-Za-z_][A-Za-z0-9_]*|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?|[{}:,])')
    while index < len(literal):
        match = pattern.match(literal, index)
        if not match:
            return None
        tokens.append(match[1])
        index = match.end()
    for i, token in enumerate(tokens[:-1]):
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token) and tokens[i + 1] == ":":
            tokens[i] = json.dumps(token)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result
    try:
        args = json.loads("".join(tokens), object_pairs_hook=unique)
    except (ValueError, RecursionError):
        return None
    allowed = {"cmd": str, "workdir": str, "shell": str, "login": bool,
               "max_output_tokens": int, "yield_time_ms": int, "tty": bool}
    if not isinstance(args, dict) or "cmd" not in args or set(args) - set(allowed):
        return None
    if any(type(v) is not allowed[k] for k, v in args.items()):
        return None
    if redactor is not None:
        args = redactor.clean(args)
    return "text(await tools.exec_command(" + json.dumps(args, ensure_ascii=False, separators=(",", ":")) + "));"
