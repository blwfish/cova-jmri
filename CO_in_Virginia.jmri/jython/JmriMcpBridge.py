# JmriMcpBridge.py -- embedded HTTP listener for jmri-mcp
# (https://github.com/blwfish/jmri-mcp), run as a PerformScriptModelXml
# startup action inside JMRI's own JVM. Opens a plain JDK HttpServer (no
# external library, no MQTT broker) and executes submitted Jython via
# jmri.script.JmriScriptEngineManager, returning stdout/result/traceback
# as the synchronous HTTP response body.
#
# STATUS: wired into the CO_in_Virginia.jmri test-rig profile.xml's
# <startup> block, third entry, enabled="yes" -- see jmri-mcp's design
# spec, Next Steps 2-4. Live-testing in progress; some JMRI-API calls
# below are still best-effort/TESTME pending confirmation against a real
# submitted script (particularly: does JmriScriptEngineManager expose
# getEngineByName, and under what name).
#
# Carries forward jmri_throttle_bridge.py's conventions (confirmed during
# the spec review pass): request_id correlation, reject-and-continue
# rather than crash on a malformed request, explicit validation before
# acting -- not its MQTT transport.

import ast
import json
import os
import re
import traceback as _traceback

import jarray
from java.io import ByteArrayOutputStream, PrintWriter, StringWriter
from java.lang import String as JString
from java.lang import System, Throwable
from java.net import InetSocketAddress
from java.security import SecureRandom
from com.sun.net.httpserver import HttpHandler, HttpServer

from jmri.script import JmriScriptEngineManager
from jmri.util import FileUtil

# --- Configuration -----------------------------------------------------
# Loopback-only default: this profile is the local test rig (see
# jmri-mcp's AskUserQuestion exchange confirming pid 7959's simulator/
# loopback connections are safe to use as the test rig). NEVER 0.0.0.0.
# For a real remote instance (the live Mini), this becomes that host's
# specific LAN interface -- never 0.0.0.0 there either, per the spec's
# Security paragraph.
BIND_HOST = "127.0.0.1"
BIND_PORT = 2059

# Generated on first run, stored alongside this script, re-read (not
# cached at import time) so redeploying this file rotates the token --
# matches freecad-mcp's Windows-fallback shape (TCP + shared-secret
# token), except here the token is the primary mechanism, not a fallback.
#
# __file__ is NOT available here -- confirmed empirically: JMRI's
# PerformScriptModel runs this script's text through
# JmriScriptEngineManager.eval() rather than a file-load path that would
# bind __file__, so referencing it raised NameError and crashed the
# whole startup action before the HTTP server ever came up. Use JMRI's
# own path-alias resolver instead (the same "preference:" mechanism that
# already resolved this script's own path in profile.xml) -- portable
# across users/deployments, not hardcoded to one machine.
TOKEN_PATH = FileUtil.getDefault().getExternalFilename("preference:jython/bridge_token.txt")


def _get_or_create_token():
    if os.path.exists(TOKEN_PATH):
        with open(TOKEN_PATH, "r") as f:
            token = f.read().strip()
            if token:
                return token
    rng = SecureRandom()
    # A Python bytearray does NOT get mutated in place by a Java method
    # expecting byte[] -- confirmed empirically (it silently produced all
    # zeros). jarray.zeros gives a genuine Java byte[] that nextBytes can
    # actually fill.
    raw = jarray.zeros(24, "b")
    rng.nextBytes(raw)
    token = "".join("%02x" % (b & 0xFF) for b in raw)
    with open(TOKEN_PATH, "w") as f:
        f.write(token)
    os.chmod(TOKEN_PATH, 0o600)
    print("JmriMcpBridge: generated new bearer token at %s" % TOKEN_PATH)
    return token


_TOKEN = _get_or_create_token()


# --- Request handling ---------------------------------------------------

def _read_body(exchange):
    """Reads the full request body as a unicode string. Uses a genuine
    Java byte[] (jarray) plus ByteArrayOutputStream, not a Python
    bytearray -- confirmed empirically (see the token-generation fix
    above) that InputStream.read(byte[]) does not mutate a Python
    bytearray in place through Jython's Java interop; it silently reads
    into a discarded copy, leaving the body empty/garbled."""
    stream = exchange.getRequestBody()
    out = ByteArrayOutputStream()
    buf = jarray.zeros(4096, "b")
    while True:
        n = stream.read(buf)
        if n == -1:
            break
        out.write(buf, 0, n)
    stream.close()
    return unicode(JString(out.toByteArray(), "UTF-8"))


def _send_json(exchange, status, obj):
    body = json.dumps(obj).encode("utf-8")
    exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8")
    exchange.sendResponseHeaders(status, len(body))
    out = exchange.getResponseBody()
    out.write(body)
    out.close()


def _check_auth(exchange):
    """Returns True iff the request carries the correct bearer token.
    Checked BEFORE any request-body parsing or script execution -- per
    the spec's own Unknown item, the token check must happen first, not
    after."""
    headers = exchange.getRequestHeaders()
    values = headers.get("Authorization")
    if not values:
        return False
    auth = values.get(0)
    if not auth or not auth.startswith("Bearer "):
        return False
    return auth[len("Bearer "):] == _TOKEN


def _split_last_expression(script):
    """jmri-mcp issue #6: ScriptEngine.eval() only ever returns a value
    for a script that's a SINGLE bare expression -- a multi-statement
    script (even one ending in a legitimate bare expression) otherwise
    always gets `result: None`, with no way to tell that apart from "the
    script genuinely produced nothing." Real REPL behavior -- exec every
    statement but the last, then, if the last one is a bare expression,
    eval() just that -- recovers the value without changing what the
    script actually does.

    Uses `ast.parse`, not a text/line split, to find the boundary: a
    naive split on the last newline would misfire on a multi-line final
    statement, a statement containing a multi-line string, or any
    statement before it that happens to look like a boundary in raw text
    (Syntactic-Semantic Seam Rule -- a semantic distinction like
    "statement boundary" needs a real parse, not a syntactic stand-in).
    Only the ast.parse() call and the AST shape decide whether/where to
    split; the actual text sent to manager.eval() for both halves is
    always a verbatim slice of the original script, so what actually
    *runs* is never affected by anything this function gets wrong -- at
    worst it fails to split and behavior falls back to today's
    single-eval-call semantics (see the three `return None, script`
    fallbacks below, all deliberately conservative rather than guessing).

    CONFIRMED live against the real test-rig JVM (2026-09-27): `x = 5\\nx+1`
    -> 6, the real `jmri.InstanceManager.getDefault(...LogixNG_Manager)\\n
    ...getNamedBeanSet().size()` two-liner from the issue -> a real int,
    `a=1\\nb=2\\na+b` -> 3, a `print()` line ahead of the split point still
    lands in `stdout`, a bare single expression is still a single
    manager.eval() call (unchanged), an assignment-only script still
    correctly returns None, the semicolon-joined fallback (`x = 1; x + 1`)
    correctly declines to split, and an exception raised in either half
    still returns a `traceback` with whatever `stdout` was captured before
    the raise -- see tests/test_split_last_expression.py for the
    unit-level split-boundary coverage this doesn't re-run against a JVM."""
    try:
        tree = ast.parse(script)
    except SyntaxError:
        return None, script
    body = tree.body
    if not body or not isinstance(body[-1], ast.Expr):
        return None, script
    if len(body) == 1:
        return None, script
    prev, last = body[-2], body[-1]
    if getattr(prev, "lineno", None) == last.lineno:
        # Semicolon-joined statements sharing the final line (`x = 1;
        # x + 1`) -- a line-based split can't separate these safely.
        return None, script
    lines = script.splitlines(True)
    split_at = last.lineno - 1
    exec_part = "".join(lines[:split_at])
    eval_part = "".join(lines[split_at:])
    return (exec_part if exec_part.strip() else None), eval_part


def _run_jython(script):
    """CONFIRMED live against the real JVM: getEngineByName("python") is
    the correct registered name -- a plain successful script round-trips
    stdout/result correctly.

    except (Exception, Throwable), not except Exception alone: confirmed
    empirically that a script exception propagating out of a NESTED
    manager.eval() call surfaces as a genuine java.lang.Throwable
    (javax.script.ScriptException specifically) that Jython's `except
    Exception` -- and even `except BaseException` -- does NOT match here;
    it silently falls through both, killing the request with no response
    and no log output at all (empty-reply-from-server, reproduced and
    confirmed against the real bridge before this fix). Only catching the
    concrete Java type, java.lang.Throwable, or a bare `except:` catches
    it. A native Python error (e.g. ZeroDivisionError raised directly,
    not through a nested eval) is the opposite case -- Throwable alone
    does NOT catch that. The combined tuple is required for both.

    _split_last_expression's exec/eval split (jmri-mcp issue #6) reuses
    this SAME `engine` instance for both manager.eval() calls -- a
    ScriptEngine's default Bindings persist across separate eval() calls
    on one engine instance (javax.script spec), so a variable the exec
    half assigns is visible to the eval half, the same way two REPL
    lines share state. If splitting the script itself raises anything,
    fall back to the original single-eval-call behavior rather than
    letting a bug in the split machinery break a script that would have
    worked fine unsplit."""
    manager = JmriScriptEngineManager.getDefault()
    engine = manager.getEngineByName("python")
    sw = StringWriter()
    writer = PrintWriter(sw)
    engine.getContext().setWriter(writer)
    engine.getContext().setErrorWriter(writer)
    try:
        try:
            exec_part, eval_part = _split_last_expression(script)
        except (Exception, Throwable):
            exec_part, eval_part = None, script
        if exec_part:
            manager.eval(exec_part, engine)
        result = manager.eval(eval_part, engine)
        writer.flush()
        return {"stdout": sw.toString(), "result": _jsonable(result)}
    except (Exception, Throwable) as exc:
        writer.flush()
        try:
            detail = "%s: %s" % (type(exc).__name__, exc)
        except (Exception, Throwable):
            detail = "<could not format exception>"
        try:
            detail += "\n" + _traceback.format_exc()
        except (Exception, Throwable):
            pass
        return {"stdout": sw.toString(), "traceback": detail}


def _jsonable(value):
    """Best-effort coercion of a Jython eval() return value to something
    json.dumps can serialize -- a bare Java object (not a Python-native
    str/int/list/dict) falls back to str(value) rather than raising.
    TESTME: what eval() actually returns for a typical script (None most
    of the time, since JMRI scripts are usually run for side effects) is
    unconfirmed until real scripts are run against this."""
    if value is None or isinstance(value, (bool, int, float, str, list, dict)):
        return value
    try:
        json.dumps(value)
        return value
    except TypeError:
        return str(value)


def _describe_class(class_name):
    """Live Java reflection -- retires the javap-on-jmri.jar workaround.
    Pure java.lang.Class/reflect calls, no ScriptEngine involved, so this
    doesn't share _run_jython's engine-lookup uncertainty above. Highest
    confidence, lowest risk of the operations here (spec Next Steps #6:
    "wire describe_class early"). Live-tested against
    jmri.implementation.MatrixSignalMast on the real JVM; confirms
    setBitsForAspect(String, char[]) -- the exact Unknown this project
    exists to resolve."""
    from java.lang import Class

    cls = Class.forName(class_name)

    def fmt(t):
        # Class.getName(t), NOT t.getName() -- confirmed empirically that
        # Jython auto-boxes a Class instance representing a JDK-wrapped
        # type (e.g. java.lang.String) into a Python `type` object rather
        # than leaving it a plain Class instance, at which point
        # t.getName() resolves to the UNBOUND Class.getName and raises
        # "TypeError: getName(): expected 1 args; got 0". Calling it
        # unbound-style with the instance passed explicitly sidesteps
        # the ambiguity regardless of which way Jython boxed it.
        return Class.getName(t)

    # Reporting the raw JVM modifier bitmask (java.lang.reflect.Modifier's
    # own constants: PUBLIC=1, PRIVATE=2, PROTECTED=4, STATIC=8, FINAL=16,
    # ...) rather than Modifier.toString(int)'s human string --
    # Modifier.toString(1) returned the literal string "1" here, not
    # "public", for reasons not yet understood (same family of Jython
    # overload-resolution surprise as the getName() issue above, but not
    # chased further since it isn't load-bearing for what this tool is
    # for). The bitmask is standard JVM spec, not JMRI-specific, and
    # fully decodable by whoever/whatever reads this response.
    constructors = [
        {
            "modifiers": c.getModifiers(),
            "params": [fmt(p) for p in c.getParameterTypes()],
        }
        for c in cls.getDeclaredConstructors()
    ]
    methods = [
        {
            "name": m.getName(),
            "modifiers": m.getModifiers(),
            "params": [fmt(p) for p in m.getParameterTypes()],
            "returns": fmt(m.getReturnType()),
        }
        for m in cls.getDeclaredMethods()
    ]
    superclass = cls.getSuperclass()
    return {
        "class": class_name,
        "superclass": fmt(superclass) if superclass else None,
        "interfaces": [fmt(i) for i in cls.getInterfaces()],
        "constructors": constructors,
        "methods": methods,
    }


# JmriMcpBridgeOps.py holds every JMRI-domain operation handler --
# split out so this file stays well under Jython's ~100,000-
# character ScriptEngine parse ceiling (see JmriMcpBridgeOps.py's
# own header, and AGENT-INSTALL.md's Critical Rules). __file__ is
# NOT available here (see TOKEN_PATH above) -- resolve this
# script's own directory the same way, so the import works
# regardless of deployment path.
import sys
_ops_dir = FileUtil.getDefault().getExternalFilename("preference:jython")
if _ops_dir not in sys.path:
    sys.path.insert(0, _ops_dir)
import JmriMcpBridgeOps as ops



# Structured (tool, operation, target_type) tuples this bridge actually
# implements -- target_type is None for every tool except jmri_authoring,
# which is the only one with that extra dimension (see _handle's own
# comment). Everything else -- jmri_authoring's preference target_type
# (see that section's own comment above for why) -- returns a clear "not
# yet implemented" error rather than a fabricated JMRI API call I'm not
# confident about. See jmri-mcp's TOOLS.md status legend; these get filled
# in incrementally, each validated against this live instance before being
# trusted.
_STRUCTURED_OPS = {
    ("jmri_introspect", "describe_class", None): lambda payload: _describe_class(payload["class_name"]),
    ("jmri_introspect", "get_panel_structure", None): ops._get_panel_structure,
    ("jmri_introspect", "get_block_boundaries", None): ops._get_block_boundaries,
    ("jmri_introspect", "list_signal_masts", None): ops._list_signal_masts,
    ("jmri_introspect", "list_signal_mast_logic", None): ops._list_signal_mast_logic,
    ("jmri_introspect", "list_sections", None): ops._list_sections,
    ("jmri_introspect", "list_transits", None): ops._list_transits,
    ("jmri_introspect", "get_section", None): ops._introspect_get_section,
    ("jmri_introspect", "get_transit", None): ops._introspect_get_transit,
    ("jmri_logixng", "list", None): ops._logixng_list,
    ("jmri_logixng", "get", None): ops._logixng_get,
    ("jmri_logixng", "audit", None): ops._logixng_audit,
    ("jmri_logixng", "create", None): ops._logixng_create,
    ("jmri_logixng", "enable", None): ops._logixng_enable,
    ("jmri_logixng", "disable", None): ops._logixng_disable,
    ("jmri_authoring", "create", "signalMast"): ops._authoring_create_signal_mast,
    ("jmri_authoring", "create", "signalHead"): ops._authoring_create_signal_head,
    ("jmri_authoring", "create", "block"): ops._authoring_create_block,
    ("jmri_authoring", "create", "section"): ops._authoring_create_section,
    ("jmri_authoring", "create", "transit"): ops._authoring_create_transit,
    ("jmri_authoring", "setState", "section"): ops._authoring_set_section_state,
    ("jmri_authoring", "delete", "section"): ops._authoring_delete_section,
    ("jmri_authoring", "delete", "transit"): ops._authoring_delete_transit,
    ("jmri_authoring", "create", "testOval"): ops._authoring_create_test_oval,
    ("jmri_authoring", "create", "testDoubleOval"): ops._authoring_create_test_double_oval,
    ("jmri_authoring", "discover", "connection"): ops._authoring_connection_discover,
    ("jmri_authoring", "generateSections", "connection"): ops._authoring_connection_generate_sections,
    ("jmri_logs", "tail", None): ops._jmri_logs_tail,
    ("jmri_logs", "grep", None): ops._jmri_logs_grep,
    ("jmri_logs", "get_last_error", None): ops._jmri_logs_get_last_error,
}


class BridgeHandler(HttpHandler):
    def handle(self, exchange):
        # Defensive: the whole handler is wrapped so an unexpected
        # exception here (not just a submitted-script exception, which
        # _run_jython already catches) reports as a clean 500 instead of
        # propagating into HttpServer's own thread pool. CONFIRMED live:
        # `except Exception` alone is NOT sufficient here -- a Java
        # exception surfacing from a nested script eval silently falls
        # through it (see _run_jython's docstring); this outer net needs
        # the same (Exception, Throwable) catch to actually be a net.
        # Still TESTME: a genuine JVM Error (StackOverflowError,
        # OutOfMemoryError) rather than a Throwable subclass reachable
        # this way -- not yet deliberately triggered.
        try:
            self._handle(exchange)
        except (Exception, Throwable) as exc:
            try:
                _send_json(exchange, 500, {"error": "internal bridge error: %s" % exc})
            except (Exception, Throwable):
                pass
        finally:
            exchange.close()

    def _handle(self, exchange):
        if exchange.getRequestMethod() != "POST":
            _send_json(exchange, 405, {"error": "only POST is supported"})
            return

        if not _check_auth(exchange):
            _send_json(exchange, 401, {"error": "missing or invalid bearer token"})
            return

        try:
            raw_body = _read_body(exchange)
            payload = json.loads(raw_body)
        except (ValueError, UnicodeDecodeError) as exc:
            _send_json(exchange, 400, {"error": "malformed request body: %s" % exc})
            return

        request_id = payload.get("request_id", "")

        if "script" in payload:
            outcome = _run_jython(payload["script"])
            _send_json(exchange, 200, dict(request_id=request_id, **outcome))
            return

        tool = payload.get("tool")
        operation = payload.get("operation")
        # jmri_authoring is the one structured tool with a third dispatch
        # dimension (target_type) -- every other tool's payload simply
        # omits it, so payload.get() defaults to None, which is also what
        # _STRUCTURED_OPS' keys use for those tools (see its own comment).
        target_type = payload.get("target_type")
        handler_fn = _STRUCTURED_OPS.get((tool, operation, target_type))
        if handler_fn is None:
            label = "%s.%s" % (tool, operation)
            if target_type is not None:
                label += "(target_type=%s)" % target_type
            _send_json(exchange, 501, {
                "request_id": request_id,
                "error": "operation '%s' not yet implemented on the bridge" % label,
            })
            return

        try:
            result = handler_fn(payload)
            _send_json(exchange, 200, {"request_id": request_id, "stdout": "", "result": result})
        except (Exception, Throwable) as exc:
            _send_json(exchange, 200, {
                "request_id": request_id,
                "stdout": "",
                "traceback": "%s: %s\n%s" % (type(exc).__name__, exc, _traceback.format_exc()),
            })


def start():
    addr = InetSocketAddress(BIND_HOST, BIND_PORT)
    server = HttpServer.create(addr, 0)
    server.createContext("/", BridgeHandler())
    # No executor set -> HttpServer's default sequential handling: only
    # one request processed at a time. Deliberate for v1 -- avoids
    # concurrent script execution racing on live JMRI object-graph state.
    # Revisit only if serialized throughput becomes an actual problem.
    server.start()
    print("JmriMcpBridge: listening on %s:%d" % (BIND_HOST, BIND_PORT))
    return server


_server = start()
