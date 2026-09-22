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

import json
import os
import traceback as _traceback

import jarray
from java.io import ByteArrayOutputStream, PrintWriter, StringWriter
from java.lang import String as JString
from java.lang import Throwable
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
    does NOT catch that. The combined tuple is required for both."""
    manager = JmriScriptEngineManager.getDefault()
    engine = manager.getEngineByName("python")
    sw = StringWriter()
    writer = PrintWriter(sw)
    engine.getContext().setWriter(writer)
    engine.getContext().setErrorWriter(writer)
    try:
        result = manager.eval(script, engine)
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


# Structured (tool, operation) pairs this bridge actually implements.
# Everything else -- jmri_introspect's other operations, jmri_authoring,
# jmri_logixng, jmri_logs -- returns a clear "not yet implemented" error
# rather than a fabricated JMRI API call I'm not confident about. See
# jmri-mcp's TOOLS.md status legend; these get filled in incrementally,
# each validated against this live instance before being trusted.
_STRUCTURED_OPS = {
    ("jmri_introspect", "describe_class"): lambda payload: _describe_class(payload["class_name"]),
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
        handler_fn = _STRUCTURED_OPS.get((tool, operation))
        if handler_fn is None:
            _send_json(exchange, 501, {
                "request_id": request_id,
                "error": "operation '%s.%s' not yet implemented on the bridge" % (tool, operation),
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
