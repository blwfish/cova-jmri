# JmriMcpBridge.py -- embedded HTTP listener for jmri-mcp
# (https://github.com/blwfish/jmri-mcp), run as a PerformScriptModelXml
# startup action inside JMRI's own JVM. Opens a plain JDK HttpServer (no
# external library, no MQTT broker) and executes submitted Jython via
# jmri.script.JmriScriptEngineManager, returning stdout/result/traceback
# as the synchronous HTTP response body.
#
# STATUS: unwired. Not yet added to profile.xml's <startup> block -- see
# jmri-mcp's design spec, Next Steps 2-4. NOT YET LIVE-TESTED. Several
# JMRI-API calls below are best-effort, not confirmed against a running
# JVM -- each is flagged inline with "TESTME" where the spec's own
# Unknowns section already calls this out as needing empirical proving
# (particularly: does JmriScriptEngineManager expose getEngineByName, and
# under what name; does an exception in a submitted script crash just
# this request, this thread, or the JVM).
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
from java.net import InetSocketAddress
from java.security import SecureRandom
from com.sun.net.httpserver import HttpHandler, HttpServer

from jmri.script import JmriScriptEngineManager

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
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
TOKEN_PATH = os.path.join(_SCRIPT_DIR, "bridge_token.txt")


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
    """TESTME: getEngineByName's exact registered name for Jython under
    JmriScriptEngineManager is unconfirmed -- "python" is JSR-223's
    conventional registration name and the most likely candidate, but
    this needs live confirmation (spec Next Steps #2). If this raises
    AttributeError/None-engine, that's the first thing to check."""
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
    except Exception as exc:
        writer.flush()
        return {
            "stdout": sw.toString(),
            "traceback": "%s: %s\n%s" % (
                type(exc).__name__, exc, _traceback.format_exc(),
            ),
        }


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
    "wire describe_class early")."""
    from java.lang import Class
    from java.lang.reflect import Modifier

    cls = Class.forName(class_name)

    def fmt(t):
        return t.getName()

    constructors = [
        {
            "modifiers": Modifier.toString(c.getModifiers()),
            "params": [fmt(p) for p in c.getParameterTypes()],
        }
        for c in cls.getDeclaredConstructors()
    ]
    methods = [
        {
            "name": m.getName(),
            "modifiers": Modifier.toString(m.getModifiers()),
            "params": [fmt(p) for p in m.getParameterTypes()],
            "returns": fmt(m.getReturnType()),
        }
        for m in cls.getDeclaredMethods()
    ]
    superclass = cls.getSuperclass()
    return {
        "class": class_name,
        "superclass": superclass.getName() if superclass else None,
        "interfaces": [i.getName() for i in cls.getInterfaces()],
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
        # propagating into HttpServer's own thread pool. TESTME (spec
        # Next Steps #2): confirm this actually holds for a JVM-level
        # error (StackOverflowError, OutOfMemoryError), not just a
        # regular Exception -- Jython's `except Exception` may not catch
        # a java.lang.Error subtype.
        try:
            self._handle(exchange)
        except Exception as exc:
            try:
                _send_json(exchange, 500, {"error": "internal bridge error: %s" % exc})
            except Exception:
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
        except Exception as exc:
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
