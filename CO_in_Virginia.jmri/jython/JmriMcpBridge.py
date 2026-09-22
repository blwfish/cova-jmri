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


# --- jmri_logs ----------------------------------------------------------
# JMRI's own log4j2 config (default_lcf.xml) writes session.log/
# messages.log to ${sys:jmri.log.path} -- the Java system property is the
# only portable source of truth for this directory (confirmed live
# 2026-09-22: matches the open file descriptors of the actual running
# JMRI process on this machine, and is NOT the profile directory -- log
# files are shared across all profiles run under this JMRI install, not
# per-profile). jmri.util.FileUtil has no equivalent "logs:" alias.

# Every log line JMRI itself writes starts with an ISO8601-ish timestamp
# (log4j2's ISO8601 pattern actually renders as "2026-09-21T21:53:13,486",
# confirmed against the real session.log -- NOT "yyyy-MM-dd HH:mm:ss,SSS"
# with a space, which is what the pattern's own name would suggest),
# followed by the padded/truncated logger-name field (%-37.37c{2}), then
# the level field (%-5p), then " - ", then the message. A stack-trace
# continuation line never starts this way, so this regex doubles as
# "does this line start a new log entry" for get_last_error's multi-line
# capture below. `\S+` for the logger-name field relies on class names
# never containing whitespace -- true for every JMRI/Java class name.
_LOG_ENTRY_RE = re.compile(r"^(\S+)\s+\S+\s+([A-Z]+)\s*-\s")


def _log_file_path(file_name):
    """Resolve a bare JMRI log filename to its absolute path. Defense in
    depth against path traversal even though jmri_mcp_server.py already
    validates `file` is a bare filename before this bridge ever sees a
    request -- this script has no other caller today, but nothing
    structurally prevents one, and this check is nearly free."""
    if "/" in file_name or "\\" in file_name or ".." in file_name:
        raise ValueError("file must be a bare filename, got %r" % (file_name,))
    log_dir = System.getProperty("jmri.log.path")
    if not log_dir:
        raise ValueError("jmri.log.path system property is not set -- cannot locate JMRI's log directory")
    return os.path.join(log_dir, file_name)


def _read_log_lines(file_name):
    path = _log_file_path(file_name)
    if not os.path.exists(path):
        raise ValueError("log file %r does not exist at %s" % (file_name, path))
    f = open(path, "r")
    try:
        return f.readlines()
    finally:
        f.close()


def _jmri_logs_tail(payload):
    n = payload.get("lines") or 200
    lines = _read_log_lines(payload["file"])
    tail = lines[-n:] if n > 0 else []
    return {"lines": [line.rstrip("\r\n") for line in tail]}


def _jmri_logs_grep(payload):
    pattern = payload.get("pattern")
    if not pattern:
        raise ValueError("grep requires a non-empty `pattern` (a regex, searched per-line)")
    regex = re.compile(pattern)
    lines = _read_log_lines(payload["file"])
    matches = [line.rstrip("\r\n") for line in lines if regex.search(line)]
    return {"lines": matches}


def _jmri_logs_get_last_error(payload):
    """Most recent ERROR (or FATAL) log entry, including any stack-trace
    continuation lines that followed it -- not just its first line, since
    a bare first line without the trace is rarely the useful part."""
    lines = _read_log_lines(payload["file"])
    start_index = None
    for i in range(len(lines) - 1, -1, -1):
        m = _LOG_ENTRY_RE.match(lines[i])
        if m and m.group(2) in ("ERROR", "FATAL"):
            start_index = i
            break
    if start_index is None:
        return {"found": False}
    end_index = start_index + 1
    while end_index < len(lines) and not _LOG_ENTRY_RE.match(lines[end_index]):
        end_index += 1
    entry_lines = [line.rstrip("\r\n") for line in lines[start_index:end_index]]
    return {"found": True, "lines": entry_lines}


# --- jmri_introspect's list_* operations ---------------------------------
# Bridge-side pagination: jmri_mcp_server.py forwards `limit`/`offset` as
# hints (see its jmri_introspect docstring) and, once an operation is
# implemented here, this is what actually owns honoring them -- strictly
# better than fetching the whole object graph over HTTP just to slice it
# client-side.
def _paginate(items, payload):
    limit = payload.get("limit")
    offset = payload.get("offset") or 0
    total = len(items)
    page = items[offset:] if limit is None else items[offset:offset + limit]
    next_offset = offset + len(page)
    return {
        "items": page,
        "total": total,
        "count": len(page),
        "offset": offset,
        "has_more": next_offset < total,
        "next_offset": next_offset if next_offset < total else None,
    }


def _list_signal_masts(payload):
    """Live-confirmed 2026-09-22 against a real registered VirtualSignalMast
    (created and deregistered again for the test -- see jmri-mcp's commit
    history) -- getSystemName/getUserName/getClass/getAspect all round-
    tripped correctly, including the empty-list case (no signal masts
    configured on this test rig otherwise)."""
    from jmri import InstanceManager, SignalMastManager
    masts = InstanceManager.getDefault(SignalMastManager).getNamedBeanSet()
    items = [
        {
            "name": m.getSystemName(),
            "userName": m.getUserName(),
            "class": m.getClass().getName(),
            "aspect": m.getAspect(),
        }
        for m in masts
    ]
    return _paginate(items, payload)


def _list_signal_mast_logic(payload):
    """Live-confirmed 2026-09-22 against a real, temporarily-created
    SignalMastLogic pairing two VirtualSignalMasts (created and removed
    again for the test). SignalMastLogic itself is not a NamedBean (no
    system/user name of its own) -- identified here by its source mast."""
    from jmri import InstanceManager, SignalMastLogicManager
    smls = InstanceManager.getDefault(SignalMastLogicManager).getSignalMastLogicList()
    items = []
    for sml in smls:
        source = sml.getSourceMast()
        items.append({
            "source": source.getSystemName() if source else None,
            "destinations": [
                {"name": d.getSystemName(), "enabled": sml.isEnabled(d)}
                for d in sml.getDestinationList()
            ],
        })
    return _paginate(items, payload)


def _list_sections(payload):
    """Live-confirmed 2026-09-22 against a real, temporarily-created
    Section spanning two real Blocks from this layout (created and deleted
    again for the test) -- getSectionType() (a Java enum) stringifies via
    Jython's str() to its plain name (e.g. "USERDEFINED"), confirmed
    empirically rather than assumed."""
    from jmri import InstanceManager, SectionManager
    sections = InstanceManager.getDefault(SectionManager).getNamedBeanSet()
    items = [
        {
            "name": s.getSystemName(),
            "userName": s.getUserName(),
            "sectionType": str(s.getSectionType()),
            "blocks": [b.getSystemName() for b in s.getBlockList()],
        }
        for s in sections
    ]
    return _paginate(items, payload)


def _list_transits(payload):
    """Live-confirmed 2026-09-22 against a real, temporarily-created
    Transit containing one TransitSection (created and deleted again for
    the test). Note TransitSection.getSectionName() returns JMRI's own
    formatted "system(username)" string when the Section has a user name,
    not a bare system name -- confirmed empirically, passed through as-is
    rather than reformatted."""
    from jmri import InstanceManager, TransitManager
    transits = InstanceManager.getDefault(TransitManager).getNamedBeanSet()
    items = [
        {
            "name": t.getSystemName(),
            "userName": t.getUserName(),
            "sections": [
                {
                    "name": ts.getSectionName(),
                    "sequenceNumber": ts.getSequenceNumber(),
                    "direction": ts.getDirection(),
                }
                for ts in t.getTransitSectionList()
            ],
        }
        for t in transits
    ]
    return _paginate(items, payload)


def _get_panel_structure(payload):
    """No `limit`/`offset` -- this isn't forwarded as a list_* pagination
    hint by jmri_mcp_server.py (see its jmri_introspect docstring), so this
    always returns every open Layout Editor panel's full summary.

    JMRI's Layout Editor has no single API for "which blocks belong to
    this panel" -- confirmed against source, not assumed, which is exactly
    why this operation was deferred past the four list_* ones. Each
    concrete LayoutTrack subclass owns its LayoutBlock reference(s) via
    its own differently-named method(s):
      - TrackSegment: getLayoutBlock() (one block)
      - LayoutTurnout (LayoutRHTurnout/LayoutLHTurnout, and LayoutSlip --
        both extend LayoutTurnout, confirmed against source): getLayoutBlock(),
        plus getLayoutBlockB()/C()/D() for a double/three-way turnout's other
        legs -- each of those three defaults back to getLayoutBlock() when
        that specific block isn't set (confirmed against LayoutTurnout.java),
        so calling all four unconditionally and de-duplicating is always
        safe, never a crash on a plain single turnout.
      - LevelXing: getLayoutBlockAC() / getLayoutBlockBD() (two blocks, for
        its two crossing tracks) -- a different method-name pattern again.
      - PositionablePoint: no block of its own -- it's a connector between
        two other LayoutTrack elements (see below), not a track element.
    Live-confirmed 2026-09-22 against this test rig's two real open panels
    (105+90 TrackSegments, 14+4 turnouts between them) -- resolving through
    to real Block system names via LayoutBlock.getBlock().getSystemName()
    (LayoutBlock itself is a NamedBean with its OWN, different system name,
    e.g. "IL..." -- confirmed against LayoutBlock.java; the underlying
    Block it wraps, e.g. "IB:AUTO:...", is what this reports, matching what
    jmri_introspect's list_sections/jmri_authoring's section create already
    use elsewhere). Neither panel has a LevelXing or LayoutSlip configured,
    so that branch is verified against source only, not live data -- TESTME
    if one is ever added to this rig.

    "Connection points" are PositionablePoints (LayoutEditor.
    getPositionablePoints()) -- confirmed live against all three real
    PointType values (ANCHOR, END_BUMPER, EDGE_CONNECTOR all occur on this
    rig's panels) and against real edge cases live data actually contained:
    an END_BUMPER has only one connection (getConnect2() is null, handled),
    and this rig has a few ANCHOR points with only one connection or even
    zero (apparent leftover/orphaned points in the layout's own data, not a
    bug here) -- this returns whatever's actually there rather than
    assuming every ANCHOR has exactly two."""
    from jmri import InstanceManager
    from jmri.jmrit.display import EditorManager
    from jmri.jmrit.display.layoutEditor import LayoutEditor, TrackSegment, LayoutTurnout, LevelXing

    panels = []
    for editor in InstanceManager.getDefault(EditorManager).getAll():
        if not isinstance(editor, LayoutEditor):
            continue

        block_names = set()
        for track in editor.getLayoutTracks():
            layout_blocks = []
            if isinstance(track, TrackSegment):
                layout_blocks = [track.getLayoutBlock()]
            elif isinstance(track, LayoutTurnout):
                layout_blocks = [track.getLayoutBlock(), track.getLayoutBlockB(),
                                  track.getLayoutBlockC(), track.getLayoutBlockD()]
            elif isinstance(track, LevelXing):
                layout_blocks = [track.getLayoutBlockAC(), track.getLayoutBlockBD()]
            for lb in layout_blocks:
                if lb is None:
                    continue
                real_block = lb.getBlock()
                if real_block is not None:
                    block_names.add(real_block.getSystemName())

        connection_points = []
        for pp in editor.getPositionablePoints():
            connects = []
            for c in (pp.getConnect1(), pp.getConnect2()):
                if c is not None:
                    connects.append(c.getName())
            connection_points.append({
                "name": pp.getName(),
                "type": pp.getType().toString(),
                "connects": connects,
            })

        panels.append({
            "name": editor.getTitle(),
            "blocks": sorted(block_names),
            "connectionPoints": connection_points,
        })

    return {"panels": panels}


# --- jmri_logixng ---------------------------------------------------------
# LogixNG has two separate, independent on/off signals, confirmed against
# JMRI's own actions/EnableLogixNG.java (the built-in action our tool's
# "enable"/"disable" op names are meant to match): setEnabled(bool) is the
# persisted "is this in the table at all" flag; setActive(bool) is a
# separate runtime activate/deactivate toggle. EnableLogixNG's own enum
# maps its "Enable"/"Disable" choices to setEnabled ONLY -- never touching
# setActive -- so that's what this bridge's enable/disable operations do
# too, not some combination of both.
#
# isActive() (used for reporting only, never set directly here) is derived:
# DefaultLogixNG.isActive() = _enabled && _isActive && _manager.isActive().
# _isActive starts false on a freshly created LogixNG and is set true by
# activate() (called once by the manager for every LogixNG that already
# existed when JMRI started, via activateAllLogixNGs() -- confirmed in
# DefaultLogixNGManager.java). A LogixNG created at runtime (this bridge's
# "create" op) needs its own explicit activate() call for the same effect,
# which is exactly the sequence jmri.jmrit.beantable.LogixNGTableAction's
# own "Add LogixNG" GUI dialog uses -- createLogixNG(...) -> activate() ->
# setEnabled(true) -> clearStartup() -- replicated here rather than
# invented, and live-confirmed 2026-09-22 to produce a real, fully active
# LogixNG (registerListeners()/execute() do run, since setEnabled(true)'s
# own internal checkIfActiveAndEnabled() only takes effect once isActive()
# is already true, which needs activate() to have run first).
def _logixng_info(logixng):
    return {
        "name": logixng.getSystemName(),
        "userName": logixng.getUserName(),
        "enabled": logixng.isEnabled(),
        "active": logixng.isActive(),
        "comment": logixng.getComment(),
    }


def _logixng_manager():
    from jmri import InstanceManager
    from jmri.jmrit.logixng import LogixNG_Manager
    return InstanceManager.getDefault(LogixNG_Manager)


def _logixng_list(payload):
    items = [_logixng_info(l) for l in _logixng_manager().getNamedBeanSet()]
    return _paginate(items, payload)


def _logixng_get(payload):
    """`name` may be either a system name or a user name -- getLogixNG()
    tries both (confirmed live), matching JMRI's own usual bean-lookup
    convention."""
    name = payload.get("name")
    logixng = _logixng_manager().getLogixNG(name)
    if logixng is None:
        raise ValueError("no LogixNG named %r" % (name,))
    return _logixng_info(logixng)


def _logixng_create(payload):
    params = payload.get("params") or {}
    user_name = params.get("userName")
    if not user_name:
        raise ValueError("create requires params.userName")
    system_name = params.get("systemName")
    mgr = _logixng_manager()
    logixng = mgr.createLogixNG(system_name, user_name) if system_name else mgr.createLogixNG(user_name)
    logixng.activate()
    logixng.setEnabled(True)
    logixng.clearStartup()
    return _logixng_info(logixng)


def _logixng_set_enabled(payload, enabled):
    name = payload.get("name")
    logixng = _logixng_manager().getLogixNG(name)
    if logixng is None:
        raise ValueError("no LogixNG named %r" % (name,))
    logixng.setEnabled(enabled)
    return _logixng_info(logixng)


def _logixng_enable(payload):
    return _logixng_set_enabled(payload, True)


def _logixng_disable(payload):
    return _logixng_set_enabled(payload, False)


# --- jmri_authoring --------------------------------------------------------
# Four of the six target_types the client accepts (see jmri-mcp's TOOLS.md):
# signalMast, block, section, transit. Each "create" recipe below was proven
# live 2026-09-22 before being trusted, not written speculatively -- see
# each function's own comment for what that proving caught.
#
# Deliberately NOT implemented here, and not planned as a quick follow-on:
#
# - target_type="connection" (JMRI's "SML Discover" --
#   SignalMastLogicManager.automaticallyDiscoverSignallingPairs()) and the
#   companion "Generate Sections" (DefaultSignalMastLogicManager.
#   generateSection() / SectionManager.generateBlockSections()): JMRI's own
#   GUI action (SignalMastLogicTableAction) runs discovery on a background
#   thread specifically because "this process can take some time", then
#   marshals the follow-up work (table update, optional section generation)
#   back onto the EDT via SwingUtilities.invokeAndWait. That's exactly the
#   open, documented EDT-marshaling risk in AGENT-DEBUGGING.md's "hangs or
#   crashes JMRI's UI" section -- this bridge's handler runs on a plain HTTP
#   worker thread, not the EDT, and that gap is not resolved. Also unlike
#   signalMast/block/section/transit create, there was no way to responsibly
#   validate this live: it needs real Layout Editor connectivity (blocks
#   wired into TrackSegments with signal masts facing them) that this test
#   rig's panels don't have configured, and fabricating a credible test
#   fixture for that is a substantially bigger undertaking than anything
#   else proven today.
# - target_type="preference": TOOLS.md/the client's own docstring name this
#   as a valid target_type value but never specify what operation it's for
#   -- there is nothing concrete here to implement without inventing scope
#   that was never actually asked for.
def _lookup_named_bean(manager, name):
    """`name` may be a system name or a user name -- most JMRI Manager
    getBySystemName/getByUserName pairs don't combine the two lookups the
    way SignalMastLogicManager.getLogixNG() does, so this bridge does it
    itself wherever a caller-supplied name needs to resolve either way."""
    bean = manager.getBySystemName(name)
    if bean is None:
        bean = manager.getByUserName(name)
    return bean


def _authoring_create_signal_mast(payload):
    """A MatrixSignalMast's system name ENCODES its signal-system and
    mast-type (parsed by configureFromName() from "IF$xsm:<system>:
    <mastType>($NNNN)" -- confirmed against MatrixSignalMast.java's source,
    not guessed), so this builds that string from structured params rather
    than asking the caller to construct JMRI's own internal name format.
    getLastRef()/the "($NNNN)" ordinal is MatrixSignalMast's own class-wide
    auto-numbering counter (confirmed live 2026-09-22: creating one bumps
    it, so a second create with the same signalSystem/mastType doesn't
    collide). Passing a plain Python string ("0100") for the char[]
    setBitsForAspect expects works without any manual conversion --
    confirmed live, Jython does this automatically."""
    params = payload.get("params") or {}
    signal_system = params.get("signalSystem")
    mast_type = params.get("mastType")
    aspects = params.get("aspects")
    user_name = params.get("userName")
    if not signal_system or not mast_type:
        raise ValueError("signalMast create requires params.signalSystem and params.mastType")
    if not aspects:
        raise ValueError("signalMast create requires params.aspects (a non-empty {aspect: bitPattern} mapping)")

    from jmri.implementation import MatrixSignalMast
    from jmri import InstanceManager, SignalMastManager

    ordinal = MatrixSignalMast.getLastRef() + 1
    system_name = "IF$xsm:%s:%s($%04d)" % (signal_system, mast_type, ordinal)
    mast = MatrixSignalMast(system_name, user_name) if user_name else MatrixSignalMast(system_name)
    for aspect, bits in aspects.items():
        mast.setBitsForAspect(aspect, bits)
    InstanceManager.getDefault(SignalMastManager).register(mast)
    return {
        "name": mast.getSystemName(),
        "userName": mast.getUserName(),
        "class": mast.getClass().getName(),
        "aspects": sorted(aspects.keys()),
    }


def _authoring_create_block(payload):
    """Two things live-testing caught here, neither obvious from the method
    names alone:
      - Block has NO getLength() -- only getLengthMm()/getLengthCm()/
        getLengthIn() (confirmed against Block.java; calling the plausible-
        looking getLength() raises AttributeError at the Jython/Java
        boundary).
      - Block.setSensor(name) is NOT a lookup -- it calls SensorManager.
        provideSensor(name), which CREATES a new Sensor bean if none exists
        by that name yet, and still returns True. Confirmed live: passing
        a typo'd sensor name silently created a real, permanent phantom
        Sensor (auto-prefixed onto this layout's default connection, e.g.
        "M2Sno-such-sensor") rather than failing. This function checks
        SensorManager.getSensor(name) itself FIRST (get-only, confirmed
        against SensorManager.java's own doc comment: "Get an existing
        Sensor or return null if it doesn't exist") and refuses before
        ever calling setSensor, rather than trusting setSensor's return
        value to mean what it sounds like it means."""
    params = payload.get("params") or {}
    user_name = params.get("userName")
    if not user_name:
        raise ValueError("block create requires params.userName")

    from jmri import InstanceManager, BlockManager, SensorManager

    sensor_name = params.get("sensor")
    sensor = None
    if sensor_name:
        sensor = InstanceManager.getDefault(SensorManager).getSensor(sensor_name)
        if sensor is None:
            raise ValueError(
                "no Sensor named %r -- refusing to auto-create one "
                "(Block.setSensor() would silently do that)" % (sensor_name,)
            )

    mgr = InstanceManager.getDefault(BlockManager)
    block = mgr.createNewBlock(user_name)
    if block is None:
        raise ValueError("could not create block %r (userName may already be in use)" % (user_name,))

    if sensor is not None:
        block.setSensor(sensor_name)

    length = params.get("length")
    if length is not None:
        block.setLength(float(length))

    return {
        "name": block.getSystemName(),
        "userName": block.getUserName(),
        "sensor": sensor_name,
        "lengthMm": block.getLengthMm(),
    }


def _authoring_create_section(payload):
    """SectionManager.createNewSection(userName) throws (IllegalArgumentException,
    per its own interface signature) on a name collision, rather than
    returning null the way BlockManager.createNewBlock does -- confirmed
    against SectionManager.java/Section.java; different managers, different
    failure conventions for what looks like the same "create" shape (see
    CLAUDE.md's Parallel Implementation Rule). Left to propagate as-is into
    the bridge's normal traceback response rather than pre-checked, since
    JMRI's own exception message is already clear."""
    params = payload.get("params") or {}
    user_name = params.get("userName")
    block_names = params.get("blocks")
    if not user_name:
        raise ValueError("section create requires params.userName")
    if not block_names:
        raise ValueError("section create requires params.blocks (a non-empty list of Block names)")

    from jmri import InstanceManager, SectionManager, BlockManager

    block_mgr = InstanceManager.getDefault(BlockManager)
    blocks = []
    for name in block_names:
        block = _lookup_named_bean(block_mgr, name)
        if block is None:
            raise ValueError("no Block named %r" % (name,))
        blocks.append(block)

    section = InstanceManager.getDefault(SectionManager).createNewSection(user_name)
    for block in blocks:
        section.addBlock(block)

    return {
        "name": section.getSystemName(),
        "userName": section.getUserName(),
        "blocks": [b.getSystemName() for b in section.getBlockList()],
    }


def _authoring_create_transit(payload):
    """TransitManager.createNewTransit also throws (NamedBean.BadNameException)
    on a collision rather than returning null -- same note as section
    create above. TransitSection.getSectionName() in the response below
    returns JMRI's own "system( username )" formatted string when the
    Section has a user name, not a bare system name -- confirmed live,
    passed through as-is (see jmri_introspect's list_transits, which hit
    the same thing first)."""
    params = payload.get("params") or {}
    user_name = params.get("userName")
    section_specs = params.get("sections")
    if not user_name:
        raise ValueError("transit create requires params.userName")
    if not section_specs:
        raise ValueError("transit create requires params.sections (a non-empty list of "
                          "{name, sequenceNumber, direction} objects)")

    from jmri import InstanceManager, SectionManager, TransitManager, Section, TransitSection

    sec_mgr = InstanceManager.getDefault(SectionManager)
    resolved = []
    for spec in section_specs:
        name = spec.get("name")
        section = _lookup_named_bean(sec_mgr, name) if name else None
        if section is None:
            raise ValueError("no Section named %r" % (name,))
        direction_str = spec.get("direction", "FORWARD")
        if direction_str == "FORWARD":
            direction = Section.FORWARD
        elif direction_str == "REVERSE":
            direction = Section.REVERSE
        else:
            raise ValueError("direction must be \"FORWARD\" or \"REVERSE\", got %r" % (direction_str,))
        seq = spec.get("sequenceNumber")
        if seq is None:
            raise ValueError("each section spec requires sequenceNumber")
        resolved.append((section, seq, direction))

    transit = InstanceManager.getDefault(TransitManager).createNewTransit(user_name)
    for section, seq, direction in resolved:
        transit.addTransitSection(TransitSection(section, seq, direction))

    return {
        "name": transit.getSystemName(),
        "userName": transit.getUserName(),
        "sections": [
            {"name": ts.getSectionName(), "sequenceNumber": ts.getSequenceNumber(), "direction": ts.getDirection()}
            for ts in transit.getTransitSectionList()
        ],
    }


# Structured (tool, operation, target_type) tuples this bridge actually
# implements -- target_type is None for every tool except jmri_authoring,
# which is the only one with that extra dimension (see _handle's own
# comment). Everything else -- jmri_authoring's connection/preference
# target_types (see that section's own comment above for why) -- returns a
# clear "not yet implemented" error rather than a fabricated JMRI API call
# I'm not confident about. See jmri-mcp's TOOLS.md status legend; these get
# filled in incrementally, each validated against this live instance before
# being trusted.
_STRUCTURED_OPS = {
    ("jmri_introspect", "describe_class", None): lambda payload: _describe_class(payload["class_name"]),
    ("jmri_introspect", "get_panel_structure", None): _get_panel_structure,
    ("jmri_introspect", "list_signal_masts", None): _list_signal_masts,
    ("jmri_introspect", "list_signal_mast_logic", None): _list_signal_mast_logic,
    ("jmri_introspect", "list_sections", None): _list_sections,
    ("jmri_introspect", "list_transits", None): _list_transits,
    ("jmri_logixng", "list", None): _logixng_list,
    ("jmri_logixng", "get", None): _logixng_get,
    ("jmri_logixng", "create", None): _logixng_create,
    ("jmri_logixng", "enable", None): _logixng_enable,
    ("jmri_logixng", "disable", None): _logixng_disable,
    ("jmri_authoring", "create", "signalMast"): _authoring_create_signal_mast,
    ("jmri_authoring", "create", "block"): _authoring_create_block,
    ("jmri_authoring", "create", "section"): _authoring_create_section,
    ("jmri_authoring", "create", "transit"): _authoring_create_transit,
    ("jmri_logs", "tail", None): _jmri_logs_tail,
    ("jmri_logs", "grep", None): _jmri_logs_grep,
    ("jmri_logs", "get_last_error", None): _jmri_logs_get_last_error,
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
