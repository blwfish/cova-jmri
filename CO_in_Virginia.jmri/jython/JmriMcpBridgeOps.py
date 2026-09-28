# JmriMcpBridgeOps.py -- operation handlers for JmriMcpBridge.py, split
# into a sibling module so the top-level startup script stays well
# under Jython's ~100,000-character ScriptEngine parse ceiling (see
# AGENT-INSTALL.md's Critical Rules -- Jython's own ParserFacade hits
# 'IOException: Mark invalid' past that size on a script with no PEP
# 263 encoding declaration, loaded via javax.script.ScriptEngine.
# eval(Reader), which is exactly how PerformScriptModel loads a
# startup script -- confirmed against Jython 2.7.4's own bytecode,
# not assumed). Imported by JmriMcpBridge.py after inserting this
# file's own directory onto sys.path (FileUtil.getExternalFilename
# resolves it -- __file__ is NOT available in this execution context,
# same reason TOKEN_PATH above uses the same trick). Loading a module
# via Jython's own `import` goes through org.python.core.imp, a
# completely different code path from ScriptEngine.eval(Reader) --
# confirmed empirically NOT subject to the same mark/reset bug
# regardless of this file's own size.

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


def _get_block_boundaries(payload):
    """Find every real block boundary on each open Layout Editor panel --
    candidate signal-mast locations (jmri-mcp issue #13, design-docs'
    SIGNAL_DISPATCH_SPEC.md phase 1) -- by calling JMRI's OWN canonical
    connectivity mechanism, `LayoutEditorAuxTools.getConnectivityList()`,
    rather than reimplementing "does the block change here" as a
    client-side heuristic (this project's own Parallel Implementation
    Rule: prefer JMRI's APIs/managers over reinventing their rules).

    This is the exact list JMRI's own Layout Editor "Set Signals at Block
    Boundary"/"...at Turnout"/"...at Double Crossover" wizards are built
    on. Confirmed against source (`LayoutEditorAuxTools.java`,
    `initializeBlockConnectivity()`): `PositionablePoint`, `TrackSegment`,
    and `LayoutTurnout` (which `LayoutXOver`/`LayoutSlip` both extend --
    confirmed against source, same as `_get_panel_structure` above) each
    contribute a `LayoutConnectivity` entry wherever the `LayoutBlock` on
    one side of a real connection differs from the other side.
    `getConnectivityList(blk)` lazily initializes and safely re-reads that
    cache -- no mutation of actual layout objects (unlike
    `PositionablePoint.reCheckBlockBoundary()`, which can delete signal
    masts as a side effect and is deliberately NOT called here).

    **Confirmed, fixed staleness bug (2026-09-28, found live-testing
    signalMastPlacement)**: `getConnectivityList()` only does a full
    rebuild (`initializeBlockConnectivity()`) on its very first-ever call
    for a given panel; every call after that only recomputes
    (`updateBlockConnectivity()`) if `setBlockConnectivityChanged()` was
    called first. Confirmed against source that `LayoutTurnout`'s block
    setters call it (`LayoutTurnout.java` line ~1483) but `TrackSegment`'s
    do NOT -- and a plain `ANCHOR` boundary's blocks live entirely on its
    two connected `TrackSegment`s, never on the `PositionablePoint`
    itself. Net effect: any block assigned to a `TrackSegment` AFTER this
    operation has already been called once for that panel was silently
    invisible to every later call -- live-reproduced with a minimal
    two-Block anchor boundary that a direct read of `PositionablePoint.
    getConnect1()/getConnect2()`'s current blocks confirmed was real.
    Fixed by unconditionally calling `editor.getLEAuxTools().
    setBlockConnectivityChanged()` before reading each panel's
    connectivity below -- confirmed live this forces the same full,
    correct recompute every call, at the cost of that recompute's work
    (a full walk of the panel's points/segments/turnouts/slips) on every
    invocation rather than only when something changed; acceptable here
    since this operation is already documented as a full-panel scan, not
    a hot-path call. This does NOT touch `PositionablePoint.
    reCheckBlockBoundary()` or any mast state -- purely an internal cache
    invalidation, safe to call unconditionally.

    **Confirmed gap in JMRI's OWN mechanism, not this bridge's** (jmri-mcp
    issue #13): `LevelXing` is never fed into `LayoutEditorAuxTools` at
    all -- confirmed against source, both `initializeBlockConnectivity()`
    and `updateBlockConnectivity()` iterate PositionablePoint/
    TrackSegment/LayoutTurnout/LayoutSlip only, and JMRI's own source has
    an unresolved "why?" comment on the omission. A LevelXing's two block
    pairs (`getLayoutBlockAC()`/`getLayoutBlockBD()`) are reported
    separately below as `levelXingBlocks`, unresolved into boundary pairs
    against their neighbors, until this bridge does that comparison
    itself. Untested (Gville-arsenal.xml has zero LevelXings today), not
    just unbuilt.

    **Second, distinct gap** (jmri-mcp issue #13, added 2026-09-27 cold
    review): a turnout bean with no `LayoutTurnout` icon placed on any
    panel is invisible to this whole mechanism -- it's simply not in the
    `LayoutTrack` graph. This op cross-references the full Turnout roster
    against every `Turnout` actually referenced by a placed
    `LayoutTurnout` (via `getTurnout()`/`getSecondTurnout()` -- a
    double-crossover or linked pair can reference two beans from one
    icon) and reports the difference as `unplacedTurnouts`, so that gap
    shows up in the tool's own output instead of staying a silent
    unknown.

    Live-confirmed 2026-09-27 two ways: against a synthetic testDoubleOval
    fixture (all three boundary shapes -- plain anchor, turnout-to-
    neighbor, internal crossover) and against a cleanly-loaded (full
    startup, not mid-session ConfigureManager.load() -- that leaves most
    LayoutBlocks unlinked from their real Block, a separate JMRI bug, see
    TOOLS.md) Gville-arsenal.xml: 23 real boundaries (15 + 8 across the
    two panels), superseding SIGNAL_DISPATCH_SPEC.md's earlier offline-
    script estimate of 16."""
    from jmri import InstanceManager, TurnoutManager
    from jmri.jmrit.display import EditorManager
    from jmri.jmrit.display.layoutEditor import LayoutEditor, LayoutTurnout, LevelXing, TrackSegment

    panels = []
    placed_turnouts = set()  # system names of Turnout beans referenced by a placed LayoutTurnout

    def _block_name(layout_block):
        if layout_block is None:
            return None
        real_block = layout_block.getBlock()
        return real_block.getSystemName() if real_block is not None else None

    for editor in InstanceManager.getDefault(EditorManager).getAll():
        if not isinstance(editor, LayoutEditor):
            continue

        aux = editor.getLEAuxTools()
        # Force a fresh recompute every call -- see the staleness-bug
        # comment on this function's own docstring above. Pure cache
        # invalidation, no mutation of any layout object or bean.
        aux.setBlockConnectivityChanged()

        # Same per-track-type block resolution as _get_panel_structure,
        # but keeping the LayoutBlock objects themselves (not just their
        # wrapped Block's system name) since getConnectivityList() takes
        # a LayoutBlock, and recording which real Turnout beans this
        # panel actually places an icon for.
        layout_blocks_by_id = {}
        level_xings = []
        for track in editor.getLayoutTracks():
            legs = []
            if isinstance(track, LayoutTurnout):
                legs = [track.getLayoutBlock(), track.getLayoutBlockB(),
                        track.getLayoutBlockC(), track.getLayoutBlockD()]
                for t in (track.getTurnout(), track.getSecondTurnout()):
                    if t is not None:
                        placed_turnouts.add(t.getSystemName())
            elif isinstance(track, LevelXing):
                legs = [track.getLayoutBlockAC(), track.getLayoutBlockBD()]
                level_xings.append(track)
            elif isinstance(track, TrackSegment):
                legs = [track.getLayoutBlock()]
            for lb in legs:
                if lb is not None:
                    layout_blocks_by_id[id(lb)] = lb

        boundaries = []
        seen_ids = set()
        for lb in layout_blocks_by_id.values():
            for lc in aux.getConnectivityList(lb):
                if id(lc) in seen_ids:
                    continue
                seen_ids.add(id(lc))
                connected = lc.getConnectedObject()
                connected_type = lc.getConnectedType()
                anchor = lc.getAnchor()
                xover = lc.getXover()
                track_segment = lc.getTrackSegment()
                boundaries.append({
                    "block1": _block_name(lc.getBlock1()),
                    "block2": _block_name(lc.getBlock2()),
                    "trackSegment": track_segment.getName() if track_segment is not None else None,
                    "connectedObject": connected.getName() if connected is not None else None,
                    "connectedType": connected_type.toString() if connected_type is not None else None,
                    "anchor": anchor.getName() if anchor is not None else None,
                    "xover": xover.getName() if xover is not None else None,
                    "xoverBoundaryType": lc.getXoverBoundaryType() if xover is not None else None,
                })

        level_xing_blocks = [
            {
                "name": lx.getName(),
                "blockAC": _block_name(lx.getLayoutBlockAC()),
                "blockBD": _block_name(lx.getLayoutBlockBD()),
            }
            for lx in level_xings
        ]

        panels.append({
            "name": editor.getTitle(),
            "boundaries": boundaries,
            "levelXingBlocks": level_xing_blocks,
        })

    all_turnouts = InstanceManager.getDefault(TurnoutManager).getNamedBeanSet()
    unplaced_turnouts = sorted(
        t.getSystemName() for t in all_turnouts
        if t.getSystemName() not in placed_turnouts
    )

    return {"panels": panels, "unplacedTurnouts": unplaced_turnouts}


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


# jmri-mcp issue #7. The generic tree-walk uses ONLY jmri.jmrit.logixng.
# Base's own interface (getChild/getChildCount/getShortDescription) --
# confirmed against Base.java that every action/expression/ConditionalNG
# implements this, so no per-class special-casing is needed for the tree
# structure itself, unlike printTree()'s human-formatted text output this
# replaces.
#
# Bean-reference detection is reflection-based: for every zero-arg method
# on a node's concrete class that returns
# jmri.jmrit.logixng.util.LogixNG_SelectNamedBean, call it and inspect
# the wrapper. Confirmed by actually surveying this project's own JMRI
# 5.17.3 source checkout (java/src/jmri/jmrit/logixng/{actions,
# expressions}/**/*.java, non-Swing files): 160 of 416 action/expression
# classes hold at least one bean reference via this wrapper; only one
# non-Swing class (ActionListenOnBeans) uses something else (a raw
# NamedBeanHandle list) and isn't covered by this -- a known, source-
# confirmed gap, not a surprise found later.
#
# LogixNG_SelectNamedBean.getBean() can NEVER usefully answer "does this
# still exist" on its own -- confirmed against its own source
# (jmri.jmrit.logixng.util.LogixNG_SelectNamedBean): the NamedBeanHandle
# it wraps holds a direct, @Nonnull Java object reference, not a live
# name-based lookup, and JMRI's own delete path (the "DoDelete"
# vetoable-change LogixNG_SelectNamedBean.vetoableChange() handles) nulls
# the handle out the moment the referenced bean is actually deleted
# through a manager's normal deleteBean() call -- so under normal
# operation the handle is either valid or null, never a stale reference
# to a since-deleted object. Live-confirmed by constructing exactly that
# scenario: create a bean, reference it from an ActionTurnout, delete the
# bean via deleteBean(bean, "DoDelete"), re-check the action -- the
# handle came back null, not a dangling non-null handle. Rather than
# trust that reasoning alone for "exists", this still does a FRESH lookup
# by name against the bean's own manager (select.getManager().
# getNamedBean(name)) for the actually-configured case -- authoritative
# regardless of any handle-caching subtlety this reasoning might have
# missed, and it's what genuinely answers "does this exist right now".
#
# isDirectAddressing() gates all of the above -- confirmed live for both
# sides of that gate, not just Direct: setReference(...) alone does NOT
# switch a LogixNG_SelectNamedBean into Reference addressing (its own
# addressing field is separate from the reference string and needs an
# explicit setAddressing(NamedBeanAddressing.Reference) call first,
# confirmed live the hard way -- getAddressing() still read "Direct"
# after setReference() alone). Once genuinely Reference-addressed, this
# reports {"configured": null, "addressing": "Reference"} with no name/
# exists, confirmed live -- correct, since there's no fixed name to
# check until the LogixNG actually runs and evaluates the reference.
def _logixng_bean_references(base):
    from java.lang import Class
    select_named_bean_class = Class.forName("jmri.jmrit.logixng.util.LogixNG_SelectNamedBean")

    refs = []
    for method in base.getClass().getMethods():
        if len(method.getParameterTypes()) != 0:
            continue
        if not select_named_bean_class.isAssignableFrom(method.getReturnType()):
            continue
        try:
            select = method.invoke(base, [])
        except (Exception, Throwable):
            continue
        if select is None:
            continue

        entry = {"accessor": method.getName(), "addressing": str(select.getAddressing())}
        if select.isDirectAddressing():
            handle = select.getNamedBean()
            if handle is None:
                entry["configured"] = False
            else:
                name = handle.getName()
                entry["configured"] = True
                entry["name"] = name
                try:
                    entry["beanType"] = select.getManager().getBeanTypeHandled()
                except (Exception, Throwable):
                    entry["beanType"] = None
                entry["exists"] = select.getManager().getNamedBean(name) is not None
        else:
            # Reference/LocalVariable/Formula/Table addressing -- no
            # fixed name exists to check; it's resolved at runtime.
            entry["configured"] = None
        refs.append(entry)
    return refs


def _logixng_walk_tree(base, depth=0):
    from jmri.jmrit.logixng import MaleSocket
    if depth > 50:
        # A genuine LogixNG tree is never anywhere near this deep --
        # a cap here turns a hypothetical cycle (a socket connected back
        # to one of its own ancestors, which JMRI's own editor is
        # supposed to prevent but this bridge shouldn't simply trust)
        # into a clean error instead of a JVM stack overflow.
        raise ValueError("LogixNG tree exceeds max depth 50 while walking -- possible cycle")

    node = {
        "class": base.getClass().getName(),
        "shortDescription": base.getShortDescription(),
        "beanReferences": _logixng_bean_references(base),
        "children": [],
    }
    for i in range(base.getChildCount()):
        female = base.getChild(i)
        child = {"socketName": female.getName(), "connected": female.isConnected()}
        if female.isConnected():
            male = female.getConnectedSocket()
            child["enabled"] = male.isEnabled()
            # A connected socket is not necessarily the leaf action/
            # expression directly -- confirmed live that it's commonly
            # wrapped a second time (jmri.jmrit.logixng.tools.debugger.
            # DebuggerMaleDigital{Action,Expression}Socket, present on
            # every socket in this rig's test ConditionalNG, not an
            # opt-in rarity) on top of the "normal" Default...Socket
            # wrapper, which is itself on top of the real object. Loop
            # until genuinely past every MaleSocket layer -- the same
            # pattern JMRI's own jmri.jmrit.logixng.util.WhereUsed (a
            # built-in "what uses this bean" tool doing a structurally
            # identical tree walk) uses for exactly this, not invented
            # here: `while (b instanceof MaleSocket) b = ((MaleSocket)
            # b).getObject();`. Getting this wrong silently produced
            # beanReferences: [] for every real node (the reflection
            # found no LogixNG_SelectNamedBean getters because it was
            # inspecting a socket wrapper class, not the action/
            # expression class that actually has them) -- caught by
            # actually building a real reference and checking the
            # result, not assumed from Base.java's interface alone.
            obj = male.getObject()
            while isinstance(obj, MaleSocket):
                obj = obj.getObject()
            child["node"] = _logixng_walk_tree(obj, depth + 1)
        node["children"].append(child)
    return node


def _logixng_audit(payload):
    """`name` may be either a system name or a user name, same lookup as
    `get`. Audits EVERY ConditionalNG the named LogixNG has (via
    getNumConditionalNGs()/getConditionalNG(i)) -- not just the first,
    unlike the ad-hoc script this replaces (jmri-mcp issue #7's own
    example only checked index 0).

    Live-confirmed against a real, deliberately non-trivial tree built on
    this test rig (a Timeout action -- two sockets, one connected to an
    ExpressionSensor referencing a real Sensor, the other deliberately
    left unconnected -- inside a ConditionalNG, inside a LogixNG), plus a
    genuinely dangling-reference scenario (an ActionTurnout referencing a
    Turnout that was then deleted via deleteBean(t, "DoDelete")) and a
    Reference-addressed expression (setAddressing(Reference) +
    setReference("{IS1}")). All three real gaps this caught before
    shipping, none obvious from Base.java's interface alone:
      1. A connected socket's object is wrapped, commonly twice (a
         jmri.jmrit.logixng.tools.debugger.DebuggerMaleDigital*Socket on
         top of the normal Default...Socket wrapper) -- getObject() must
         be called in a loop until the result is no longer a MaleSocket,
         same as JMRI's own jmri.jmrit.logixng.util.WhereUsed does; a
         single getObject() call left every real node's beanReferences
         empty, since the reflection was inspecting a socket wrapper
         class instead of the real action/expression class.
      2. A bean reference's NamedBeanHandle never usefully answers
         "does this still exist" via getBean() alone -- confirmed by the
         actual delete-then-recheck test, not reasoned from source alone
         (the handle came back null after "DoDelete", not a dangling
         non-null reference to a deleted object) -- see
         _logixng_bean_references's own comment for the mechanism.
      3. setReference(...) alone does not switch addressing to
         Reference -- setAddressing(NamedBeanAddressing.Reference) is a
         separate, required call; getAddressing() still read "Direct"
         after setReference() alone until that was added."""
    name = payload.get("name")
    logixng = _logixng_manager().getLogixNG(name)
    if logixng is None:
        raise ValueError("no LogixNG named %r" % (name,))

    conditional_ngs = []
    for i in range(logixng.getNumConditionalNGs()):
        cng = logixng.getConditionalNG(i)
        conditional_ngs.append({
            "name": cng.getSystemName(),
            "userName": cng.getUserName(),
            "enabled": cng.isEnabled(),
            "tree": _logixng_walk_tree(cng),
        })

    return {
        "name": logixng.getSystemName(),
        "userName": logixng.getUserName(),
        "conditionalNGs": conditional_ngs,
    }


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
# Five of the six target_types the client accepts (see jmri-mcp's TOOLS.md):
# signalMast, block, section, transit, connection. Each recipe below was
# proven live before being trusted, not written speculatively -- see each
# function's own comment for what that proving caught.
#
# connection's two operations (discover/generateSections, added 2026-09-25)
# needed a real correction to this project's own earlier assessment: reading
# SignalMastLogicManager.automaticallyDiscoverSignallingPairs()'s actual
# source shows no Swing/AWT calls anywhere in it -- it's pure model-layer
# graph traversal. The EDT-marshaling risk flagged in AGENT-DEBUGGING.md's
# "hangs or crashes JMRI's UI" section is real, but specific to JMRI's own
# GUI wrapper (SignalMastLogicTableAction, which marshals its OWN table-view
# refresh and dialog back onto the EDT via SwingUtilities.invokeAndWait) --
# a headless bridge call has no table view or dialog to refresh, so that
# part of the GUI's flow doesn't apply here. Confirmed live 2026-09-25:
# calling automaticallyDiscoverSignallingPairs() directly from this bridge's
# HTTP-worker-thread handler completed synchronously with no hang, both
# with zero signal masts configured (a safe no-op) and with two real
# VirtualSignalMasts temporarily attached to real PositionablePoints on this
# rig's "C&O in Virginia" panel.
#
# What DOES gate discover: it requires JMRI's "Advanced Layout Block
# Routing" preference enabled first (LayoutBlockManager.
# isAdvancedRoutingEnabled()) and its routing tables to have finished a
# background stabilisation pass (routingStablised()) -- confirmed live,
# ~3 seconds after enabling on this rig's ~200-element layout. This is a
# real, layout-wide, non-trivial toggle (kicks off a background routing
# computation over every block) -- deliberately NOT auto-enabled by
# discover itself; it's the caller's explicit choice via jmri_run_jython,
# with a clear error here if it hasn't been done. generateSections'
# generateBlockSections() does NOT share this precondition, confirmed by
# testing it both with and without Advanced Routing enabled and getting
# identical, correct results both times (it depends on each LayoutBlock's
# already-populated throughPaths list, not the advanced-routing-specific
# multi-hop tables) -- an initial theory that it needed the same
# precondition turned out to be wrong once actually tested, not assumed.
#
# Getting automaticallyDiscoverSignallingPairs() to find a genuine
# mast-to-mast pair (rather than a mast with an empty destination list, its
# own valid "found nothing reachable from here" result) needs signal masts
# positioned at real block-boundary PositionablePoints with facing
# directions this project didn't fully reverse-engineer -- not needed to
# validate that the operation itself is safe to expose, since a caller
# who's actually placed masts via jmri_run_jython/JMRI's own GUI has
# already solved that part.
#
# Deliberately NOT implemented, and not planned as a quick follow-on:
#
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
    """A MatrixSignalMast's or VirtualSignalMast's system name ENCODES its
    signal-system and mast-type -- confirmed against both classes' own
    configureFromName() (MatrixSignalMast.java: "IF$xsm:<system>:
    <mastType>($NNNN)"; VirtualSignalMast.java: "IF$vsm:<system>:
    <mastType>($NNNN)", same three-colon-part shape, just a different
    THE_MAST_TYPE prefix constant) -- so this builds that string from
    structured params rather than asking the caller to construct JMRI's
    own internal name format. getLastRef()/the "($NNNN)" ordinal is each
    class's OWN class-wide auto-numbering counter -- confirmed against
    source that VirtualSignalMast has the identical public static
    getLastRef()/protected setLastRef() pattern as MatrixSignalMast
    (MatrixSignalMast behavior live-confirmed 2026-09-22: creating one
    bumps it, so a second create with the same signalSystem/mastType
    doesn't collide; VirtualSignalMast not yet live-confirmed, same
    mechanism per source).

    params.mastClass selects which: "matrix" (default, unchanged from
    before this param existed -- existing callers that omit it keep
    getting a MatrixSignalMast) or "virtual". The two classes' `mastType`
    param means something DIFFERENT despite the shared name -- not a bug,
    just how JMRI itself defines each system name's third part:
      - "matrix": mastType is an arbitrary label for this bridge's own
        bit-pattern definitions -- params.aspects (a non-empty
        {aspect: bitPattern} mapping) is REQUIRED; passing a plain Python
        string ("0100") for the char[] setBitsForAspect expects works
        without manual conversion (confirmed live, Jython does this
        automatically).
      - "virtual": mastType must name an aspect-map table that ACTUALLY
        EXISTS for that signalSystem in JMRI's own signal-system XML data
        (e.g. "one-searchlight" for "basic" -- see
        jmri.implementation.VirtualSignalMast's own class javadoc example,
        confirmed against source) -- VirtualSignalMast.configureFromName()
        loads it by name via configureAspectTable(system, mast); an
        unknown system/mastType pair is a JMRI-side failure surfaced as
        whatever exception that load raises, not pre-validated here (no
        reason to duplicate JMRI's own lookup). params.aspects is NOT
        used for this mastClass -- the aspect table's own XML defines the
        valid aspects, not the caller.
    Both classes share jmri.implementation.AbstractSignalMast's
    getValidAspects() (confirmed against source) -- used here for BOTH
    mastClass values so the returned `aspects` field always reflects what
    JMRI itself now considers valid for the created mast, not (for
    "matrix") just an echo of the caller's own input keys."""
    params = payload.get("params") or {}
    mast_class = params.get("mastClass", "matrix")
    signal_system = params.get("signalSystem")
    mast_type = params.get("mastType")
    user_name = params.get("userName")
    if not signal_system or not mast_type:
        raise ValueError("signalMast create requires params.signalSystem and params.mastType")
    if mast_class not in ("matrix", "virtual"):
        raise ValueError("signalMast create requires params.mastClass to be 'matrix' or 'virtual' (got %r)" % (mast_class,))

    from jmri import InstanceManager, SignalMastManager

    if mast_class == "matrix":
        aspects = params.get("aspects")
        if not aspects:
            raise ValueError(
                "signalMast create with params.mastClass='matrix' requires "
                "params.aspects (a non-empty {aspect: bitPattern} mapping)"
            )
        from jmri.implementation import MatrixSignalMast
        ordinal = MatrixSignalMast.getLastRef() + 1
        system_name = "IF$xsm:%s:%s($%04d)" % (signal_system, mast_type, ordinal)
        mast = MatrixSignalMast(system_name, user_name) if user_name else MatrixSignalMast(system_name)
        for aspect, bits in aspects.items():
            mast.setBitsForAspect(aspect, bits)
    else:  # virtual
        from jmri.implementation import VirtualSignalMast
        ordinal = VirtualSignalMast.getLastRef() + 1
        system_name = "IF$vsm:%s:%s($%04d)" % (signal_system, mast_type, ordinal)
        mast = VirtualSignalMast(system_name, user_name) if user_name else VirtualSignalMast(system_name)

    InstanceManager.getDefault(SignalMastManager).register(mast)
    return {
        "name": mast.getSystemName(),
        "userName": mast.getUserName(),
        "class": mast.getClass().getName(),
        "mastClass": mast_class,
        "aspects": sorted(mast.getValidAspects()),
    }


# --- jmri_authoring: signalMastPlacement -----------------------------------
# LOGICAL (not physical/icon) signal-mast placement at Layout Editor
# connectivity boundaries -- the actual prerequisite for DispatcherPro's
# Signal Mast Logic (SML), confirmed against JMRI source
# (LayoutTurnout.java, PositionablePoint.java,
# jmri.implementation.DefaultSignalMastLogic, LayoutBlockManager.java):
# SML/Dispatcher's train-authority lookups (LayoutBlockManager.
# getFacingSignalMast(), DefaultSignalMastLogic.getFacingBlock()) read
# ONLY the signalAMast/B/C/D (LayoutTurnout) and eastBoundSignalMast/
# westBoundSignalMast (PositionablePoint) fields on these connectivity
# objects -- NEVER a SignalMastIcon placed on a panel (confirmed against
# every call site of LayoutEditor's own signalMastList: purely cosmetic,
# the one exception being a minor max-line-speed fallback in
# DispatcherFrame.java, unrelated to authority logic). This is exactly
# what cova-jmri's AutoPlaceSignalMasts-spec.md was designed around, as a
# standalone Jython script contribution to JMRI's own script library --
# these three operations bring that same capability into jmri-mcp
# instead, split into a granular `assign` (works for ANY existing mast,
# any class -- virtual, matrix, DCC, physical -- so a boundary can be
# migrated from a virtual placeholder to a real hardware-backed mast
# later just by calling `assign` again with the new mast's name) plus a
# bulk `apply` convenience that creates-then-assigns for every boundary
# lacking one, and a `discover` read-only report of every boundary and
# its current assignment state.
#
# CRITICAL, confirmed against JMRI source (NOT documented in JMRI's own
# javadoc for these methods): LayoutTurnout.setSignalAMast()/
# setSignalBMast()/setSignalCMast()/setSignalDMast() and
# PositionablePoint.setEastBoundSignalMast()/setWestBoundSignalMast() are
# ALL silent-failure void methods -- passing a mast name that doesn't
# resolve via SignalMastManager.getSignalMast() logs a JMRI-internal
# ERROR (that class's own logger, never raised to this caller) and
# leaves the field null/unchanged, with NOTHING thrown and NOTHING
# returned to check. Every assignment here reads the field back
# immediately after calling the setter and raises if it doesn't match
# what was requested -- never trusts the call silently (this project's
# own Unchecked-Result Rule scenario, found by reading source before
# writing this, not discovered by a live failure).
#
# Scope, deliberately (2026-09-28 design discussion): LayoutTurnout
# (ends A/B/C, plus D for DOUBLE_XOVER/RH_XOVER/LH_XOVER only -- via
# LayoutTurnout.isTurnoutTypeXover(), confirmed against source) and
# PositionablePoint (ANCHOR, END_BUMPER) only, matching
# AutoPlaceSignalMasts-spec.md's own coverage and Gville-arsenal.xml's
# current inventory (18 turnouts, 177 points, zero LevelXings). LevelXing
# and LayoutSlip signal-mast fields exist in JMRI (LevelXing.java has
# signalAMastNamed/signalBMastNamed; LayoutSlip extends LayoutTurnout so
# it's already covered incidentally via the LayoutTurnout branch below,
# not specially handled) but LevelXing support was explicitly deferred,
# not silently dropped -- add it if/when a real LevelXing shows up on
# this layout. EDGE_CONNECTOR points are also skipped (deliberately,
# same scope decision) even though PositionablePoint DOES support
# east/west masts for them (confirmed against source: getEastBoundSignal
# MastNamed()/getWestBoundSignalMastNamed() special-case EDGE_CONNECTOR,
# resolving direction via a PROTECTED getConnect1Dir() this bridge has no
# clean way to call) -- discover reports every skipped EDGE_CONNECTOR by
# name under `skippedEdgeConnectors` rather than omitting them silently
# (Data-Capture Backward-Chaining Rule: dropped-with-reason, not
# "didn't notice").
#
# Ambiguity resolved explicitly, not guessed silently (Threshold-Boundary
# Testing Rule): an END_BUMPER is a dead end with only ONE real direction
# of approach, but JMRI exposes no PUBLIC api on PositionablePoint to
# determine WHICH of east/west that is for a plain ANCHOR/END_BUMPER (only
# EDGE_CONNECTOR resolves it internally, via the same protected
# getConnect1Dir() noted above) -- so an END_BUMPER candidate's `end` is
# reported as the literal string "both", and `assign`/`apply` set BOTH
# eastBoundSignalMast and westBoundSignalMast to the SAME terminus mast for
# it. This is safe (not a guess dressed up as certainty): there is no track
# beyond a bumper in either direction, so whichever field SML/Dispatcher
# actually ends up reading, it reads the correct (only) mast; the other
# field's assignment is simply never queried, never wrong.

_TURNOUT_END_FIELDS = {
    "A": ("getSignalAMastName", "setSignalAMast"),
    "B": ("getSignalBMastName", "setSignalBMast"),
    "C": ("getSignalCMastName", "setSignalCMast"),
    "D": ("getSignalDMastName", "setSignalDMast"),
}
_TURNOUT_END_BLOCK_GETTERS = {
    "A": "getLayoutBlock",
    "B": "getLayoutBlockB",
    "C": "getLayoutBlockC",
    "D": "getLayoutBlockD",
}
_POINT_END_FIELDS = {
    "east": ("getEastBoundSignalMastName", "setEastBoundSignalMast"),
    "west": ("getWestBoundSignalMastName", "setWestBoundSignalMast"),
}
_TURNOUT_END_CONNECT_GETTERS = {
    "A": "getConnectA", "B": "getConnectB", "C": "getConnectC", "D": "getConnectD",
}


def _signal_mast_placement_block_name(layout_block):
    if layout_block is None:
        return None
    real_block = layout_block.getBlock()
    return real_block.getSystemName() if real_block is not None else None


def _turnout_leg_pointing_at(neighbor_turnout, target):
    """Which of `neighbor_turnout`'s own ends (A/B/C/D) connects back to
    `target` -- needed only for the rare case of two LayoutTurnouts wired
    directly together with no TrackSegment between them (most real
    connections go through a TrackSegment, handled separately below)."""
    for end, getter_name in _TURNOUT_END_CONNECT_GETTERS.items():
        if getattr(neighbor_turnout, getter_name)() is target:
            return end
    return None


def _neighbor_block_for_turnout_leg(track, end):
    """The LayoutBlock on the OTHER SIDE of this leg's real connection --
    NOT this leg's own assigned block. This is the check that actually
    matters for the common real-world case (confirmed empirically
    2026-09-28 against this bridge's own testDoubleOval fixture, cross-
    checked against `_get_block_boundaries`' already-proven
    LayoutEditorAuxTools-based mechanism, which caught this gap): a plain
    turnout is very often entirely inside ONE LayoutBlock (all of its own
    legs share the same block -- so a same-object leg-vs-leg comparison
    alone finds nothing), with the real boundary sitting between the
    turnout and whatever's connected beyond one specific leg. Returns
    None if unresolvable (no connection, or the connected object isn't a
    TrackSegment or another LayoutTurnout -- e.g. a LevelXing directly
    wired in, which is out of scope per this module's own scope note) --
    None here means "can't tell," not "confirmed no boundary," so it
    never manufactures a false boundary, only possibly misses one in
    this rare unresolvable case."""
    from jmri.jmrit.display.layoutEditor import LayoutTurnout, TrackSegment

    connect_getter = _TURNOUT_END_CONNECT_GETTERS.get(end)
    if connect_getter is None:
        return None
    neighbor = getattr(track, connect_getter)()
    if neighbor is None:
        return None
    if isinstance(neighbor, TrackSegment):
        return _signal_mast_placement_block_name(neighbor.getLayoutBlock())
    if isinstance(neighbor, LayoutTurnout):
        neighbor_end = _turnout_leg_pointing_at(neighbor, track)
        if neighbor_end is None:
            return None
        neighbor_block_getter = _TURNOUT_END_BLOCK_GETTERS[neighbor_end]
        return _signal_mast_placement_block_name(getattr(neighbor, neighbor_block_getter)())
    return None


def _find_layout_turnout(name):
    """Searches every open Layout Editor panel's LayoutTracks for a
    LayoutTurnout (which LayoutSlip/LayoutXOver both extend, same as
    elsewhere in this file) with this exact icon name -- NOT the
    underlying Turnout bean's own system name, a different, separately-
    named object (see the module comment above)."""
    from jmri import InstanceManager
    from jmri.jmrit.display import EditorManager
    from jmri.jmrit.display.layoutEditor import LayoutEditor, LayoutTurnout

    for editor in InstanceManager.getDefault(EditorManager).getAll():
        if not isinstance(editor, LayoutEditor):
            continue
        for track in editor.getLayoutTracks():
            if isinstance(track, LayoutTurnout) and track.getName() == name:
                return track
    return None


def _find_positionable_point(name):
    from jmri import InstanceManager
    from jmri.jmrit.display import EditorManager
    from jmri.jmrit.display.layoutEditor import LayoutEditor

    for editor in InstanceManager.getDefault(EditorManager).getAll():
        if not isinstance(editor, LayoutEditor):
            continue
        for pp in editor.getPositionablePoints():
            if pp.getName() == name:
                return pp
    return None


def _signal_mast_placement_set_and_verify(element, end, field_map, mast_name):
    if end not in field_map:
        raise ValueError("unrecognized end %r (known: %s)" % (end, sorted(field_map.keys())))
    getter_name, setter_name = field_map[end]
    getattr(element, setter_name)(mast_name)
    actual = getattr(element, getter_name)()
    if actual != mast_name:
        raise ValueError(
            "%s(%r) did not take effect -- %s() now reports %r. JMRI silently "
            "refuses this assignment when the mast name doesn't resolve to an "
            "existing SignalMast (logged server-side as a JMRI-internal ERROR, "
            "not raised here) -- confirm %r is an existing SignalMast's system "
            "or user name." % (setter_name, mast_name, getter_name, actual, mast_name)
        )
    return actual


def _authoring_signal_mast_placement_discover(payload):
    """Read-only: every real signal-mast boundary on each open Layout
    Editor panel -- LayoutTurnout ends that need a mast, and
    PositionablePoint (ANCHOR) connections whose two sides differ --
    each annotated with its CURRENT mast assignment (empty string if
    none), so a caller can tell an already-wired boundary from one that
    still needs one without a separate round trip. See the module
    comment above for the exact scope (LayoutTurnout + PositionablePoint
    only) and the END_BUMPER "both" / EDGE_CONNECTOR-skip decisions.

    A turnout end qualifies as a boundary via EITHER of two independent
    checks (candidate if either is true) -- both matter, confirmed
    empirically 2026-09-28 against this bridge's own testDoubleOval
    fixture, cross-checked against `_get_block_boundaries`'s already-
    proven LayoutEditorAuxTools mechanism:
      1. ITS OWN block differs from AT LEAST ONE other end's block on
         the SAME turnout object (a plain, non-crossover turnout can
         legitimately have different blocks on different legs -- e.g. a
         siding entrance -- confirmed against LayoutTurnout.java's own
         internal block-comparison logic, e.g. `lbA != lbC`, which is
         not gated on crossover type).
      2. ITS OWN block differs from the block of whatever's actually
         CONNECTED beyond that leg (`_neighbor_block_for_turnout_leg()`)
         -- this is the common real-world case check #1 alone MISSES: a
         plain turnout is very often entirely inside ONE block (all legs
         share the same block), with the real boundary sitting between
         the turnout and the next block beyond one specific leg. An
         earlier version of this operation checked #1 only and found
         ZERO candidates on a turnout deliberately set up this way in
         testing, while `_get_block_boundaries` correctly found one --
         that comparison is what caught this gap before it shipped.
    An end with no LayoutBlock assigned at all is not a candidate
    (nothing to protect).

    Returns {"candidates": [...], "count", "skippedEdgeConnectors"}. Each
    candidate: {"panel", "elementType": "turnout"|"point", "elementName",
    "end", "block", "currentMastName", plus "turnoutType" (turnout) or
    "pointType"/"neighborBlock" (point, ANCHOR only)}."""
    from jmri import InstanceManager
    from jmri.jmrit.display import EditorManager
    from jmri.jmrit.display.layoutEditor import LayoutEditor, LayoutTurnout

    candidates = []
    skipped_edge_connectors = []

    for editor in InstanceManager.getDefault(EditorManager).getAll():
        if not isinstance(editor, LayoutEditor):
            continue
        panel_name = editor.getTitle()

        for track in editor.getLayoutTracks():
            if not isinstance(track, LayoutTurnout):
                continue
            ends = ["A", "B", "C"]
            if LayoutTurnout.isTurnoutTypeXover(track.getTurnoutType()):
                ends.append("D")
            end_blocks = {
                end: _signal_mast_placement_block_name(getattr(track, _TURNOUT_END_BLOCK_GETTERS[end])())
                for end in ends
            }
            for end in ends:
                this_block = end_blocks[end]
                if this_block is None:
                    continue
                differs_internally = any(
                    end_blocks[other] is not None and end_blocks[other] != this_block
                    for other in ends if other != end
                )
                neighbor_block = _neighbor_block_for_turnout_leg(track, end)
                differs_from_neighbor = neighbor_block is not None and neighbor_block != this_block
                if not (differs_internally or differs_from_neighbor):
                    continue
                mast_getter = _TURNOUT_END_FIELDS[end][0]
                candidates.append({
                    "panel": panel_name,
                    "elementType": "turnout",
                    "elementName": track.getName(),
                    "turnoutType": track.getTurnoutType().toString(),
                    "end": end,
                    "block": this_block,
                    "neighborBlock": neighbor_block,
                    "currentMastName": getattr(track, mast_getter)(),
                })

        for pp in editor.getPositionablePoints():
            point_type = pp.getType().toString()
            if point_type == "EDGE_CONNECTOR":
                skipped_edge_connectors.append(pp.getName())
                continue
            if point_type == "ANCHOR":
                c1, c2 = pp.getConnect1(), pp.getConnect2()
                block1 = _signal_mast_placement_block_name(c1.getLayoutBlock()) if c1 is not None else None
                block2 = _signal_mast_placement_block_name(c2.getLayoutBlock()) if c2 is not None else None
                if block1 is None or block2 is None or block1 == block2:
                    continue
                for end in ("east", "west"):
                    candidates.append({
                        "panel": panel_name,
                        "elementType": "point",
                        "elementName": pp.getName(),
                        "pointType": point_type,
                        "end": end,
                        "block": block1,
                        "neighborBlock": block2,
                        "currentMastName": getattr(pp, _POINT_END_FIELDS[end][0])(),
                    })
            elif point_type == "END_BUMPER":
                c1 = pp.getConnect1()
                block1 = _signal_mast_placement_block_name(c1.getLayoutBlock()) if c1 is not None else None
                # Single "both" candidate, not separate east/west entries --
                # see the module comment's Ambiguity-resolved-explicitly note.
                east_mast = pp.getEastBoundSignalMastName()
                west_mast = pp.getWestBoundSignalMastName()
                candidates.append({
                    "panel": panel_name,
                    "elementType": "point",
                    "elementName": pp.getName(),
                    "pointType": point_type,
                    "end": "both",
                    "block": block1,
                    "currentMastName": east_mast or west_mast,
                })

    return {
        "candidates": candidates,
        "count": len(candidates),
        "skippedEdgeConnectors": skipped_edge_connectors,
    }


def _authoring_signal_mast_placement_assign(payload):
    """Granular, mastClass-agnostic assignment: writes an EXISTING
    SignalMast's name onto one boundary end (a LayoutTurnout leg or a
    PositionablePoint direction). Deliberately separate from `apply`'s
    create-then-assign convenience so a boundary can be migrated from a
    virtual placeholder mast to a real hardware-backed one later just by
    calling this again with the new mast's name -- no different code
    path needed for that migration.

    params.elementType: "turnout" | "point".
    params.elementName: the LayoutTurnout's or PositionablePoint's own
        icon name (as `discover`'s `elementName` reports it) -- NOT the
        underlying Turnout bean's system name.
    params.end: "A"/"B"/"C"/"D" for a turnout; "east"/"west"/"both" for a
        point ("both" sets both fields to the same mast -- see the
        module comment's END_BUMPER note; valid for any point, not just
        END_BUMPER, if a caller wants symmetric assignment).
    params.mastName: an EXISTING SignalMast's system or user name --
        resolved either way (SignalMastManager.getSignalMast() checks
        user name then system name, confirmed against source) and
        checked to exist BEFORE touching the turnout/point, so a typo
        can't silently null out an existing assignment (setSignalAMast(
        None-resolving-name) sets the field to null, not a no-op --
        confirmed against source)."""
    params = payload.get("params") or {}
    element_type = params.get("elementType")
    element_name = params.get("elementName")
    end = params.get("end")
    mast_name = params.get("mastName")
    if element_type not in ("turnout", "point"):
        raise ValueError("signalMastPlacement assign requires params.elementType to be 'turnout' or 'point'")
    if not element_name:
        raise ValueError("signalMastPlacement assign requires params.elementName")
    if not mast_name:
        raise ValueError("signalMastPlacement assign requires params.mastName (an existing SignalMast's name)")

    from jmri import InstanceManager, SignalMastManager
    if InstanceManager.getDefault(SignalMastManager).getSignalMast(mast_name) is None:
        raise ValueError("no such SignalMast %r" % (mast_name,))

    if element_type == "turnout":
        element = _find_layout_turnout(element_name)
        if element is None:
            raise ValueError("no LayoutTurnout named %r on any open panel" % (element_name,))
        if end == "both":
            raise ValueError("end='both' is only meaningful for a point, not a turnout")
        _signal_mast_placement_set_and_verify(element, end, _TURNOUT_END_FIELDS, mast_name)
        return {"elementType": element_type, "elementName": element_name, "end": end, "mastName": mast_name}

    element = _find_positionable_point(element_name)
    if element is None:
        raise ValueError("no PositionablePoint named %r on any open panel" % (element_name,))
    if end == "both":
        _signal_mast_placement_set_and_verify(element, "east", _POINT_END_FIELDS, mast_name)
        _signal_mast_placement_set_and_verify(element, "west", _POINT_END_FIELDS, mast_name)
    else:
        _signal_mast_placement_set_and_verify(element, end, _POINT_END_FIELDS, mast_name)
    return {"elementType": element_type, "elementName": element_name, "end": end, "mastName": mast_name}


def _authoring_signal_mast_placement_apply(payload):
    """Bulk convenience: for every boundary `discover` finds WITHOUT an
    existing mast assignment, creates a new SignalMast (via the same
    logic as `create`, target_type=signalMast) and assigns it (via the
    same logic as `assign` above) -- not a separate reimplementation of
    either.

    params.signalSystem, params.mastType, params.mastClass ("matrix" |
    "virtual") are all REQUIRED, deliberately with no default -- which
    mast class/system to use for boundary masts is a per-layout, per-run
    decision (e.g. virtual placeholders now to get DispatcherPro running,
    a real hardware-backed mast type later for specific boundaries once
    they're physically wired), not something this bulk operation should
    silently assume on the caller's behalf (2026-09-28 design decision).
    params.aspects is required when mastClass="matrix" (see `create`);
    unused when mastClass="virtual".
    params.dryRun (optional, default False): report what WOULD be
    created/assigned, without calling create or assign at all.
    params.userNamePrefix (optional, default "SM"): naming convention,
    following AutoPlaceSignalMasts-spec.md's own scheme where the
    direction is unambiguous -- "<prefix>-<turnoutName>-<end>" for a
    turnout end, "<prefix>-terminus-<pointName>" for an end-bumper.
    For an anchor point (where east vs west isn't derivable from any
    JMRI API this bridge can call -- see the module comment), the spec's
    own "reverse for west" naming can't be followed correctly, so this
    uses "<prefix>-<block>-to-<neighborBlock>-<end>" instead, appending
    the end label rather than guessing which block name belongs first --
    still unique and idempotent, just not the spec's exact string.

    Never fails the whole batch on one boundary's error (Data-Capture
    Backward-Chaining Rule: no silent drops) -- each candidate's outcome
    ("skipped_already_assigned" | "dry_run" | "created_and_assigned" |
    "error") is reported individually in `results`; `errorCount` is
    nonzero if anything failed, so a caller can't miss a partial failure
    by only checking the top-level response shape."""
    params = payload.get("params") or {}
    signal_system = params.get("signalSystem")
    mast_type = params.get("mastType")
    mast_class = params.get("mastClass")
    dry_run = bool(params.get("dryRun", False))
    user_name_prefix = params.get("userNamePrefix") or "SM"
    if not signal_system or not mast_type:
        raise ValueError("signalMastPlacement apply requires params.signalSystem and params.mastType")
    if mast_class not in ("matrix", "virtual"):
        raise ValueError(
            "signalMastPlacement apply requires params.mastClass to be 'matrix' or "
            "'virtual' -- no default, this is a deliberate per-run choice (see docstring)"
        )
    if mast_class == "matrix" and not params.get("aspects"):
        raise ValueError("signalMastPlacement apply requires params.aspects when params.mastClass='matrix'")

    discovered = _authoring_signal_mast_placement_discover(payload)
    results = []
    error_count = 0
    for candidate in discovered["candidates"]:
        if candidate["currentMastName"]:
            results.append(dict(candidate, outcome="skipped_already_assigned"))
            continue

        if candidate["elementType"] == "turnout":
            user_name = "%s-%s-%s" % (user_name_prefix, candidate["elementName"], candidate["end"])
        elif candidate["pointType"] == "END_BUMPER":
            user_name = "%s-terminus-%s" % (user_name_prefix, candidate["elementName"])
        else:  # ANCHOR
            user_name = "%s-%s-to-%s-%s" % (
                user_name_prefix, candidate["block"], candidate.get("neighborBlock") or "?", candidate["end"],
            )

        if dry_run:
            results.append(dict(candidate, outcome="dry_run", plannedUserName=user_name))
            continue

        try:
            create_params = {
                "signalSystem": signal_system, "mastType": mast_type,
                "mastClass": mast_class, "userName": user_name,
            }
            if mast_class == "matrix":
                create_params["aspects"] = params["aspects"]
            created = _authoring_create_signal_mast({"params": create_params})

            assigned = _authoring_signal_mast_placement_assign({"params": {
                "elementType": candidate["elementType"],
                "elementName": candidate["elementName"],
                "end": candidate["end"],
                "mastName": created["name"],
            }})
            results.append(dict(candidate, outcome="created_and_assigned", mastName=assigned["mastName"]))
        except (Exception, Throwable) as exc:
            error_count += 1
            results.append(dict(candidate, outcome="error", error="%s: %s" % (type(exc).__name__, exc)))

    return {"results": results, "count": len(results), "errorCount": error_count, "dryRun": dry_run}


_SIGNAL_HEAD_TURNOUT_PARAMS = {
    "virtual": (),
    "doubleTurnout": ("redTurnout", "greenTurnout"),
    "tripleTurnout": ("redTurnout", "yellowTurnout", "greenTurnout"),
}


def _authoring_create_signal_head(payload):
    """jmri-mcp issue #11. Unlike every other jmri_authoring create
    target_type, SignalHeadManager (confirmed against its interface --
    unlike BlockManager's createNewBlock(userName)) exposes no manager-
    level auto-naming helper -- the caller supplies a complete system
    name directly (params.name, e.g. "IH47" on JMRI's always-present
    Internal connection), matching the convention jmri_state's own
    `create` operation (issue #10) already uses for turnout/sensor/light.
    Checks the name doesn't already exist first and refuses rather than
    risk silently replacing a real head -- same reasoning as that
    operation's own existence guard, just enforced bridge-side here since
    there's no JMRI-side creates-or-updates PUT to worry about instead.

    params.headType selects the concrete SignalHead subclass. The fixed
    appearance-to-turnout-state mappings below are read directly from
    JMRI's own source (jmri.implementation.DoubleTurnoutSignalHead /
    TripleTurnoutSignalHead's updateOutput()), not guessed or inferred
    from behavior -- neither class exposes any way to reconfigure them:

      "virtual": jmri.implementation.VirtualSignalHead. No turnouts
          needed -- pure software. For testing signal logic
          (SignalMastLogic, LogixNG conditions, etc.) without real
          hardware. Does NOT support LUNAR/FLASHLUNAR -- confirmed
          against source: it doesn't override getValidStates(), so it
          inherits DefaultSignalHead's own default set (DARK/RED/YELLOW/
          GREEN + their FLASH variants only; that base class's own source
          comment reads "// Lunar not included"). An initial version of
          this docstring claimed the opposite before this was checked
          live -- POSTing {"state": 64} to a freshly-created virtual head
          gets a clean JMRI-side 400 "unknown state 64", not a crash, but
          also not the LUNAR support this originally (wrongly) promised.
      "doubleTurnout": jmri.implementation.DoubleTurnoutSignalHead.
          params.redTurnout, params.greenTurnout (existing Turnout
          names). RED = red THROWN + green CLOSED; GREEN = red CLOSED +
          green THROWN; YELLOW = both THROWN; DARK = both CLOSED. No
          LUNAR here either -- falls through to a JMRI-side log warning +
          DARK.
      "tripleTurnout": jmri.implementation.TripleTurnoutSignalHead.
          params.redTurnout, params.yellowTurnout, params.greenTurnout
          (existing Turnout names). Each color drives its own dedicated
          turnout THROWN, the other two CLOSED. Same no-LUNAR fallthrough
          as doubleTurnout.

    Turnout references are resolved to NamedBeanHandles via
    NamedBeanHandleManager.getNamedBeanHandle() -- matching how JMRI's
    own signal-head-creation code does it (confirmed against
    DoubleTurnoutSignalHead's constructor signature, which takes
    NamedBeanHandle<Turnout> not a bare Turnout) -- rather than the raw
    NamedBeanHandle constructor, so a later turnout rename stays tracked
    correctly instead of leaving a stale handle."""
    params = payload.get("params") or {}
    name = params.get("name")
    user_name = params.get("userName")
    head_type = params.get("headType")
    if not name:
        raise ValueError('signalHead create requires params.name (a complete JMRI system name, e.g. "IH47")')
    if head_type not in _SIGNAL_HEAD_TURNOUT_PARAMS:
        raise ValueError(
            "signalHead create requires params.headType to be one of %s"
            % (sorted(_SIGNAL_HEAD_TURNOUT_PARAMS.keys()),)
        )

    from jmri import InstanceManager, NamedBeanHandleManager, SignalHeadManager
    from jmri.implementation import DoubleTurnoutSignalHead, TripleTurnoutSignalHead, VirtualSignalHead

    mgr = InstanceManager.getDefault(SignalHeadManager)
    if mgr.getBySystemName(name) is not None:
        raise ValueError("signalHead %r already exists -- create refuses to replace an existing bean" % (name,))

    turnout_mgr = InstanceManager.turnoutManagerInstance()
    handle_mgr = InstanceManager.getDefault(NamedBeanHandleManager)

    def turnout_handle(param_name):
        turnout_name = params.get(param_name)
        if not turnout_name:
            raise ValueError(
                "signalHead create with headType=%r requires params.%s (an existing Turnout name)"
                % (head_type, param_name)
            )
        turnout = _lookup_named_bean(turnout_mgr, turnout_name)
        if turnout is None:
            raise ValueError("no such Turnout %r (referenced by params.%s)" % (turnout_name, param_name))
        return handle_mgr.getNamedBeanHandle(turnout.getSystemName(), turnout)

    handles = [turnout_handle(p) for p in _SIGNAL_HEAD_TURNOUT_PARAMS[head_type]]

    if head_type == "virtual":
        head = VirtualSignalHead(name, user_name) if user_name else VirtualSignalHead(name)
    elif head_type == "doubleTurnout":
        red, green = handles
        head = (
            DoubleTurnoutSignalHead(name, user_name, green, red)
            if user_name
            else DoubleTurnoutSignalHead(name, green, red)
        )
    else:  # tripleTurnout
        red, yellow, green = handles
        head = (
            TripleTurnoutSignalHead(name, user_name, green, yellow, red)
            if user_name
            else TripleTurnoutSignalHead(name, green, yellow, red)
        )

    mgr.register(head)
    return {
        "name": head.getSystemName(),
        "userName": head.getUserName(),
        "class": head.getClass().getName(),
        "headType": head_type,
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


# --- Section/Transit get/set/delete -----------------------------------
# jmri-mcp issue tracker follow-up (Section/Transit CRUD): JMRI's JSON
# Servlet has no HTTP API for section/transit at all (confirmed live --
# GET /json/section, /json/transit both answer a clean 404 "Unknown
# object type", not just an unlisted-but-forwardable type the way block
# was) -- unlike block/signalHead, this can never move to jmri_state; it
# has to live here.
#
# Section.state (FREE/FORWARD/REVERSE) is genuinely mutable, Dispatcher-
# relevant config -- confirmed against DefaultSection.java's own
# setState(), which also flips the Section's forward/reverse blocking
# sensors as a side effect. Values confirmed live against the real JVM
# (not assumed from the constant names): UNKNOWN=1, FREE=2, FORWARD=4,
# REVERSE=8, OCCUPIED=2, UNOCCUPIED=4 -- note OCCUPIED and FREE share the
# same int value (2) despite being unrelated properties (Block.state's
# OCCUPIED vs Section.state's FREE), so these two little maps must never
# be confused for one general "state int" lookup.
_SECTION_STATE_NAMES = {1: "UNKNOWN", 2: "FREE", 4: "FORWARD", 8: "REVERSE"}
_SECTION_STATE_VALUES = {"FREE": 2, "FORWARD": 4, "REVERSE": 8}
_SECTION_OCCUPANCY_NAMES = {2: "OCCUPIED", 4: "UNOCCUPIED"}

# Transit.state (IDLE/ASSIGNED) is Dispatcher-internal bookkeeping --
# confirmed against DefaultTransit.java, it just tracks whether an
# ActiveTrain currently has this Transit assigned, with no side effects
# of its own. Deliberately NOT exposed as a `set` here: jmri-mcp has no
# ActiveTrain/Dispatcher wrapping yet, so setting this by hand would
# produce a Transit marked ASSIGNED with no real train behind it --
# confusing, inconsistent-with-reality state for no benefit until that
# layer exists. `get` still reports it (read-only) since it's genuinely
# informative once Dispatcher usage exists on a layout.
_TRANSIT_STATE_NAMES = {2: "IDLE", 4: "ASSIGNED"}


def _section_manager():
    from jmri import InstanceManager, SectionManager
    return InstanceManager.getDefault(SectionManager)


def _transit_manager():
    from jmri import InstanceManager, TransitManager
    return InstanceManager.getDefault(TransitManager)


def _section_info(section):
    state = section.getState()
    occupancy = section.getOccupancy()
    return {
        "name": section.getSystemName(),
        "userName": section.getUserName(),
        "sectionType": str(section.getSectionType()),
        "blocks": [b.getSystemName() for b in section.getBlockList()],
        "state": state,
        "stateName": _SECTION_STATE_NAMES.get(state, "UNKNOWN"),
        "occupancy": occupancy,
        "occupancyName": _SECTION_OCCUPANCY_NAMES.get(occupancy, "UNKNOWN"),
    }


def _transit_info(transit):
    state = transit.getState()
    return {
        "name": transit.getSystemName(),
        "userName": transit.getUserName(),
        "sections": [
            {"name": ts.getSectionName(), "sequenceNumber": ts.getSequenceNumber(), "direction": ts.getDirection()}
            for ts in transit.getTransitSectionList()
        ],
        "state": state,
        "stateName": _TRANSIT_STATE_NAMES.get(state, "UNKNOWN"),
    }


def _introspect_get_section(payload):
    name = payload.get("name")
    if not name:
        raise ValueError("get_section requires `name`")
    section = _lookup_named_bean(_section_manager(), name)
    if section is None:
        raise ValueError("no Section named %r" % (name,))
    return _section_info(section)


def _introspect_get_transit(payload):
    name = payload.get("name")
    if not name:
        raise ValueError("get_transit requires `name`")
    transit = _lookup_named_bean(_transit_manager(), name)
    if transit is None:
        raise ValueError("no Transit named %r" % (name,))
    return _transit_info(transit)


def _authoring_set_section_state(payload):
    params = payload.get("params") or {}
    name = params.get("name")
    state_name = params.get("state")
    if not name:
        raise ValueError("setState requires params.name")
    if state_name not in _SECTION_STATE_VALUES:
        raise ValueError(
            "section setState requires params.state to be one of %s (UNKNOWN is not "
            "settable -- confirmed against Section.setState()'s own source, which "
            "rejects it)" % (sorted(_SECTION_STATE_VALUES.keys()),)
        )
    section = _lookup_named_bean(_section_manager(), name)
    if section is None:
        raise ValueError("no Section named %r" % (name,))
    section.setState(_SECTION_STATE_VALUES[state_name])
    return _section_info(section)


def _delete_named_bean(manager, name, label):
    """Shared safe-delete: fires JMRI's own "CanDelete" veto check first
    and refuses (raises rather than forcing the delete through) if
    ANYTHING objects. This bridge's own test-cleanup scripts use the
    "DoDelete"-only shortcut throughout jmri-mcp's development (bypassing
    vetoes, appropriate for known-safe scratch objects created and torn
    down in the same script) -- a `jmri_authoring` `delete` operation
    exposed to a real caller must not do that.

    A real nuance here, confirmed against AbstractManager.
    fireVetoableChange() and DefaultTransit.vetoableChange()'s actual
    source, not assumed: "CanDelete" has TWO distinct severities baked
    into the same exception type. A listener that re-throws with
    property name "DoNotDelete" is a genuine hard block (JMRI itself
    won't proceed past it even if forced). Anything else -- e.g.
    DefaultTransit's own veto when asked to delete a Section it
    contains, confirmed live to carry property name "CanDelete", not
    "DoNotDelete" -- is informational: a real GUI shows it as a "this is
    used elsewhere, delete anyway?" confirmation, and proceeding to
    "DoDelete" is allowed. Deliberately NOT distinguishing between the
    two here anyway: confirmed against DefaultTransit's own source that
    NOTHING handles cleaning up a Transit's reference on the "DoDelete"
    side (no vetoableChange branch for it at all) despite the veto
    message's own claim ("It will be removed from the Transits") --  so
    proceeding past an informational veto would leave a Transit holding
    a genuinely dangling Section reference, exactly the failure mode
    jmri_logixng's `audit` operation (a separate feature) exists to
    detect elsewhere. With no human to show a confirmation dialog to and
    no verified automatic cleanup to rely on, refusing on ANY veto --
    hard or informational -- is the safe default until there's a real
    reason to add an explicit force-through option."""
    from java.beans import PropertyVetoException

    bean = _lookup_named_bean(manager, name)
    if bean is None:
        raise ValueError("no %s named %r" % (label, name))
    try:
        manager.deleteBean(bean, "CanDelete")
    except PropertyVetoException as veto:
        message = veto.getMessage()
        if message and message.strip():
            raise ValueError("cannot delete %s %r: %s" % (label, name, message))
        # Empty message -- confirmed against AbstractManager.
        # fireVetoableChange()'s own source that "CanDelete" throws a
        # PropertyVetoException UNCONDITIONALLY at the end of its
        # listener loop, even when not one listener actually objected
        # (message.toString() on the never-appended-to StringBuilder is
        # just ""). Caught live: deleting a genuinely unreferenced
        # Transit still raised this exact empty-message exception --
        # treating that as a real refusal would make delete permanently
        # unusable for anything with no real objections. An empty
        # message here means nothing, proceed.
    manager.deleteBean(bean, "DoDelete")
    return {"name": bean.getSystemName(), "deleted": True}


def _authoring_delete_section(payload):
    name = (payload.get("params") or {}).get("name")
    if not name:
        raise ValueError("delete requires params.name")
    return _delete_named_bean(_section_manager(), name, "Section")


def _authoring_delete_transit(payload):
    name = (payload.get("params") or {}).get("name")
    if not name:
        raise ValueError("delete requires params.name")
    return _delete_named_bean(_transit_manager(), name, "Transit")


def _authoring_create_test_oval(payload):
    """Builds a synthetic rectangular test loop -- four corner anchors and
    one RH crossover per side, wired into the through route -- entirely
    in-memory on a freshly-created LayoutEditor panel, so jmri-mcp
    development/testing has an "obvious" fixture with real crossover
    objects on it without touching this profile's real layout panels.
    Nothing here is ever persisted (no store/save call anywhere in this
    function) -- discard by disposing the panel or restarting JMRI without
    saving; there is deliberately no delete/teardown operation to go with
    this one.

    Two things live-testing caught building this, neither obvious from the
    API alone:
      - LayoutEditor.addLayoutTurnout()/addTrackSegment()/etc. are the GUI
        toolbar's own click-handlers -- they read private mouse-position
        and live combo-box selections, not parameters, so they cannot be
        called headlessly. This constructs LayoutTrack/LayoutTrackView
        pairs directly (the same shape JMRI's own XML panel loader uses)
        and registers each via the real underlying primitive,
        LayoutEditor.addLayoutTrack(track, view).
      - A TrackSegment's own constructor only wires the segment's view of
        its endpoints (segment -> point/turnout-leg); the reverse link
        (point/turnout-leg -> segment) needs a separate, explicit call --
        PositionablePoint.setTrackConnection(segment) for a point end,
        LayoutTurnout.setConnectA/B/C/D(segment, HitPointType.TRACK) for a
        turnout leg. Skipping this produces a segment that LOOKS fully
        built (no exception, its own connect1/connect2 fields populated)
        but whose endpoints report no connection at all (getConnect1()
        returns null) -- confirmed live 2026-09-22, the first build
        attempt hit exactly this before the fix.

    All Swing-panel mutation here runs wrapped in
    ThreadingUtil.runOnGUIwithReturn() -- confirmed live 2026-09-22 that
    this bridge's own HTTP worker thread is not the EDT
    (SwingUtilities.isEventDispatchThread() is False there, True inside
    the wrapped callback), matching every other LayoutEditor-mutating
    operation's documented need for this (see jmri-mcp's usage_guidance.py
    edt-thread-safety note). A single unwrapped call also completed
    without error in testing, but that's not proof of safety under
    contention -- the wrapper costs nothing measurable, so there's no
    reason to skip it.

    Each of the four crossovers gets TWO real Turnout beans on JMRI's
    Internal connection (system name prefix "IT", via
    TurnoutManager.provideTurnout) -- a synthetic test fixture must never
    be able to command real hardware, even by accident, so this
    deliberately avoids whatever connection(s) this profile's real layout
    uses (LCC/MQTT/SPROG DCC, none of them "I"). Two beans per crossover,
    not one, because that's what an RH/LH single crossover actually is
    prototypically: two switch points (one where the diagonal departs the
    first track, one where it rejoins the second -- see the two `**`
    marks in LayoutXOver.java's own ASCII-art javadoc), which is exactly
    what LayoutTurnout's optional secondTurnoutName field
    (setSecondTurnout()) exists to represent. A caller building this for
    real would need two physical turnouts and two servos/Tortoises, not
    one -- confirmed against the user's own FastTracks-built-turnout
    workflow 2026-09-23. setTurnout() binds the first (A/B side),
    setSecondTurnout() the second (C/D side); secondTurnoutInverted is
    left at its default (False), matching the common case where both
    switch points move in lockstep as one commanded crossover throw.

    Only the A-B "through" route of each RH crossover is wired into the
    loop (per LayoutXOver.java's own javadoc: A-B and C-D are the straight
    continuing routes, A-C/B-D are the diverging routes) -- the C/D legs
    are deliberately left unconnected for this first version. A crossover
    with unconnected legs is a normal, valid JMRI object (get_panel_
    structure already handles exactly this case on real panels), and
    diverging-route stub track was judged out of scope for a v1 test
    fixture -- extend here if a caller actually needs it.

    params (all optional): editorName (default "Test Oval" -- JMRI allows
    duplicate panel names across separate LayoutEditor instances, only
    warns, so pass a distinct name to keep multiple test ovals apart
    rather than relying on this to reject a collision), centerX/centerY
    (default 300/300), width/height (default 400/300, pixels).

    A freshly-constructed LayoutEditor defaults to Editor.SCROLL_NONE
    (Editor.java's own field default, not something set here) -- in that
    mode the target canvas is forced to always exactly match the WINDOW's
    current size (a deliberate JMRI behavior, confirmed by reading
    LayoutEditor's adjustScrollBars()/resetTargetSize()), not the
    panelWidth/panelHeight the content actually needs. A headless
    construction like this one never gets the window resized by a human
    before anything might persist it, so whatever AWT/Swing defaults the
    window to (confirmed live 2026-09-23: nearly the full primary-screen
    resolution) gets baked in as the "correct" size. If that huge window
    size is later restored from a saved file, JMRI dutifully regrows the
    canvas to match it again on load -- and depending on how the viewport
    ends up scrolled at that huge size, the actual track content (drawn
    at small, sane coordinates near the origin) can end up scrolled
    completely out of view, a real, live-confirmed failure mode, not a
    hypothetical one. setScroll("both") plus an explicit, sane setSize()
    sidesteps this entirely -- the canvas keeps a fixed logical size
    regardless of window size, with real scrollbars for the rest, which
    is how virtually every genuine layout (bigger than one screen) is
    already used anyway."""
    from java.awt import Dimension
    from java.awt.geom import Point2D
    from jmri import InstanceManager
    from jmri.jmrit.display.layoutEditor import (
        LayoutEditor, LayoutRHXOver, LayoutRHXOverView,
        TrackSegment, TrackSegmentView, HitPointType,
    )
    from jmri.util import ThreadingUtil
    import uuid as _uuid

    params = payload.get("params") or {}
    editor_name = params.get("editorName") or "Test Oval"
    center_x = float(params.get("centerX", 300.0))
    center_y = float(params.get("centerY", 300.0))
    width = float(params.get("width", 400.0))
    height = float(params.get("height", 300.0))
    if width <= 0 or height <= 0:
        raise ValueError("testOval create requires width > 0 and height > 0")

    half_w = width / 2.0
    half_h = height / 2.0
    suffix = _uuid.uuid4().hex[:6]

    def build():
        editor = LayoutEditor(editor_name)
        editor.setVisible(True)
        editor.setScroll("both")
        editor.setSize(Dimension(750, 700))

        turnout_mgr = InstanceManager.turnoutManagerInstance()

        corners = {
            "NW": editor.addAnchor(Point2D.Double(center_x - half_w, center_y - half_h)),
            "NE": editor.addAnchor(Point2D.Double(center_x + half_w, center_y - half_h)),
            "SE": editor.addAnchor(Point2D.Double(center_x + half_w, center_y + half_h)),
            "SW": editor.addAnchor(Point2D.Double(center_x - half_w, center_y + half_h)),
        }

        # side: (corner_a, corner_b, crossover center point, rotation degrees).
        # 0 deg = crossover's A-B axis lies east-west (LayoutXOver's own
        # javadoc); 90 deg rotates it to north-south -- matching the N/S
        # sides' horizontal orientation and the E/W sides' vertical one.
        sides = [
            ("N", corners["NW"], corners["NE"], Point2D.Double(center_x, center_y - half_h), 0.0),
            ("E", corners["NE"], corners["SE"], Point2D.Double(center_x + half_w, center_y), 90.0),
            ("S", corners["SE"], corners["SW"], Point2D.Double(center_x, center_y + half_h), 0.0),
            ("W", corners["SW"], corners["NW"], Point2D.Double(center_x - half_w, center_y), 90.0),
        ]

        seg_counter = [0]

        def add_segment(id_prefix, c1, t1, c2, t2):
            seg_counter[0] += 1
            seg = TrackSegment("%s%d" % (id_prefix, seg_counter[0]), c1, t1, c2, t2, True, editor)
            seg_view = TrackSegmentView(seg, editor)
            editor.addLayoutTrack(seg, seg_view)
            return seg

        xovers = {}
        for side_name, corner_a, corner_b, center_point, rotation in sides:
            turnout_name = "ITTestOval%s%s" % (suffix, side_name)
            turnout = turnout_mgr.provideTurnout(turnout_name)
            second_turnout_name = "ITTestOval%s%s2" % (suffix, side_name)
            second_turnout = turnout_mgr.provideTurnout(second_turnout_name)

            xover_id = "X%s%s" % (suffix, side_name)
            xover = LayoutRHXOver(xover_id, editor)
            xover_view = LayoutRHXOverView(xover, center_point, rotation, 1.0, 1.0, editor)
            editor.addLayoutTrack(xover, xover_view)
            xover.setTurnout(turnout.getSystemName())
            xover.setSecondTurnout(second_turnout.getSystemName())

            seg_a = add_segment("T%s" % side_name, corner_a, HitPointType.POS_POINT, xover, HitPointType.TURNOUT_A)
            corner_a.setTrackConnection(seg_a)
            xover.setConnectA(seg_a, HitPointType.TRACK)

            seg_b = add_segment("T%s" % side_name, corner_b, HitPointType.POS_POINT, xover, HitPointType.TURNOUT_B)
            corner_b.setTrackConnection(seg_b)
            xover.setConnectB(seg_b, HitPointType.TRACK)

            xovers[side_name] = {
                "id": xover.getId(),
                "turnout": turnout.getSystemName(),
                "secondTurnout": second_turnout.getSystemName(),
            }

        editor.setDirty()

        return {
            "editorName": editor.getName(),
            "corners": dict((name, pt.getId()) for name, pt in corners.items()),
            "crossovers": xovers,
            "trackCount": len(list(editor.getLayoutTracks())),
        }

    return ThreadingUtil.runOnGUIwithReturn(build)


def _authoring_create_test_double_oval(payload):
    """Builds a synthetic double-oval test layout -- two concentric
    rectangular loops (outer, inner) joined by two real LayoutRHXOver
    crossovers, one on the north side and one on the south side --
    entirely in-memory on a freshly-created LayoutEditor panel, so
    jmri-mcp development/testing has a known, simple, fully-understood
    fixture for exercising route/transit/signal-mast placement without
    touching this profile's real layout panels. Nothing here is ever
    persisted (no store/save call anywhere in this function).

    This is testOval's actual double-track sibling -- testOval's four
    crossovers only wire the A-B "through" route, leaving C/D as
    unconnected stubs (a single loop has nothing for C/D to connect to).
    Here, both crossovers wire all four legs, so each crossover's own
    built-in diagonal (per LayoutXOver's javadoc: "A-B and C-D are the
    straight continuing routes, A-C and B-D are the diverging routes; B-C
    and A-D illegal") does real work -- it's what lets a train actually
    move between the outer and inner loop. LayoutRHXOver's one physical
    diagonal is A-C (confirmed against LayoutXOver.java's ASCII-art
    javadoc: the right-hand crossing runs from A's corner down to C's
    corner); no separate TrackSegment represents it -- it's inherent to
    the crossover object itself, exactly like the through route needs no
    extra track either.

    Geometry: LayoutTurnoutView's coordinate math (rotation 0.0, the
    default used here, matching LayoutXOver's own "0 degrees lies
    east-west" convention for both crossovers, since north/south sides
    run east-west) puts the crossover's A/B connection points at a
    *smaller* y than its D/C points. So whichever loop's edge sits at the
    smaller y for a given crossover is the one that has to map to A/B,
    and the other maps to D/C:
      - North crossover: the outer loop's north edge has the smaller y
        (it's further from the shared center than the inner loop's north
        edge) -- outer maps to A/B, inner maps to D/C.
      - South crossover: this flips -- the inner loop's south edge has
        the smaller y there (closer to center than the outer loop's
        south edge) -- inner maps to A/B, outer maps to D/C.
    Both crossovers still use rotation=0.0; only which loop's corners
    feed which connection points changes. West/east (short) sides carry
    no crossover at all -- just a plain point-to-point TrackSegment per
    loop, per the "two long sides only" scoping decision (real
    double-track practice keeps crossovers on tangent track, and it's
    what keeps this fixture simple rather than symmetric-for-its-own-
    sake). Each corner anchor ends up with exactly two track connections
    (one long-side leg, one short-side leg) -- the same two-slot
    connect1/connect2 pattern testOval's corners already use.

    Each crossover gets TWO real Turnout beans on JMRI's Internal
    connection (system name prefix "IT", via TurnoutManager.
    provideTurnout) -- same as testOval, a synthetic test fixture must
    never be able to command real hardware. Two beans per crossover, not
    one, because that's what an RH/LH single crossover actually is
    prototypically: two switch points (one on each of the two parallel
    tracks it joins), which is exactly what LayoutTurnout's optional
    secondTurnoutName field (setSecondTurnout()) exists to represent --
    setTurnout() binds the A/B-row switch point, setSecondTurnout() the
    D/C-row one. A caller building this for real would need two physical
    turnouts and two servos/Tortoises per crossover, not one.

    params (all optional): editorName (default "Test Double Oval"),
    centerX/centerY (default 300/300), outerWidth/outerHeight (default
    500/400, pixels), gap (default 100, pixels -- the outer-to-inner
    spacing on every side). innerWidth/innerHeight are derived as
    outerWidth/outerHeight minus 2*gap and must come out positive --
    e.g. the defaults above give a 300x200 inner loop.

    Calls setScroll("both") and a sane setSize() on the freshly-built
    editor -- see testOval's docstring above for the full story: a
    freshly-constructed LayoutEditor defaults to Editor.SCROLL_NONE, which
    forces the canvas to always match the window's current size; built
    headlessly, that window defaults to whatever AWT/Swing size the
    toolkit picks (confirmed live 2026-09-23: nearly full-screen), which
    then gets saved as "correct" and reproduces a canvas that scrolls the
    actual track content out of view on every future load. This isn't
    hypothetical -- it's exactly what happened building this fixture."""
    from java.awt import Dimension
    from java.awt.geom import Point2D
    from jmri import InstanceManager
    from jmri.jmrit.display.layoutEditor import (
        LayoutEditor, LayoutRHXOver, LayoutRHXOverView,
        TrackSegment, TrackSegmentView, HitPointType,
    )
    from jmri.util import ThreadingUtil
    import uuid as _uuid

    params = payload.get("params") or {}
    editor_name = params.get("editorName") or "Test Double Oval"
    center_x = float(params.get("centerX", 300.0))
    center_y = float(params.get("centerY", 300.0))
    outer_width = float(params.get("outerWidth", 500.0))
    outer_height = float(params.get("outerHeight", 400.0))
    gap = float(params.get("gap", 100.0))
    if outer_width <= 0 or outer_height <= 0:
        raise ValueError("testDoubleOval create requires outerWidth > 0 and outerHeight > 0")
    if gap <= 0:
        raise ValueError("testDoubleOval create requires gap > 0")
    inner_width = outer_width - 2.0 * gap
    inner_height = outer_height - 2.0 * gap
    if inner_width <= 0 or inner_height <= 0:
        raise ValueError(
            "testDoubleOval create requires gap small enough that the inner "
            "loop stays positive-sized (outerWidth - 2*gap and outerHeight - "
            "2*gap must both be > 0)"
        )

    outer_half_w, outer_half_h = outer_width / 2.0, outer_height / 2.0
    inner_half_w, inner_half_h = inner_width / 2.0, inner_height / 2.0
    suffix = _uuid.uuid4().hex[:6]

    def build():
        editor = LayoutEditor(editor_name)
        editor.setVisible(True)
        editor.setScroll("both")
        editor.setSize(Dimension(750, 700))

        turnout_mgr = InstanceManager.turnoutManagerInstance()

        def anchor(x, y):
            return editor.addAnchor(Point2D.Double(x, y))

        outer = {
            "NW": anchor(center_x - outer_half_w, center_y - outer_half_h),
            "NE": anchor(center_x + outer_half_w, center_y - outer_half_h),
            "SE": anchor(center_x + outer_half_w, center_y + outer_half_h),
            "SW": anchor(center_x - outer_half_w, center_y + outer_half_h),
        }
        inner = {
            "NW": anchor(center_x - inner_half_w, center_y - inner_half_h),
            "NE": anchor(center_x + inner_half_w, center_y - inner_half_h),
            "SE": anchor(center_x + inner_half_w, center_y + inner_half_h),
            "SW": anchor(center_x - inner_half_w, center_y + inner_half_h),
        }

        seg_counter = [0]

        def add_segment(id_prefix, c1, t1, c2, t2):
            seg_counter[0] += 1
            seg = TrackSegment("%s%d" % (id_prefix, seg_counter[0]), c1, t1, c2, t2, True, editor)
            seg_view = TrackSegmentView(seg, editor)
            editor.addLayoutTrack(seg, seg_view)
            return seg

        def make_crossover(name_suffix, center_point, ab_pair, dc_pair):
            # ab_pair/dc_pair: (west_anchor, east_anchor) for whichever
            # loop maps to this crossover's A/B row vs D/C row -- see the
            # docstring above for which loop that is on which side.
            turnout_name = "ITTestDblOval%s%s" % (suffix, name_suffix)
            turnout = turnout_mgr.provideTurnout(turnout_name)
            second_turnout_name = "ITTestDblOval%s%s2" % (suffix, name_suffix)
            second_turnout = turnout_mgr.provideTurnout(second_turnout_name)

            xover_id = "X%s%s" % (suffix, name_suffix)
            xover = LayoutRHXOver(xover_id, editor)
            xover_view = LayoutRHXOverView(xover, center_point, 0.0, 1.0, 1.0, editor)
            editor.addLayoutTrack(xover, xover_view)
            xover.setTurnout(turnout.getSystemName())
            xover.setSecondTurnout(second_turnout.getSystemName())

            ab_w, ab_e = ab_pair
            dc_w, dc_e = dc_pair

            seg_a = add_segment("T%sA" % name_suffix, ab_w, HitPointType.POS_POINT, xover, HitPointType.TURNOUT_A)
            ab_w.setTrackConnection(seg_a)
            xover.setConnectA(seg_a, HitPointType.TRACK)

            seg_b = add_segment("T%sB" % name_suffix, xover, HitPointType.TURNOUT_B, ab_e, HitPointType.POS_POINT)
            ab_e.setTrackConnection(seg_b)
            xover.setConnectB(seg_b, HitPointType.TRACK)

            seg_d = add_segment("T%sD" % name_suffix, dc_w, HitPointType.POS_POINT, xover, HitPointType.TURNOUT_D)
            dc_w.setTrackConnection(seg_d)
            xover.setConnectD(seg_d, HitPointType.TRACK)

            seg_c = add_segment("T%sC" % name_suffix, xover, HitPointType.TURNOUT_C, dc_e, HitPointType.POS_POINT)
            dc_e.setTrackConnection(seg_c)
            xover.setConnectC(seg_c, HitPointType.TRACK)

            return {
                "id": xover.getId(),
                "turnout": turnout.getSystemName(),
                "secondTurnout": second_turnout.getSystemName(),
            }

        # North side: outer's edge has the smaller y here -> outer is A/B.
        north_center = Point2D.Double(
            center_x, ((center_y - outer_half_h) + (center_y - inner_half_h)) / 2.0
        )
        north_xover = make_crossover(
            "N", north_center, (outer["NW"], outer["NE"]), (inner["NW"], inner["NE"])
        )

        # South side: flips -- inner's edge has the smaller y here.
        south_center = Point2D.Double(
            center_x, ((center_y + inner_half_h) + (center_y + outer_half_h)) / 2.0
        )
        south_xover = make_crossover(
            "S", south_center, (inner["SW"], inner["SE"]), (outer["SW"], outer["SE"])
        )

        def add_plain_side(id_prefix, corner_1, corner_2):
            seg = add_segment(id_prefix, corner_1, HitPointType.POS_POINT, corner_2, HitPointType.POS_POINT)
            corner_1.setTrackConnection(seg)
            corner_2.setTrackConnection(seg)
            return seg

        add_plain_side("OuterW", outer["NW"], outer["SW"])
        add_plain_side("OuterE", outer["NE"], outer["SE"])
        add_plain_side("InnerW", inner["NW"], inner["SW"])
        add_plain_side("InnerE", inner["NE"], inner["SE"])

        editor.setDirty()

        return {
            "editorName": editor.getName(),
            "outerCorners": dict((k, v.getId()) for k, v in outer.items()),
            "innerCorners": dict((k, v.getId()) for k, v in inner.items()),
            "crossovers": {"N": north_xover, "S": south_xover},
            "trackCount": len(list(editor.getLayoutTracks())),
        }

    return ThreadingUtil.runOnGUIwithReturn(build)


def _authoring_connection_discover(payload):
    """Runs JMRI's "SML Discover" (automaticallyDiscoverSignallingPairs()).
    Requires Advanced Layout Block Routing already enabled and its routing
    tables already stabilised -- checked explicitly here rather than
    silently enabling it, since that's an invasive, layout-wide toggle with
    its own background computation this operation shouldn't trigger as a
    side effect. See this module's jmri_authoring section comment for what
    live-testing this confirmed and corrected from an earlier assessment."""
    from jmri import InstanceManager, SignalMastLogicManager
    from jmri.jmrit.display.layoutEditor import LayoutBlockManager

    lbm = InstanceManager.getDefault(LayoutBlockManager)
    if not lbm.isAdvancedRoutingEnabled():
        raise ValueError(
            "Advanced Layout Block Routing is not enabled -- required for signal mast logic "
            "discovery. Enable it first, e.g. via jmri_run_jython: InstanceManager.getDefault"
            "(jmri.jmrit.display.layoutEditor.LayoutBlockManager).enableAdvancedRouting(True), "
            "then wait for routingStablised() to become True before calling discover."
        )
    if not lbm.routingStablised():
        raise ValueError(
            "layout block routing has not stabilised yet after enabling Advanced Routing -- "
            "wait a few seconds (confirmed ~3s on this test rig's layout) and retry."
        )

    mgr = InstanceManager.getDefault(SignalMastLogicManager)
    mgr.automaticallyDiscoverSignallingPairs()
    smls = mgr.getSignalMastLogicList()
    return {
        "signalMastLogicCount": len(smls),
        "pairs": [
            {
                "source": sml.getSourceMast().getSystemName() if sml.getSourceMast() else None,
                "destinations": [d.getSystemName() for d in sml.getDestinationList()],
            }
            for sml in smls
        ],
    }


def _authoring_connection_generate_sections(payload):
    """Runs JMRI's "Generate Sections" -- SignalMastLogicManager.
    generateSection() (Sections from discovered SML pairs) AND
    SectionManager.generateBlockSections() (Sections for stub/siding
    blocks) together, matching how JMRI's own GUI action invokes them as
    one combined step, not separately. Unlike discover, this does NOT
    require Advanced Routing enabled -- confirmed live by running it both
    with and without, getting identical, correct real Section data both
    times (an initial assumption that it shared discover's precondition
    turned out to be wrong once actually tested)."""
    from jmri import InstanceManager, SignalMastLogicManager, SectionManager

    sm = InstanceManager.getDefault(SectionManager)
    before = set(s.getSystemName() for s in sm.getNamedBeanSet())

    InstanceManager.getDefault(SignalMastLogicManager).generateSection()
    sm.generateBlockSections()

    after = sm.getNamedBeanSet()
    created = [s for s in after if s.getSystemName() not in before]
    return {
        "created": [
            {
                "name": s.getSystemName(),
                "userName": s.getUserName(),
                "blocks": [b.getSystemName() for b in s.getBlockList()],
            }
            for s in created
        ],
        "totalSections": len(after),
    }

