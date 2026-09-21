# -*- coding: utf-8 -*-
"""
AutoPlaceSignalMasts.py

Automatically places Virtual Signal Masts at all block boundaries in a
LayoutEditor panel. Eliminates the ~150 manual clicks required before
Signal Mast Logic auto-generation can run.

Run from JMRI Script Entry window:
    execfile('/path/to/AutoPlaceSignalMasts.py')

After running:
    1. Signal Mast Logic Table > Tools > Auto Generate Signaling Pairs
    2. Signal Mast Logic Table > Tools > Generate Sections
    3. Section Table > Tools > Validate All Sections
    4. Section Table > Tools > Set Direction Sensors in Logic
    5. Build Transits (or build programmatically via orchestrator)

Idempotent: safe to re-run; any end that already has a mast is skipped.
"""

import jmri
from jmri.jmrit.display.layoutEditor import LayoutEditor
from jmri.util import JmriJFrame

print("AutoPlaceSignalMasts starting...")

# ── Configuration ─────────────────────────────────────────────────────────────
SIGNALING_SYSTEM = "basic"           # e.g. "AAR-1946", "BNSF-1996"
APPEARANCE_TABLE = "one-searchlight"
PANEL_NAME       = None              # None = first LayoutEditor found
DRY_RUN          = False             # True = print only, create nothing
# ─────────────────────────────────────────────────────────────────────────────

# ── Managers (not predefined globals in all JMRI versions) ────────────────────
masts = jmri.InstanceManager.getDefault(jmri.SignalMastManager)

# ── Helpers ───────────────────────────────────────────────────────────────────

_mast_counter = [1001]

def _next_sys_name():
    """Return the next unused Virtual Signal Mast system name."""
    template = "IF$vsm:%s:%s($%%d)" % (SIGNALING_SYSTEM, APPEARANCE_TABLE)
    while True:
        n = _mast_counter[0]
        _mast_counter[0] += 1
        candidate = template % n
        if masts.getBySystemName(candidate) is None:
            return candidate

def _get_or_create_mast(user_name):
    """Return existing mast with this user name, or create and register one."""
    existing = masts.getByUserName(user_name)
    if existing is not None:
        return existing
    sys_name = _next_sys_name()
    m = masts.provideSignalMast(sys_name)
    m.setUserName(user_name)
    return m

def _tname(t):
    """Best available name for a LayoutTurnout: hardware name or internal id."""
    return t.getTurnoutName() or t.getId()

def _bname(lb):
    """User name (or system name) of the Block within a LayoutBlock."""
    if lb is None:
        return None
    b = lb.getBlock()
    if b is None:
        return None
    return b.getUserName() or b.getSystemName()

def _lb_from_connect(conn):
    """Get LayoutBlock from a connected track segment (None if not a segment)."""
    if conn is None:
        return None
    try:
        return conn.getLayoutBlock()
    except:
        return None

def _lb(turnout_lb, conn):
    """Return turnout's own LayoutBlock, falling back to connected segment's block."""
    if turnout_lb is not None:
        return turnout_lb
    return _lb_from_connect(conn)

def _place(mast_uname, setter_fn, label):
    """Create mast and call setter, or just print in DRY_RUN mode."""
    global placed
    if DRY_RUN:
        print("  %s: %s" % (label, mast_uname))
    else:
        m = _get_or_create_mast(mast_uname)
        setter_fn(m.getSystemName())
        print("  %s: %s  [%s]" % (label, mast_uname, m.getSystemName()))
    placed += 1

# ── Find panel ────────────────────────────────────────────────────────────────

le = None
for frame in JmriJFrame.getFrameList(LayoutEditor):
    if PANEL_NAME is None or frame.getTitle() == PANEL_NAME:
        le = frame
        break

if le is None:
    print("ERROR: No LayoutEditor panel found.")
else:
    placed = 0
    skipped = 0

    # ── Turnouts ──────────────────────────────────────────────────────────────
    print("=== Turnouts ===")
    for t in le.getLayoutTurnouts():
        name = _tname(t)
        # Prefer block set on the turnout object itself; fall back to the
        # connected track segment's block (the common case when blocks are
        # assigned to segments rather than to turnout ends directly).
        lbA = _lb(t.getLayoutBlock(),  t.getConnectA())
        lbB = _lb(t.getLayoutBlockB(), t.getConnectB())
        lbC = _lb(t.getLayoutBlockC(), t.getConnectC())
        print("  %s: A=%s B=%s C=%s" % (name, _bname(lbA), _bname(lbB), _bname(lbC)))

        # A end (throat) — boundary exists if A differs from B or C
        if t.getSignalAMastName():
            skipped += 1
        elif lbA is not None and (lbA != lbB or lbA != lbC):
            _place("SM-%s-A" % name, t.setSignalAMast, "A")

        # B end (continuing) — boundary exists if B differs from A
        if t.getSignalBMastName():
            skipped += 1
        elif lbB is not None and lbB != lbA:
            _place("SM-%s-B" % name, t.setSignalBMast, "B")

        # C end (diverging) — boundary exists if C differs from A
        if t.getSignalCMastName():
            skipped += 1
        elif lbC is not None and lbC != lbA:
            _place("SM-%s-C" % name, t.setSignalCMast, "C")

        # D end — crossovers only; getLayoutBlockD() returns lbA for non-xovers
        if "XOVER" in str(t.getTurnoutType()):
            lbD = _lb(t.getLayoutBlockD(), t.getConnectD())
            if t.getSignalDMastName():
                skipped += 1
            elif lbD is not None and lbD != lbA:
                _place("SM-%s-D" % name, t.setSignalDMast, "D")

    # ── Positionable Points ───────────────────────────────────────────────────
    print("\n=== Anchor Points ===")
    for pt in le.getPositionablePoints():
        ptype = pt.getType().name()

        if ptype == "ANCHOR":
            seg1 = pt.getConnect1()
            seg2 = pt.getConnect2()
            if seg1 is None or seg2 is None:
                continue
            lb1 = seg1.getLayoutBlock()
            lb2 = seg2.getLayoutBlock()
            print("  anchor %s: %s / %s" % (pt.getId(), _bname(lb1), _bname(lb2)))
            if lb1 is None or lb2 is None or lb1 == lb2:
                continue
            bn1 = _bname(lb1)
            bn2 = _bname(lb2)
            if bn1 is None or bn2 is None:
                continue

            # East-bound (bn1 → bn2)
            if pt.getEastBoundSignalMastName():
                skipped += 1
            else:
                _place("SM-%s-to-%s" % (bn1, bn2),
                       pt.setEastBoundSignalMast, "E")

            # West-bound (bn2 → bn1)
            if pt.getWestBoundSignalMastName():
                skipped += 1
            else:
                _place("SM-%s-to-%s" % (bn2, bn1),
                       pt.setWestBoundSignalMast, "W")

        elif ptype == "END_BUMPER":
            if pt.getEastBoundSignalMastName() or pt.getWestBoundSignalMastName():
                skipped += 1
            else:
                uname = "SM-terminus-%s" % pt.getId()
                if DRY_RUN:
                    print("  Terminus: %s" % uname)
                else:
                    m = _get_or_create_mast(uname)
                    try:
                        m.setAspect("Stop")
                    except:
                        pass  # aspect name may vary by signaling system
                    pt.setEastBoundSignalMast(m.getSystemName())
                    print("  Terminus: %s  [%s]" % (uname, m.getSystemName()))
                placed += 1

    # ── Finalize ──────────────────────────────────────────────────────────────
    if not DRY_RUN:
        le.redrawPanel()
        le.setDirty(True)

    print("\n=== Done ===")
    print("Placed:  %d" % placed)
    print("Skipped: %d (already had mast)" % skipped)
    if DRY_RUN:
        print("(DRY RUN — nothing created)")
