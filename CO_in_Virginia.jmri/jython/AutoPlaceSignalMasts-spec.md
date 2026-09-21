# AutoPlaceSignalMasts.py — Design Spec

Jython script for JMRI that automatically places Virtual Signal Masts at all
block boundaries in a Layout Editor panel. Eliminates ~150 manual clicks that
are otherwise required before Signal Mast Logic auto-generation can run.

Intended as a contribution to the JMRI `/jython/` community scripts library.

## Motivation

Setting up DispatcherPro with Signal Mast Logic requires masts at every block
boundary in the Layout Editor. On a layout with 30 blocks and 30 turnouts this
is 120–150 manual placements — purely mechanical work with no creative judgment.
No equivalent auto-placement script exists in JMRI's script library.

## Where it fits in the DispatcherPro setup sequence

```
1. Layout Editor panel complete (all blocks, sensors, turnouts)
2. **Run AutoPlaceSignalMasts.py**   ← this script
3. Signal Mast Logic Table > Tools > Auto Generate Signaling Pairs
4. Signal Mast Logic Table > Tools > Generate Sections
5. Section Table > Tools > Validate All Sections
6. Section Table > Tools > Set Direction Sensors in Logic
7. Build Transits
8. Configure and run DispatcherPro
```

## Algorithm

**Inputs:** Live Layout Editor panel (must be open in JMRI)

**For each LayoutTurnout:**
- Get blocks on A (throat), B (continuing), C (diverging) ends
- For each end whose block differs from any other end's block: create a mast
- Place via `t.setSignalAMast()`, `setSignalBMast()`, `setSignalCMast()`
- Handle D end for crossover types (DOUBLE_XOVER, RH_XOVER, LH_XOVER)

**For each PositionablePoint of type ANCHOR:**
- Get blocks of connected track segments (connect1, connect2)
- If blocks differ: create east-bound and west-bound masts
- Place via `pt.setEastBoundSignalMast()`, `pt.setWestBoundSignalMast()`

**For each PositionablePoint of type END_BUMPER:**
- Create a terminus Virtual Mast, set its aspect to Stop permanently
- Place on the bumper end

**Mast creation:** `masts.provideSignalMast(sysName)` + `setUserName()`  
**Idempotent:** skip any end that already has a mast assigned

## Configuration (top of script)

| Variable | Default | Description |
|---|---|---|
| `SIGNALING_SYSTEM` | `"basic"` | e.g. `"AAR-1946"`, `"BNSF-1996"` |
| `APPEARANCE_TABLE` | `"SL-1-searchlight"` | appearance table from chosen system |
| `PANEL_NAME` | `None` | `None` = first LE panel found; or match by title |
| `DRY_RUN` | `False` | Print what would be done, create nothing |

## Naming convention

- Turnout ends: `SM-<turnout-user-name>-A`, `...-B`, `...-C`, `...-D`
- Anchor point boundaries: `SM-<block1-name>-to-<block2-name>` (east), reverse for west
- Terminus masts: `SM-terminus-<point-ident>`

## Key JMRI API calls (Jython)

```python
# Find panel
for frame in JmriJFrame.getFrameList():
    if isinstance(frame, jmri.jmrit.display.layoutEditor.LayoutEditor): ...

# Enumerate track elements
le.getLayoutTurnouts()       # List<LayoutTurnout>
le.getPositionablePoints()   # List<PositionablePoint>

# Block boundary check (turnout)
t.getLayoutBlock()    # A end (throat)
t.getLayoutBlockB()   # B end (continuing)
t.getLayoutBlockC()   # C end (diverging)

# Block boundary check (anchor point)
pt.getConnect1().getLayoutBlock()
pt.getConnect2().getLayoutBlock()

# Point type enum
PositionablePoint.PointType.ANCHOR
PositionablePoint.PointType.END_BUMPER

# Create Virtual Signal Mast  (system name format: IF$vsm:<system>:<table>($<N>))
masts.provideSignalMast("IF$vsm:basic:SL-1-searchlight($1001)")

# Assign to track elements
t.setSignalAMast(sysName); t.getSignalAMastName()
t.setSignalBMast(sysName); t.getSignalBMastName()
t.setSignalCMast(sysName); t.getSignalCMastName()
pt.setEastBoundSignalMast(sysName); pt.getEastBoundSignalMast()  # returns object
pt.setWestBoundSignalMast(sysName); pt.getWestBoundSignalMast()

# Finalize
le.redrawPanel()
le.setDirty(True)
```

## Layout context (Gville-arsenal.xml, JMRI 5.8.0)

- 18 turnouts currently in panel (more to be added as layout expands)
- 177 positionable points (172 ANCHOR, 4 END_BUMPER, 1 EDGE_CONNECTOR)
- 20 layout blocks, LCC/OpenLCB occupancy detection
- No signal masts placed yet — script starts from clean state

## Notes

- `masts` is a pre-bound Jython variable (available since JMRI 4.17.5)
- Anchor point east/west labels are JMRI conventions, not compass directions
- Closure-in-loop bug: avoid lambdas capturing loop vars; use explicit helper functions
- After running: delete existing Sections and Transits (built without SML), then
  regenerate everything from SML
