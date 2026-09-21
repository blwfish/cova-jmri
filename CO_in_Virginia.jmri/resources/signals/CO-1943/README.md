# C&O-1943 JMRI signal system (draft)

A starting-point JMRI signaling-system definition for the Louisa-Gordonsville-
Charlottesville-Staunton-Afton stretch of the C&O Piedmont/Mountain Subs, circa 1943.

## Where to put it

Copy the `signals/` folder into JMRI's user preference area as:

    <JMRI preferences>/resources/signals/CO-1943/

(rename the folder itself to `CO-1943` - no ampersand/space, per JMRI's naming rules)
then restart JMRI. It should appear as a selectable signal system when you create a new
Signal Mast.

## What's confirmed vs. assumed

**Confirmed from period sources (Railway Signaling / Railway Age trade journals, and
piedmontsub.com):**
- Gordonsville-Charlottesville-Staunton-Clifton Forge was under ICC-order automatic
  train control with three-indication, AC-powered **color-light** (three separate lamps,
  not searchlight) block signals, installed in stages 1919-1926, CTC added "in the
  1940s" (exact year not pinned down).
- Richmond-Gordonsville (including Louisa) was separately "Automatic Block Territory"
  from the early 1900s, but the source used didn't specify the physical hardware there
  as of 1943 - could be the same color-light gear, could still be semaphore.

**Assumed / needs checking:**
- This file treats the whole Louisa-Afton stretch as color-light. If Richmond-Gordonsville
  turns out to still be semaphore in 1943, Louisa itself (and anything east of it) would
  need a semaphore appearance file instead, with the changeover point wherever the actual
  conversion happened.
- Aspect *names* follow the general AAR 1946 recommended set (Clear / Approach Medium /
  Medium Clear / Approach / Medium Approach / Restricting / Stop and Proceed / Stop).
  Exact wording, rule numbers, and which aspects C&O actually used at this date should be
  checked against a period C&O rulebook or timetable if you can get one through the C&OHS.
- The 2-head Restricting appearance (red/yellow) is a guess at the color-light convention;
  some roads used a lunar-white lamp for Restricting instead. Not confirmed for C&O at
  this date.
- "Stop" vs. "Stop and Proceed" are visually identical (red) and distinguished only by
  which aspect you assign to a given mast - matching real railroad practice, where the
  physical difference was a number plate on the mast, not a different light.

## Files

- `signals/aspects.xml` - the aspect table (names, indications, descriptions, speeds)
- `signals/appearance-color-light-1head.xml` - single-lamp-head mast, for plain
  intermediate ABS block signals (most of the main line)
- `signals/appearance-color-light-2head.xml` - two-lamp-head mast, for interlockings
  and any diverging-route locations (Afton, passing sidings)
- `signals/index.shtml` - JMRI-convention index page

## Suggested next steps

1. Load into JMRI, use Debug -> "Validate XML File" on all three XML files, fix whatever
   the validator flags (this was built from documentation, not tested against a live
   JMRI instance).
2. Decide the Louisa/Richmond-Gordonsville hardware question - that determines whether
   you need a semaphore appearance file for the eastern end of the layout.
3. Cross-check aspect names/rule numbers against an actual C&O rulebook if you can get
   one, and correct the Restricting appearance.
