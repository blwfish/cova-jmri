"""
JMRI Throttle Bridge - Jython script for JMRI

Runs inside JMRI as an AbstractAutomaton. Listens for MQTT commands
from the calibration system and translates them into DCC throttle
commands, roster queries, speed profile imports, and CV read/write
operations via the SPROG (or whatever command station is configured).

Prerequisites:
  - JMRI running with SPROG connection (or other DCC command station)
  - MQTT connection added in Edit > Preferences > Connections
    (same Mosquitto broker the ESP32 uses)
  - SPROG set as default for Throttle in Preferences > Defaults

To run:
  In JMRI: Scripting > Run Script > select this file

MQTT Command Topics (relative to JMRI's MQTT channel prefix):
  Throttle:
    /cova/speed-cal/throttle/acquire   payload: "ADDRESS [L|S]"
    /cova/speed-cal/throttle/speed     payload: "0.0" to "1.0"
    /cova/speed-cal/throttle/direction payload: "FORWARD" or "REVERSE"
    /cova/speed-cal/throttle/stop      payload: (any)
    /cova/speed-cal/throttle/estop     payload: (any)
    /cova/speed-cal/throttle/function  payload: "NUM ON|OFF"
    /cova/speed-cal/throttle/release   payload: (any)

  Roster:
    /cova/speed-cal/roster/query          payload: JSON {"roster_id" or "address"}
    /cova/speed-cal/roster/import_profile payload: JSON {speed entries}

  CV Programming:
    /cova/speed-cal/cv/read     payload: JSON {"cv": N} or {"cvs": [...]}
    /cova/speed-cal/cv/write    payload: JSON {"cv": N, "value": V} or {"writes": [...]}

MQTT Response Topics:
    /cova/speed-cal/throttle/status        status/ack messages
    /cova/speed-cal/roster/info            roster query results
    /cova/speed-cal/roster/import_status   import results
    /cova/speed-cal/cv/result              CV read/write results

Note: JMRI's MQTT adapter may prepend a channel prefix to these topics.
If your JMRI MQTT channel prefix is blank (default since 5.1.2), the
topics above are used as-is. If you have a prefix like "trains/", the
full topic would be "trains//cova/speed-cal/throttle/acquire" etc.
Set your JMRI MQTT channel prefix to blank to avoid double-prefixing.
"""

import jmri
import java
import json

# --- Configuration ---
TOPIC_PREFIX = "/cova/speed-cal/"

# Throttle topics
THROTTLE_PREFIX = TOPIC_PREFIX + "throttle/"
TOPIC_ACQUIRE   = THROTTLE_PREFIX + "acquire"
TOPIC_SPEED     = THROTTLE_PREFIX + "speed"
TOPIC_DIRECTION = THROTTLE_PREFIX + "direction"
TOPIC_STOP      = THROTTLE_PREFIX + "stop"
TOPIC_ESTOP     = THROTTLE_PREFIX + "estop"
TOPIC_FUNCTION  = THROTTLE_PREFIX + "function"
TOPIC_RELEASE   = THROTTLE_PREFIX + "release"
TOPIC_STATUS    = THROTTLE_PREFIX + "status"

# Roster topics
ROSTER_PREFIX       = TOPIC_PREFIX + "roster/"
TOPIC_ROSTER_QUERY  = ROSTER_PREFIX + "query"
TOPIC_ROSTER_IMPORT = ROSTER_PREFIX + "import_profile"
TOPIC_ROSTER_INFO   = ROSTER_PREFIX + "info"
TOPIC_ROSTER_IMPORT_STATUS = ROSTER_PREFIX + "import_status"

# CV topics
CV_PREFIX       = TOPIC_PREFIX + "cv/"
TOPIC_CV_READ   = CV_PREFIX + "read"
TOPIC_CV_WRITE  = CV_PREFIX + "write"
TOPIC_CV_RESULT = CV_PREFIX + "result"

# Speed conversion: 1 scale mph = 447.04 mm/sec (at 1:1 scale)
MMS_PER_MPH = 447.04


class CvResultListener(jmri.ProgListener):
    """ProgListener callback that stores the result for polling."""

    def __init__(self):
        self.value = -1
        self.status = -1
        self.done = False

    def programmingOpReply(self, value, status):
        self.value = value
        self.status = status
        self.done = True


class MqttHandler(jmri.jmrix.mqtt.MqttEventListener):
    """Receives MQTT messages and queues them for the automaton."""

    def __init__(self):
        self.pending = []  # list of (topic, message) tuples

    def notifyMqttMessage(self, topic, message):
        self.pending.append((str(topic), str(message).strip()))

    def poll(self):
        """Return and clear pending messages."""
        msgs = self.pending
        self.pending = []
        return msgs


class ThrottleBridge(jmri.jmrit.automat.AbstractAutomaton):
    """
    JMRI automaton that bridges MQTT commands to DCC throttle,
    roster queries, speed profile imports, and CV programming.
    """

    def init(self):
        self.throttle = None
        self.currentAddress = None

        # Get the MQTT adapter
        try:
            memo = jmri.InstanceManager.getDefault(
                jmri.jmrix.mqtt.MqttSystemConnectionMemo
            )
            self.mqtt = memo.getMqttAdapter()
        except Exception as e:
            print("ThrottleBridge: ERROR - No MQTT connection configured in JMRI!")
            print("  Add MQTT connection in Edit > Preferences > Connections")
            print("  Error: " + str(e))
            return

        # Create message handler and subscribe to all command topics
        self.handler = MqttHandler()
        all_topics = [
            # Throttle
            TOPIC_ACQUIRE, TOPIC_SPEED, TOPIC_DIRECTION,
            TOPIC_STOP, TOPIC_ESTOP, TOPIC_FUNCTION, TOPIC_RELEASE,
            # Roster
            TOPIC_ROSTER_QUERY, TOPIC_ROSTER_IMPORT,
            # CV
            TOPIC_CV_READ, TOPIC_CV_WRITE,
        ]
        for topic in all_topics:
            self.mqtt.subscribe(topic, self.handler)
            print("ThrottleBridge: subscribed to " + topic)

        self.publishStatus("READY")
        print("ThrottleBridge: ready, waiting for commands")

    def publishStatus(self, message):
        """Publish a throttle status message."""
        try:
            self.mqtt.publish(TOPIC_STATUS, message)
        except Exception as e:
            print("ThrottleBridge: publish error: " + str(e))

    def publishRoster(self, suffix, message):
        """Publish to a roster response topic."""
        try:
            self.mqtt.publish(ROSTER_PREFIX + suffix, message)
        except Exception as e:
            print("ThrottleBridge: roster publish error: " + str(e))

    def publishCv(self, message):
        """Publish a CV result message."""
        try:
            self.mqtt.publish(TOPIC_CV_RESULT, message)
        except Exception as e:
            print("ThrottleBridge: cv publish error: " + str(e))

    def handle(self):
        """Called repeatedly by the automaton framework."""
        messages = self.handler.poll()

        if not messages:
            self.waitMsec(50)
            return True

        for topic, payload in messages:
            try:
                self.processCommand(topic, payload)
            except Exception as e:
                error_msg = "ERROR " + str(e)
                print("ThrottleBridge: " + error_msg)
                self.publishStatus(error_msg)

        return True

    def processCommand(self, topic, payload):
        """Process a single MQTT command."""

        # Throttle commands
        if topic.endswith("/acquire"):
            self.doAcquire(payload)
        elif topic.endswith("/speed"):
            self.doSpeed(payload)
        elif topic.endswith("/direction"):
            self.doDirection(payload)
        elif topic.endswith("/throttle/stop"):
            self.doStop()
        elif topic.endswith("/estop"):
            self.doEstop()
        elif topic.endswith("/function"):
            self.doFunction(payload)
        elif topic.endswith("/release"):
            self.doRelease()

        # Roster commands
        elif topic.endswith("/roster/query"):
            self.doRosterQuery(payload)
        elif topic.endswith("/roster/import_profile"):
            self.doImportProfile(payload)

        # CV commands
        elif topic.endswith("/cv/read"):
            self.doCvRead(payload)
        elif topic.endswith("/cv/write"):
            self.doCvWrite(payload)

    # --- Throttle handlers ---

    def doAcquire(self, payload):
        """Acquire a throttle. Payload: 'ADDRESS [L|S]'"""
        parts = payload.split()
        if len(parts) < 1:
            self.publishStatus("ERROR missing address")
            return

        address = int(parts[0])
        # Default: long address if >= 128, short if < 128
        if len(parts) >= 2:
            isLong = parts[1].upper() == "L"
        else:
            isLong = address >= 128

        # Release any existing throttle
        if self.throttle is not None:
            self.throttle.setSpeedSetting(0)
            self.throttle = None

        print("ThrottleBridge: acquiring throttle for %d (%s)" %
              (address, "long" if isLong else "short"))
        self.publishStatus("ACQUIRING %d" % address)

        # getThrottle blocks until acquired or timeout (30s default)
        self.throttle = self.getThrottle(address, isLong)

        if self.throttle is not None:
            self.currentAddress = address
            self.publishStatus("ACQUIRED %d" % address)
            print("ThrottleBridge: acquired throttle for %d" % address)
        else:
            self.publishStatus("FAILED %d" % address)
            print("ThrottleBridge: FAILED to acquire throttle for %d" % address)

    def doSpeed(self, payload):
        """Set speed. Payload: '0.0' to '1.0'"""
        if self.throttle is None:
            self.publishStatus("ERROR no throttle")
            return

        speed = float(payload)
        speed = max(0.0, min(1.0, speed))
        self.throttle.setSpeedSetting(speed)
        self.publishStatus("SPEED %.3f" % speed)

    def doDirection(self, payload):
        """Set direction. Payload: 'FORWARD' or 'REVERSE'"""
        if self.throttle is None:
            self.publishStatus("ERROR no throttle")
            return

        forward = payload.upper().startswith("F")
        self.throttle.setIsForward(forward)
        self.publishStatus("FORWARD" if forward else "REVERSE")

    def doStop(self):
        """Stop (speed = 0)."""
        if self.throttle is None:
            self.publishStatus("ERROR no throttle")
            return

        self.throttle.setSpeedSetting(0)
        self.publishStatus("STOPPED")

    def doEstop(self):
        """Emergency stop."""
        if self.throttle is None:
            self.publishStatus("ERROR no throttle")
            return

        self.throttle.setSpeedSetting(-1)
        self.publishStatus("ESTOPPED")

    def doFunction(self, payload):
        """Set function. Payload: 'NUM ON|OFF'"""
        if self.throttle is None:
            self.publishStatus("ERROR no throttle")
            return

        parts = payload.split()
        if len(parts) < 2:
            self.publishStatus("ERROR bad function format")
            return

        fnum = int(parts[0])
        fstate = parts[1].upper() == "ON"
        self.throttle.setFunction(fnum, fstate)
        self.publishStatus("FUNCTION %d %s" % (fnum, "ON" if fstate else "OFF"))

    def doRelease(self):
        """Release the current throttle."""
        if self.throttle is not None:
            self.throttle.setSpeedSetting(0)
            addr = self.currentAddress
            self.throttle = None
            self.currentAddress = None
            self.publishStatus("RELEASED %s" % str(addr))
            print("ThrottleBridge: released throttle")
        else:
            self.publishStatus("RELEASED")

    # --- Roster handlers ---

    def doRosterQuery(self, payload):
        """Query JMRI roster. Payload: JSON with roster_id or address."""
        try:
            req = json.loads(payload)
        except Exception:
            self.publishRoster("info", json.dumps({"error": "invalid JSON"}))
            return

        request_id = req.get("request_id", "")
        roster = jmri.jmrit.roster.Roster.getDefault()
        entries = []

        if req.get("roster_id"):
            entry = roster.getEntryForId(req["roster_id"])
            if entry is None:
                self.publishRoster("info", json.dumps({
                    "request_id": request_id,
                    "found": False,
                    "error": "No roster entry for id '%s'" % req["roster_id"]
                }))
                return
            entries = [entry]
        elif req.get("address") is not None:
            addr_str = str(req["address"])
            all_entries = roster.matchingList(None, None, addr_str,
                                             None, None, None, None)
            if all_entries is None or all_entries.size() == 0:
                self.publishRoster("info", json.dumps({
                    "request_id": request_id,
                    "found": False,
                    "error": "No roster entry for address %s" % addr_str
                }))
                return
            entries = list(all_entries)
        else:
            self.publishRoster("info", json.dumps({
                "request_id": request_id,
                "found": False,
                "error": "Provide roster_id or address"
            }))
            return

        result_entries = []
        for entry in entries:
            sp = entry.getSpeedProfile()
            sp_size = 0
            if sp is not None:
                try:
                    sp_size = sp.getProfileSize()
                except Exception:
                    pass
            result_entries.append({
                "roster_id": str(entry.getId()),
                "address": str(entry.getDccAddress()),
                "is_long_address": entry.getDccLocoAddress().isLongAddress(),
                "decoder_model": str(entry.getDecoderModel() or ""),
                "decoder_family": str(entry.getDecoderFamily() or ""),
                "has_speed_profile": sp is not None and sp_size > 0,
                "speed_profile_size": sp_size,
            })

        self.publishRoster("info", json.dumps({
            "request_id": request_id,
            "found": True,
            "entries": result_entries,
        }))

    def doImportProfile(self, payload):
        """Import speed profile into a JMRI roster entry."""
        try:
            req = json.loads(payload)
        except Exception:
            self.publishRoster("import_status", json.dumps({
                "success": False, "error": "invalid JSON"
            }))
            return

        request_id = req.get("request_id", "")
        roster_id = req.get("roster_id", "")
        scale_factor = req.get("scale_factor", 87.1)
        clear_existing = req.get("clear_existing", True)
        import_entries = req.get("entries", [])

        roster = jmri.jmrit.roster.Roster.getDefault()
        entry = roster.getEntryForId(roster_id)

        if entry is None:
            self.publishRoster("import_status", json.dumps({
                "request_id": request_id,
                "success": False,
                "roster_id": roster_id,
                "error": "Roster entry '%s' not found" % roster_id,
            }))
            return

        sp = entry.getSpeedProfile()
        if sp is None:
            sp = jmri.jmrit.roster.RosterSpeedProfile(entry)
            entry.setSpeedProfile(sp)

        if clear_existing:
            try:
                sp.clearCurrentProfile()
            except Exception:
                pass  # method may not exist in older JMRI versions

        count = 0
        for e in import_entries:
            speed_step = e.get("speed_step", 0)
            speed_mph = e.get("speed_mph", 0)
            direction = e.get("direction", "forward")

            throttle = speed_step / 126.0
            speed_mms = speed_mph * MMS_PER_MPH / scale_factor

            if direction == "forward":
                sp.setForwardSpeed(throttle, speed_mms)
            else:
                sp.setReverseSpeed(throttle, speed_mms)
            count += 1

        # Save to disk
        entry.updateFile()
        roster.writeRoster()

        self.publishRoster("import_status", json.dumps({
            "request_id": request_id,
            "success": True,
            "roster_id": roster_id,
            "entries_imported": count,
            "message": "Speed profile imported and saved",
        }))
        print("ThrottleBridge: imported %d speed entries for %s" % (count, roster_id))

    # --- CV handlers ---

    def _decodeProgStatus(self, status):
        """Convert ProgListener status int to string."""
        if status == jmri.ProgListener.OK:
            return "OK"
        elif status == jmri.ProgListener.NoLocoDetected:
            return "NoLocoDetected"
        elif status == jmri.ProgListener.ProgrammerBusy:
            return "ProgrammerBusy"
        elif status == jmri.ProgListener.NoAck:
            return "NoAck"
        elif status == jmri.ProgListener.FailedTimeout:
            return "FailedTimeout"
        elif status == jmri.ProgListener.ProgrammingShort:
            return "ProgrammingShort"
        elif status == jmri.ProgListener.CommError:
            return "CommError"
        else:
            return "UnknownError"

    def _getProgrammer(self):
        """Get the global (service mode) programmer, or None."""
        try:
            pm = jmri.InstanceManager.getNullableDefault(
                jmri.GlobalProgrammerManager
            )
            if pm is not None:
                return pm.getGlobalProgrammer()
        except Exception:
            pass
        return None

    def _cvReadSingle(self, programmer, cv):
        """Read a single CV. Returns (value, status_str)."""
        listener = CvResultListener()
        try:
            programmer.readCV(str(cv), listener)
        except Exception as e:
            return (-1, "ERROR: " + str(e))

        # Poll for result (up to 30 seconds)
        timeout = 300
        while not listener.done and timeout > 0:
            self.waitMsec(100)
            timeout -= 1

        if not listener.done:
            return (-1, "FailedTimeout")

        return (listener.value, self._decodeProgStatus(listener.status))

    def _cvWriteSingle(self, programmer, cv, value):
        """Write a single CV. Returns status_str."""
        listener = CvResultListener()
        try:
            programmer.writeCV(str(cv), value, listener)
        except Exception as e:
            return "ERROR: " + str(e)

        timeout = 300
        while not listener.done and timeout > 0:
            self.waitMsec(100)
            timeout -= 1

        if not listener.done:
            return "FailedTimeout"

        return self._decodeProgStatus(listener.status)

    def doCvRead(self, payload):
        """Read CV(s). Payload: JSON with cv (single) or cvs (batch)."""
        try:
            req = json.loads(payload)
        except Exception:
            self.publishCv(json.dumps({"error": "invalid JSON"}))
            return

        request_id = req.get("request_id", "")
        programmer = self._getProgrammer()

        if programmer is None:
            self.publishCv(json.dumps({
                "request_id": request_id,
                "operation": "read",
                "status": "NoProgrammer",
                "error": "No service mode programmer available",
            }))
            return

        if "cvs" in req:
            # Batch read
            cvs = req["cvs"]
            results = []
            for i, cv in enumerate(cvs):
                value, status = self._cvReadSingle(programmer, cv)
                result = {"cv": cv, "value": value, "status": status}
                results.append(result)
                # Publish per-CV progress
                self.publishCv(json.dumps({
                    "request_id": request_id,
                    "operation": "read",
                    "cv": cv,
                    "value": value,
                    "status": status,
                    "batch_index": i + 1,
                    "batch_total": len(cvs),
                }))

            # Publish batch summary
            ok_count = sum(1 for r in results if r["status"] == "OK")
            self.publishCv(json.dumps({
                "request_id": request_id,
                "operation": "read_batch_complete",
                "results": results,
                "success_count": ok_count,
                "error_count": len(results) - ok_count,
            }))
        else:
            # Single read
            cv = req.get("cv", 0)
            value, status = self._cvReadSingle(programmer, cv)
            self.publishCv(json.dumps({
                "request_id": request_id,
                "operation": "read",
                "cv": cv,
                "value": value,
                "status": status,
            }))

    def doCvWrite(self, payload):
        """Write CV(s). Payload: JSON with cv+value (single) or writes (batch)."""
        try:
            req = json.loads(payload)
        except Exception:
            self.publishCv(json.dumps({"error": "invalid JSON"}))
            return

        request_id = req.get("request_id", "")
        programmer = self._getProgrammer()

        if programmer is None:
            self.publishCv(json.dumps({
                "request_id": request_id,
                "operation": "write",
                "status": "NoProgrammer",
                "error": "No service mode programmer available",
            }))
            return

        if "writes" in req:
            # Batch write
            writes = req["writes"]
            results = []
            for i, w in enumerate(writes):
                cv = w.get("cv", 0)
                value = w.get("value", 0)
                status = self._cvWriteSingle(programmer, cv, value)
                result = {"cv": cv, "value": value, "status": status}
                results.append(result)
                # Publish per-CV progress
                self.publishCv(json.dumps({
                    "request_id": request_id,
                    "operation": "write",
                    "cv": cv,
                    "value": value,
                    "status": status,
                    "batch_index": i + 1,
                    "batch_total": len(writes),
                }))

            ok_count = sum(1 for r in results if r["status"] == "OK")
            self.publishCv(json.dumps({
                "request_id": request_id,
                "operation": "write_batch_complete",
                "results": results,
                "success_count": ok_count,
                "error_count": len(results) - ok_count,
            }))
        else:
            # Single write
            cv = req.get("cv", 0)
            value = req.get("value", 0)
            status = self._cvWriteSingle(programmer, cv, value)
            self.publishCv(json.dumps({
                "request_id": request_id,
                "operation": "write",
                "cv": cv,
                "value": value,
                "status": status,
            }))


# --- Start the bridge ---
bridge = ThrottleBridge()
bridge.setName("SpeedCal Throttle Bridge")
bridge.start()
print("")
print("=== Speed Calibration Throttle Bridge started ===")
print("Listening for commands on " + TOPIC_PREFIX + "*")
print("Publishing status to " + TOPIC_STATUS)
print("")
