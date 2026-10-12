#!/usr/bin/env python3
"""The screen: sends what the display shows to each person watching, over WebRTC, and takes their mouse and keys.

It listens on loopback and trusts whoever reaches it; the gate decides who that is.
  POST /offer   {"as", "session"}       -> {"id", "sdp", "iceServers"}   a new connection, for the viewer to answer
  POST /answer  {"id", "as", "sdp"}
  POST /close   {"id", ["as"]}
  GET  /peers                           -> [{"id", "as", "session"}]

The display is captured once for everyone, and each connection has its own encoder, so each gets the rate its own
link carries. Mouse and keys arrive on the connection's data channel and are played into the display as if from a
real mouse and keyboard. Text arrives there too, made on the viewer's device by its own keyboard or input method, and
goes in through an input method of the screen's own, wherever a field has focus: a page, the address bar, a dialog.
The same channel tells every viewer when a field has focus, and where the page's fields are.
"""
import ctypes
import json
import os
import queue
import secrets
import threading
import time
import urllib.request
import weakref
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import gi
from websockets.sync.client import connect

gi.require_version("Gst", "1.0")
gi.require_version("GstSdp", "1.0")
gi.require_version("GstWebRTC", "1.0")
gi.require_version("IBus", "1.0")
from gi.repository import GLib, GObject, Gst, GstSdp, GstWebRTC, IBus  # noqa: E402
from Xlib import X, XK, display  # noqa: E402
from Xlib.ext import xtest  # noqa: E402

DISPLAY = os.environ.get("DISPLAY", ":99")
FPS = int(os.environ.get("SB_SCREEN", "1440x960@30").partition("@")[2] or 30)
FIRST, _, LAST = os.environ.get("SB_WEBRTC_PORT", "59000").partition("-")
PORTS = range(int(FIRST), int(LAST or FIRST) + 1)
PUBLIC_IP = os.environ.get("SB_PUBLIC_IP", "")
STUN = os.environ.get("SB_STUN", "")
ICE_SERVERS = json.loads(os.environ.get("SB_ICE_SERVERS") or "[]")
PORT = int(os.environ.get("SCREEN_PORT", "8081"))
KBPS = int(os.environ.get("SCREEN_KBPS", "6000"))   # the most a connection may use
CDP = os.environ.get("SCREEN_CDP", "http://127.0.0.1:9222")
FIELDS = Path(__file__).with_name("fields.js").read_text()
RTP = ("application/x-rtp,media=video,encoding-name=H264,payload=102,clock-rate=90000,packetization-mode=(string)1,"
       "rtcp-fb-nack-pli=true,rtcp-fb-nack=true,rtcp-fb-transport-cc=(boolean)true,"
       "extmap-1=(string)http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01")

Gst.init(None)
CLOCK = Gst.SystemClock.obtain()
BASE = CLOCK.get_time()
PEERS = {}
PEERS_LOCK = threading.Lock()

GOBJECT = ctypes.CDLL("libgobject-2.0.so.0")
GOBJECT.g_object_unref.argtypes = [ctypes.c_void_p]
POINTER = ctypes.pythonapi.PyCapsule_GetPointer
POINTER.restype, POINTER.argtypes = ctypes.c_void_p, [ctypes.py_object, ctypes.c_char_p]


def limit_ports(webrtc):
    """Keep a connection's ICE on the ports compose publishes.

    Done in C: webrtcbin holds its ICE agent by a floating reference, and wrapping the agent as a Python object
    would sink that reference into the wrapper, freeing the agent under webrtcbin when the wrapper goes.
    """
    agent = ctypes.c_void_p()
    GOBJECT.g_object_get(ctypes.c_void_p(POINTER(webrtc.__gpointer__, None)), b"ice-agent", ctypes.byref(agent), None)
    GOBJECT.g_object_set(agent, b"min-rtp-port", ctypes.c_uint(PORTS.start),
                         b"max-rtp-port", ctypes.c_uint(PORTS.stop - 1), None)
    GOBJECT.g_object_unref(agent)


def weakly(method):
    """A handler that does not keep its connection alive.

    The connection's own elements hold these handlers, and Python cannot follow a reference out of an element its
    pipeline also holds. A handler holding the connection would make a loop that is never freed, and a closed
    connection would keep its port.
    """
    ref = weakref.WeakMethod(method)
    return lambda *args: (bound := ref()) is not None and bound(*args)


class Rate:
    """Keeps the encoder just under what the link carries, so frames do not wait in a queue on the way.

    The viewer reports when each packet arrived. If packets arrive more slowly than they were sent, or get lost,
    the link is full: drop to a little under what got through, once, and let the queue drain. Otherwise, while the
    rate is in use, climb back, quickly while far below the rate the link last carried and slowly near it.
    """
    LOW = 300

    def __init__(self, apply, high):
        self.apply, self.high = apply, high
        self.target = self.applied = min(high, 1500)
        self.capacity = None
        self.recv = self.sent = 0.0
        self.calm_after = 0.0
        apply(self.target)

    def report(self, sent_kbps, recv_kbps, loss, now=None):
        now = time.monotonic() if now is None else now
        self.recv = 0.7 * self.recv + 0.3 * recv_kbps
        self.sent = 0.7 * self.sent + 0.3 * sent_kbps
        full = loss > 10 or (self.sent > 0.5 * self.target and self.recv < 0.9 * self.sent)
        if full and now >= self.calm_after:
            self.capacity = self.recv
            self.target = max(self.LOW, 0.5 * self.target, min(self.target, 0.9 * self.recv))
            self.calm_after = now + 1.0
        elif not full and loss < 2 and now >= self.calm_after and self.sent > 0.8 * self.target:
            # Only a rate in use shows the link can carry it; a still screen sends little and proves nothing.
            near = self.capacity and self.target > 0.8 * self.capacity
            self.target = min(self.high, self.target * (1.002 if near else 1.015) + 2)
            if self.capacity and self.target > 1.1 * self.capacity:
                self.capacity = None
        if abs(self.target - self.applied) >= 0.03 * self.applied:
            self.applied = self.target
            self.apply(self.target)


class Input:
    """Mouse and keys from viewers, played into the display. Viewers share one display, so one at a time."""
    NAMED = {"Enter": "Return", "Tab": "Tab", "Backspace": "BackSpace", "Escape": "Escape", "Delete": "Delete",
             "Insert": "Insert", "Home": "Home", "End": "End", "PageUp": "Prior", "PageDown": "Next",
             "ArrowUp": "Up", "ArrowDown": "Down", "ArrowLeft": "Left", "ArrowRight": "Right", "Shift": "Shift_L",
             "Control": "Control_L", "Alt": "Alt_L", "Meta": "Super_L", "CapsLock": "Caps_Lock",
             "ContextMenu": "Menu", " ": "space", **{f"F{i}": f"F{i}" for i in range(1, 13)}}
    STEP = 120   # pixels Chrome scrolls for one wheel click
    SETTLE = 0.03   # seconds for text or keys to land; 10 ms was enough in testing

    def __init__(self):
        while True:
            try:
                self.d = display.Display(DISPLAY)
                break
            except Exception:
                time.sleep(0.2)
        screen = self.d.screen()
        self.size = (screen.width_in_pixels, screen.height_in_pixels)
        low, high = self.d.display.info.min_keycode, self.d.display.info.max_keycode
        mapping = self.d.get_keyboard_mapping(low, high - low + 1)
        # A keycode with nothing on it, to lend to characters the keyboard map does not have.
        self.spare = next(low + i for i in range(len(mapping) - 1, -1, -1) if not any(mapping[i]))
        self.lock = threading.Lock()
        self.pressed = {}      # the viewer's key code -> X keycode held down for it
        self.buttons = set()
        self.wheel = [0.0, 0.0]
        self.shift = False
        self.way, self.sent = "keys", 0.0   # how the last input went in, and when

    def handle(self, message):
        try:
            m = json.loads(message)
        except ValueError:
            return
        with self.lock:
            kind = m.get("t")
            if kind in ("text", "compose"):
                self.turn("text")
            elif kind in ("button", "wheel", "key", "press"):
                self.turn("keys")
            if kind == "move":
                self.move(m)
            elif kind == "button":
                self.move(m)
                self.button(int(m.get("b", 1)), bool(m.get("down")))
            elif kind == "wheel":
                self.scroll(float(m.get("dx", 0)), float(m.get("dy", 0)))
            elif kind == "key":
                self.key(bool(m.get("down")), str(m.get("key", "")), str(m.get("code", "")))
            elif kind == "release":
                self.release()
            elif kind == "text":   # into the field with focus; key by key into a password, which takes no input method
                text = str(m.get("text", ""))
                if BROWSER.secret() or not TYPING.commit(text):
                    for char in text:
                        self.tap({"\n": "Enter", "\t": "Tab"}.get(char, char))
            elif kind == "compose":
                if not BROWSER.secret():
                    TYPING.compose(str(m.get("text", "")))
            elif kind == "press":   # a key that edits the text around it: Backspace, Enter, the arrows
                for _ in range(min(max(int(m.get("count", 1)), 0), 1000)):
                    self.tap(str(m.get("key", "")), bool(m.get("shift")))
            self.d.sync()
            self.sent = time.monotonic()

    def turn(self, way):
        """Text goes in through the input method and keys through X, and Chrome takes the two in its own order: when
        the way changes, let what went the other way land first."""
        if way != self.way:
            time.sleep(max(0.0, self.sent + self.SETTLE - time.monotonic()))
            self.way = way

    def move(self, m):
        if "x" in m and "y" in m:
            x = min(max(int(m["x"]), 0), self.size[0] - 1)
            y = min(max(int(m["y"]), 0), self.size[1] - 1)
            xtest.fake_input(self.d, X.MotionNotify, x=x, y=y)

    def button(self, number, down):
        if not 1 <= number <= 9 or down == (number in self.buttons):
            return
        xtest.fake_input(self.d, X.ButtonPress if down else X.ButtonRelease, number)
        (self.buttons.add if down else self.buttons.discard)(number)

    def scroll(self, dx, dy):
        for axis, delta, (back, forth) in ((0, dx, (6, 7)), (1, dy, (4, 5))):
            self.wheel[axis] += delta
            while abs(self.wheel[axis]) >= self.STEP:
                number = forth if self.wheel[axis] > 0 else back
                xtest.fake_input(self.d, X.ButtonPress, number)
                xtest.fake_input(self.d, X.ButtonRelease, number)
                self.wheel[axis] -= self.STEP if self.wheel[axis] > 0 else -self.STEP

    def key(self, down, key, code):
        if not down:
            keycode = self.pressed.pop(code, None)
            if keycode:
                xtest.fake_input(self.d, X.KeyRelease, keycode)
                if keycode in self.shift_keys():
                    self.shift = False
            return
        if code in self.pressed:   # held down: let go first, so a held key repeats
            xtest.fake_input(self.d, X.KeyRelease, self.pressed.pop(code))
        if key in self.NAMED:
            keycode = self.d.keysym_to_keycode(XK.string_to_keysym(self.NAMED[key]))
            if keycode:
                xtest.fake_input(self.d, X.KeyPress, keycode)
                self.pressed[code] = keycode
                self.shift = self.shift or key == "Shift"
            return
        if len(key) != 1:
            return
        symbol = ord(key) if ord(key) < 0x100 else 0x01000000 + ord(key)
        places = [(keycode, index) for keycode, index in self.d.keysym_to_keycodes(symbol) if index in (0, 1)]
        same = [keycode for keycode, index in places if index == (1 if self.shift else 0)]
        if same:   # where the keyboard map has it with Shift as it is now: an ordinary key press
            xtest.fake_input(self.d, X.KeyPress, same[0])
            self.pressed[code] = same[0]
        elif places and places[0][1] == 1:   # it needs Shift, which is not held: type it with Shift
            shift = self.d.keysym_to_keycode(XK.string_to_keysym("Shift_L"))
            for kind, keycode in ((X.KeyPress, shift), (X.KeyPress, places[0][0]),
                                  (X.KeyRelease, places[0][0]), (X.KeyRelease, shift)):
                xtest.fake_input(self.d, kind, keycode)
        else:   # not on the keyboard map, or not as Shift is now: lend it the spare keycode and type it
            self.d.change_keyboard_mapping(self.spare, [(symbol, symbol)])
            self.d.sync()
            xtest.fake_input(self.d, X.KeyPress, self.spare)
            xtest.fake_input(self.d, X.KeyRelease, self.spare)

    def tap(self, key, shift=False):
        if shift:
            self.key(True, "Shift", "tap-shift")
        self.key(True, key, "tap")
        self.key(False, key, "tap")
        if shift:
            self.key(False, "Shift", "tap-shift")

    def shift_keys(self):
        return {self.d.keysym_to_keycode(XK.string_to_keysym(n)) for n in ("Shift_L", "Shift_R")}

    def release(self):
        for keycode in self.pressed.values():
            xtest.fake_input(self.d, X.KeyRelease, keycode)
        for number in self.buttons:
            xtest.fake_input(self.d, X.ButtonRelease, number)
        self.pressed.clear()
        self.buttons.clear()
        self.shift = False


class Browser:
    """What the viewers are told about typing: whether a field has focus and where, and where the page's fields are.

    A script in each frame (fields.js) tells the page's part: where its fields are, so a phone can bring up its
    keyboard within a tap on one, and of the field with focus, its kind and the text before its caret. It runs in a
    world of its own, which the page cannot see, and is reached without the Runtime domain, whose events would let a
    page tell it is watched. Chrome's own fields, such as the address bar, are the input method's to tell (Typing).
    Another CDP client, such as an agent's, may make every page think it is shown, so the page in front is the one
    Chrome lists first, as its tab shown last.
    """
    WORLD = "shared-browser"

    def __init__(self):
        self.ws = None
        self.lock = threading.Lock()
        self.replies, self.count = {}, 0
        self.jobs = queue.Queue()
        self.sessions = {}         # tab -> our session with it
        self.pages = {}            # session with a frame of another site -> the session of its page
        self.frames = {}           # (session, context) -> what the frame last reported
        self.focus = None          # the field with focus, as the viewers were last told
        self.listening = set()     # (session, context) waiting for the frame's next report
        self.front = None          # the tab in front
        self.state = json.dumps({"t": "page", "focus": None, "fields": []})
        threading.Thread(target=self.run, daemon=True).start()
        threading.Thread(target=self.work, daemon=True).start()
        threading.Thread(target=self.follow_front, daemon=True).start()

    def follow_front(self):
        while True:
            try:
                with urllib.request.urlopen(CDP + "/json/list", timeout=2) as reply:
                    front = next((t["id"] for t in json.load(reply) if t.get("type") == "page"), None)
            except Exception:
                front = None
            if front != self.front:
                self.front = front
                self.update()
            time.sleep(0.3)

    def run(self):
        while True:
            try:
                with urllib.request.urlopen(CDP + "/json/version", timeout=2) as reply:
                    url = json.load(reply)["webSocketDebuggerUrl"]
                with connect(url, max_size=None, open_timeout=5) as ws:
                    self.ws = ws
                    self.jobs.put((self.call, ("Target.setAutoAttach",), {
                        "autoAttach": True, "waitForDebuggerOnStart": False, "flatten": True,
                        "filter": [{"type": "page"}]}))
                    for raw in ws:
                        self.receive(json.loads(raw))
            except Exception:
                pass
            with self.lock:
                self.ws = None
                self.replies.clear()
                self.sessions.clear()
                self.pages.clear()
                self.frames.clear()
                self.listening.clear()
            self.update()
            time.sleep(1)

    def work(self):
        while True:
            job, args, kwargs = self.jobs.get()
            try:
                job(*args, **kwargs)
            except Exception:
                pass

    def call(self, method, session=None, then=None, **params):
        """Send a command and wait for its result, None if it failed. With then, return at once and hand it the
        result when it comes."""
        done, result = threading.Event(), []
        with self.lock:
            if self.ws is None:
                return None
            self.count += 1
            self.replies[self.count] = then or (lambda value: (result.append(value), done.set()))
            message = {"id": self.count, "method": method, "params": params}
            if session:
                message["sessionId"] = session
            try:
                self.ws.send(json.dumps(message))
            except Exception:
                return None
        if then is None:
            done.wait(3)
            return result[0] if result else None

    def receive(self, message):
        if "id" in message:
            with self.lock:
                reply = self.replies.pop(message["id"], None)
            if reply:
                reply(message.get("result"))
            return
        method, params, session = message.get("method"), message.get("params", {}), message.get("sessionId")
        if method == "Target.attachedToTarget":
            with self.lock:
                if session:   # a frame of another site, in a process of its own: it counts as its page's
                    self.pages[params["sessionId"]] = self.pages.get(session, session)
                else:
                    self.sessions[params["targetInfo"]["targetId"]] = params["sessionId"]
            self.jobs.put((self.watch, (params["sessionId"],), {}))
        elif method in ("Page.frameNavigated", "Page.frameStoppedLoading"):
            frame = params["frame"]["id"] if "frame" in params else params["frameId"]
            self.jobs.put((self.install, (session, frame), {}))
        elif method == "Target.detachedFromTarget":
            with self.lock:
                for tab in [tab for tab, s in self.sessions.items() if s == params["sessionId"]]:
                    del self.sessions[tab]
                self.pages.pop(params["sessionId"], None)
                for key in [key for key in self.frames if key[0] == params["sessionId"]]:
                    del self.frames[key]
            self.update()

    def watch(self, session):
        """Look into every frame of a page, now and as its frames load, those of other sites included."""
        if self.call("Page.enable", session) is None:
            return
        self.call("Target.setAutoAttach", session, autoAttach=True, waitForDebuggerOnStart=False, flatten=True,
                  filter=[{"type": "iframe"}])
        tree = self.call("Page.getFrameTree", session)
        nodes = [tree["frameTree"]] if tree else []
        while nodes:
            node = nodes.pop()
            self.install(session, node["frame"]["id"])
            nodes.extend(node.get("childFrames", []))

    def install(self, session, frame):
        world = self.call("Page.createIsolatedWorld", session, frameId=frame, worldName=self.WORLD)
        if world and self.call("Runtime.evaluate", session, expression=FIELDS, contextId=world["executionContextId"]):
            key = (session, world["executionContextId"])
            with self.lock:
                if key in self.listening:
                    return
                self.listening.add(key)
            self.listen(key, first=True)

    def listen(self, key, first=False):
        """Wait for the frame's next report, or at first ask for how it is now: the script may have run before, for
        an earlier connection. Its world goes with its document, and then the wait ends with an error."""
        def heard(result):
            value = ((result or {}).get("result") or {}).get("value")
            report = json.loads(value) if isinstance(value, str) else {"gone": True}
            with self.lock:
                if report.get("gone"):
                    self.frames.pop(key, None)
                    self.listening.discard(key)
                else:
                    self.frames[key] = report
            self.update()
            if not report.get("gone"):
                self.listen(key)
        self.call("Runtime.evaluate", key[0], then=heard, expression=f"__sbNext({'true' if first else ''})",
                  contextId=key[1], awaitPromise=True, returnByValue=True)

    def update(self):
        """Put together what the viewers are told, and tell them when it changes.

        A field has focus in the page if the frame where focus last moved says so. Chrome's own fields, such as the
        address bar, are not the page's: for those the input method knows where the caret is.
        """
        with self.lock:
            session = self.sessions.get(self.front)
            frames = [(key, report) for key, report in self.frames.items() if self.pages.get(key[0], key[0]) == session]
        (where, context), last = max(frames, key=lambda frame: frame[1].get("moved", 0), default=((None, None), {}))
        caret = TYPING.caret
        if last.get("focus"):
            focus = dict(last["focus"], id=f"{where}/{context}/{last['focus']['id']}")
        elif caret:
            focus = {"id": "browser", "kind": "text", "before": "", "caret": caret,
                     "box": [caret[0] - 300, caret[1] - 8, caret[2] + 600, caret[3] + 16]}
        else:
            focus = None
        self.focus = focus
        fields = [box for _, report in frames for box in report.get("fields") or []]
        state = json.dumps({"t": "page", "focus": focus, "fields": fields})
        with self.lock:
            if state == self.state:
                return
            self.state = state
        with PEERS_LOCK:
            peers = list(PEERS.values())
        for peer in peers:
            peer.tell(state)

    def secret(self):
        return (self.focus or {}).get("kind") == "password"


class Typing:
    """An input method of the screen's own, which converts nothing: text comes made, from the viewer's device.

    It puts text in wherever typing goes, the way input methods do, a composition as it is made and then the text
    committed: a page's field, Chrome's address bar, its dialogs, other programs. So typing works the same
    everywhere, in any language. Chrome tells it where the caret is in its own fields, not in pages.
    """
    NAME = "shared-browser"

    def __init__(self):
        self.engine = None   # Chrome's input context, as the framework hands it to this input method
        self.caret = None    # where the caret is in a field of Chrome's own, while one has it: [x, y, width, height]
        self.settling = False
        IBus.init()
        GLib.idle_add(self.connect)

    def connect(self):
        bus = IBus.Bus.new()
        if not bus.is_connected():   # the framework may not be up yet, or may have been started again
            GLib.timeout_add_seconds(1, self.connect)
            return False
        bus.connect("disconnected", lambda _bus: GLib.timeout_add_seconds(1, self.connect))
        self.factory = IBus.Factory.new(bus.get_connection())
        self.factory.add_engine(self.NAME, GObject.type_from_name("ScreenField"))
        component = IBus.Component.new(f"org.sharedbrowser.{self.NAME}", "Text typed by viewers", "1", "", "", "", "",
                                       self.NAME)
        component.add_engine(IBus.EngineDesc.new(self.NAME, "Shared browser", "Text typed by viewers", "", "", "", "",
                                                 "us"))
        bus.register_component(component)
        bus.set_global_engine_async(self.NAME, -1, None, None, None)
        self.bus = bus
        return False

    def focused(self, engine):
        self.engine = engine

    def moved(self, engine, caret):
        """Where the caret is: in a field of Chrome's own, or nowhere Chrome tells, as in a page (all zero)."""
        caret = caret if any(caret) else None
        if engine is self.engine and caret != self.caret:
            self.caret = caret
            self.changed()

    def changed(self):
        """Tell the viewers once things settle: Chrome tells it over again as focus moves."""
        if not self.settling:
            self.settling = True
            GLib.timeout_add(40, self.settle)

    def settle(self):
        self.settling = False
        BROWSER.update()
        return False

    def commit(self, text):
        def put(engine):
            engine.update_preedit_text(IBus.Text.new_from_string(""), 0, False)
            engine.commit_text(IBus.Text.new_from_string(text))
        return self.on_main(put)

    def compose(self, text):
        def show(engine):
            preedit = IBus.Text.new_from_string(text)
            preedit.append_attribute(IBus.AttrType.UNDERLINE, IBus.AttrUnderline.SINGLE, 0, len(text))
            engine.update_preedit_text(preedit, len(text), bool(text))
        return self.on_main(show)

    def on_main(self, act):
        """Act on the main loop, where the input method lives, and wait, so what comes next comes after. False when
        Chrome has not handed the input method a context yet."""
        engine = self.engine
        if engine is None:
            return False
        done = threading.Event()

        def go():
            try:
                act(engine)
            finally:
                done.set()
            return False
        GLib.idle_add(go)
        return done.wait(1)


class ScreenField(IBus.Engine):
    """A program's input context, as the screen's input method sees it."""
    __gtype_name__ = "ScreenField"

    def do_focus_in(self):
        TYPING.focused(self)

    def do_set_cursor_location(self, x, y, width, height):
        TYPING.moved(self, [x, y, width, height])

    def do_process_key_event(self, keyval, keycode, state):
        return False   # keys pass as they come


INPUT = BROWSER = TYPING = CAPTURE = None


def turn_url(server, url):
    """A TURN address as webrtcbin takes it, with the credentials inside."""
    user, password = server.get("username", ""), server.get("credential", "")
    rest = url.split(":", 1)[1].lstrip("/")
    scheme = "turns" if url.startswith("turns:") else "turn"
    return f"{scheme}://{GLib.Uri.escape_string(user, None, False)}:{GLib.Uri.escape_string(password, None, False)}@{rest}"


def reachable(sdp):
    """Only UDP candidates; with a known public address, host candidates carry it instead of the container's."""
    lines = []
    for line in sdp.split("\r\n"):
        if line.startswith("a=candidate:"):
            parts = line.split()
            if parts[2].upper() != "UDP":
                continue
            if PUBLIC_IP and parts[7] == "host":
                parts[4] = PUBLIC_IP
            line = " ".join(parts)
        lines.append(line)
    return "\r\n".join(lines)


def timed(pipe):
    """Every pipeline counts time on one clock from one moment, so a frame's time means the same in each."""
    pipe.use_clock(CLOCK)
    pipe.set_start_time(Gst.CLOCK_TIME_NONE)
    pipe.set_base_time(BASE)
    return pipe


class Capture:
    """The display, captured once for everyone watching. Each connection encodes these frames at its own rate.

    Once, not once for each connection: ximagesrc holds the X server grabbed while it takes a frame, and takes
    Xlib's process-wide lock on the way. A second ximagesrc opening its display holds that lock while it waits for
    the server, which the grab keeps from answering. The two wait for each other, and the X server stays grabbed:
    the browser and every picture stop.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.pipe = None
        self.watching = ()   # each connection's appsrc; replaced whole, so frames go out without the lock

    def join(self, frames):
        with self.lock:
            if self.pipe is None:
                self.pipe = timed(Gst.parse_launch(
                    f"ximagesrc display-name={DISPLAY} use-damage=false show-pointer=true "
                    f"! video/x-raw,framerate={FPS}/1 ! videoconvert n-threads=4 ! video/x-raw,format=I420 "
                    "! appsink name=frames emit-signals=true max-buffers=1 drop=true sync=false"))
                self.pipe.get_by_name("frames").connect("new-sample", self.send)
                bus = self.pipe.get_bus()
                bus.add_signal_watch()
                bus.connect("message::error", lambda _bus, message: print("capture error:", message.parse_error(),
                                                                          flush=True))
                self.pipe.set_state(Gst.State.PLAYING)
            self.watching += (frames,)

    def leave(self, frames):
        with self.lock:
            self.watching = tuple(other for other in self.watching if other is not frames)
            if not self.watching and self.pipe is not None:
                self.pipe.set_state(Gst.State.NULL)
                self.pipe.get_bus().remove_signal_watch()
                self.pipe = None

    def send(self, sink):
        sample = sink.emit("pull-sample")
        for frames in self.watching:
            frames.emit("push-sample", sample)   # never waits: a connection that is behind drops its older frame
        return Gst.FlowReturn.OK


class Peer:
    """One person's connection: an encoder and a WebRTC endpoint of its own, fed from the one capture."""

    def __init__(self, who, session):
        self.id, self.who, self.session = secrets.token_urlsafe(12), who, session
        self.closed = False
        self.pipe = timed(Gst.parse_launch(
            "appsrc name=frames is-live=true format=time max-buffers=1 max-bytes=0 leaky-type=downstream "
            f"! x264enc name=encoder tune=zerolatency speed-preset=ultrafast key-int-max={FPS * 60} vbv-buf-capacity=120 "
            "! video/x-h264,profile=constrained-baseline ! rtph264pay config-interval=-1 aggregate-mode=zero-latency "
            f"! {RTP} ! webrtcbin name=webrtc bundle-policy=max-bundle"))
        self.frames = self.pipe.get_by_name("frames")
        self.webrtc = self.pipe.get_by_name("webrtc")
        encoder = self.pipe.get_by_name("encoder")
        self.rate = Rate(lambda kbps: encoder.set_property("bitrate", int(kbps)), KBPS)
        limit_ports(self.webrtc)
        for server in ICE_SERVERS:
            for url in server.get("urls", []):
                if url.startswith("stun:"):
                    self.webrtc.set_property("stun-server", "stun://" + url[5:])
                elif url.startswith(("turn:", "turns:")):
                    self.webrtc.emit("add-turn-server", turn_url(server, url))
        if STUN and not PUBLIC_IP and not ICE_SERVERS:
            self.webrtc.set_property("stun-server", "stun://" + STUN.removeprefix("stun:"))
        gathered = threading.Event()
        self.webrtc.connect("notify::ice-gathering-state", lambda element, _: gathered.set() if element.get_property(
            "ice-gathering-state") == GstWebRTC.WebRTCICEGatheringState.COMPLETE else None)
        self.webrtc.connect("notify::connection-state", weakly(self.on_state))
        bus = self.pipe.get_bus()
        bus.add_signal_watch()
        bus.connect("message::error", lambda _bus, message: print("screen error:", message.parse_error(), flush=True))
        self.pipe.set_state(Gst.State.PLAYING)

        transceiver = self.webrtc.emit("get-transceiver", 0)
        transceiver.set_property("direction", GstWebRTC.WebRTCRTPTransceiverDirection.SENDONLY)
        transceiver.set_property("codec-preferences", Gst.Caps.from_string(RTP))
        transceiver.set_property("do-nack", True)
        self.channel = self.webrtc.emit("create-data-channel", "input", None)
        self.channel.connect("on-open", lambda channel: channel.emit("send-string", BROWSER.state))
        self.channel.connect("on-message-string", lambda _channel, text: INPUT.handle(text))
        self.channel.connect("on-close", lambda _channel: INPUT.handle('{"t": "release"}'))
        promise = Gst.Promise.new()
        self.webrtc.emit("create-offer", None, promise)
        promise.wait()
        reply = promise.get_reply()   # the offer lives inside the reply, which must stay alive while it is used
        offer = reply.get_value("offer")
        done = Gst.Promise.new()
        self.webrtc.emit("set-local-description", offer, done)
        done.wait()
        gathered.wait(5)
        self.offer = reachable(self.webrtc.get_property("local-description").sdp.as_text())
        CAPTURE.join(self.frames)
        GLib.timeout_add_seconds(30, weakly(self.close_if_unanswered))

    def answer(self, sdp):
        _, message = GstSdp.SDPMessage.new_from_text(sdp)
        self.webrtc.emit("set-remote-description",
                         GstWebRTC.WebRTCSessionDescription.new(GstWebRTC.WebRTCSDPType.ANSWER, message), Gst.Promise.new())
        session = self.webrtc.get_by_name("rtpbin").emit("get-session", 0)
        session.connect("notify::twcc-stats", weakly(self.on_feedback))

    def on_feedback(self, session, _):
        stats = session.get_property("twcc-stats")
        if stats.get_value("packets-recv"):
            self.rate.report(stats.get_value("bitrate-sent") / 1000, stats.get_value("bitrate-recv") / 1000,
                             stats.get_value("packet-loss-pct"))

    def on_state(self, element, _):
        if element.get_property("connection-state") in (GstWebRTC.WebRTCPeerConnectionState.FAILED,
                                                         GstWebRTC.WebRTCPeerConnectionState.CLOSED):
            threading.Thread(target=self.close, daemon=True).start()   # not from webrtcbin's own thread

    def close_if_unanswered(self):
        if self.webrtc.get_property("connection-state") != GstWebRTC.WebRTCPeerConnectionState.CONNECTED:
            threading.Thread(target=self.close, daemon=True).start()
        return False

    def tell(self, text):
        if not self.closed and self.channel.get_property("ready-state") == GstWebRTC.WebRTCDataChannelState.OPEN:
            self.channel.emit("send-string", text)

    def close(self):
        with PEERS_LOCK:
            if self.closed:
                return
            self.closed = True
            PEERS.pop(self.id, None)
        CAPTURE.leave(self.frames)
        self.pipe.set_state(Gst.State.NULL)
        self.pipe.get_bus().remove_signal_watch()


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/peers":
            with PEERS_LOCK:
                self.reply(200, [{"id": p.id, "as": p.who, "session": p.session} for p in PEERS.values()])
        else:
            self.reply(404, {})

    def do_POST(self):
        try:
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        except ValueError:
            return self.reply(400, {})
        if self.path == "/offer":
            with PEERS_LOCK:
                full = len(PEERS) >= len(PORTS)
            if full:
                return self.reply(503, {"error": "full"})
            peer = Peer(str(body.get("as", "")), str(body.get("session", "")))
            with PEERS_LOCK:
                PEERS[peer.id] = peer
            servers = [{k: v for k, v in s.items() if k in ("urls", "username", "credential")} for s in ICE_SERVERS]
            return self.reply(200, {"id": peer.id, "sdp": peer.offer, "iceServers": servers})
        with PEERS_LOCK:
            peer = PEERS.get(str(body.get("id", "")))
        if self.path == "/answer" and peer and peer.who == body.get("as"):
            peer.answer(str(body.get("sdp", "")))
            return self.reply(200, {})
        if self.path == "/close":
            if peer and body.get("as") in (None, peer.who):
                peer.close()
            return self.reply(200, {})
        self.reply(404, {})

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    INPUT = Input()
    TYPING = Typing()
    BROWSER = Browser()
    CAPTURE = Capture()
    threading.Thread(target=GLib.MainLoop().run, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
