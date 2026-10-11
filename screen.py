#!/usr/bin/env python3
"""The screen: sends what the display shows to each person watching, over WebRTC, and takes their mouse and keys.

It listens on loopback and trusts whoever reaches it; the gate decides who that is.
  POST /offer   {"as", "session"}       -> {"id", "sdp", "iceServers"}   a new connection, for the viewer to answer
  POST /answer  {"id", "as", "sdp"}
  POST /close   {"id", ["as"]}
  GET  /peers                           -> [{"id", "as", "session"}]

Each connection has its own encoder, so each gets the rate its own link carries. Mouse and keys arrive on the
connection's data channel and are played into the display as if from a real mouse and keyboard.
"""
import ctypes
import json
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import gi

gi.require_version("Gst", "1.0")
gi.require_version("GstSdp", "1.0")
gi.require_version("GstWebRTC", "1.0")
from gi.repository import GLib, Gst, GstSdp, GstWebRTC  # noqa: E402
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
RTP = ("application/x-rtp,media=video,encoding-name=H264,payload=102,clock-rate=90000,packetization-mode=(string)1,"
       "rtcp-fb-nack-pli=true,rtcp-fb-nack=true,rtcp-fb-transport-cc=(boolean)true,"
       "extmap-1=(string)http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01")

Gst.init(None)
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

    def handle(self, message):
        try:
            m = json.loads(message)
        except ValueError:
            return
        with self.lock:
            kind = m.get("t")
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
            self.d.sync()

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


INPUT = None


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


class Peer:
    """One person's connection: a capture, an encoder and a WebRTC endpoint of its own."""

    def __init__(self, who, session):
        self.id, self.who, self.session = secrets.token_urlsafe(12), who, session
        self.closed = False
        self.pipe = Gst.parse_launch(
            f"ximagesrc display-name={DISPLAY} use-damage=false show-pointer=true ! video/x-raw,framerate={FPS}/1 "
            "! videoconvert n-threads=4 ! video/x-raw,format=I420 "
            "! queue max-size-buffers=1 max-size-bytes=0 max-size-time=0 leaky=downstream "
            f"! x264enc name=encoder tune=zerolatency speed-preset=ultrafast key-int-max={FPS * 60} vbv-buf-capacity=120 "
            "! video/x-h264,profile=constrained-baseline ! rtph264pay config-interval=-1 aggregate-mode=zero-latency "
            f"! {RTP} ! webrtcbin name=webrtc bundle-policy=max-bundle")
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
        self.webrtc.connect("notify::connection-state", self.on_state)
        bus = self.pipe.get_bus()
        bus.add_signal_watch()
        bus.connect("message::error", lambda _bus, message: print("screen error:", message.parse_error(), flush=True))
        self.pipe.set_state(Gst.State.PLAYING)

        transceiver = self.webrtc.emit("get-transceiver", 0)
        transceiver.set_property("direction", GstWebRTC.WebRTCRTPTransceiverDirection.SENDONLY)
        transceiver.set_property("codec-preferences", Gst.Caps.from_string(RTP))
        transceiver.set_property("do-nack", True)
        self.channel = self.webrtc.emit("create-data-channel", "input", None)
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
        GLib.timeout_add_seconds(30, self.close_if_unanswered)

    def answer(self, sdp):
        _, message = GstSdp.SDPMessage.new_from_text(sdp)
        self.webrtc.emit("set-remote-description",
                         GstWebRTC.WebRTCSessionDescription.new(GstWebRTC.WebRTCSDPType.ANSWER, message), Gst.Promise.new())
        session = self.webrtc.get_by_name("rtpbin").emit("get-session", 0)
        session.connect("notify::twcc-stats", self.on_feedback)

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

    def close(self):
        with PEERS_LOCK:
            if self.closed:
                return
            self.closed = True
            PEERS.pop(self.id, None)
        self.pipe.set_state(Gst.State.NULL)


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
    threading.Thread(target=GLib.MainLoop().run, daemon=True).start()
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
