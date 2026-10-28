from __future__ import annotations

"""Low-level network helpers built on *Scapy*.

This is *not* a full abstraction of the Ada `Packets.Network_Devices` API – it
only provides the basic functionality needed by the high-level command
implementation:

* open a specific interface (or guess the first active non-loopback one)
* craft an Ethernet frame that contains one of our payload buffers
* send the frame
* wait for a single reply (optional)

The original program uses libpcap in *immediate* mode and waits on a poll()able
file descriptor.  Scapy does all the heavy lifting for us.
"""

from contextlib import contextmanager
from threading import Event
from typing import Callable, Iterator, Optional, Any
import logging
import time
import platform
import os

from scapy.all import Ether, Raw, sendp, conf, get_if_hwaddr  # type: ignore
from scapy.error import Scapy_Exception  # type: ignore
from scapy.sendrecv import AsyncSniffer  # type: ignore

from .messages import ether_type_for_payload

_LOG = logging.getLogger(__name__)


class NetworkError(RuntimeError):
    """Raised for unrecoverable network-level issues."""


DEFAULT_TIMEOUT = 0.5  # seconds – mirrors Ada default of 500 ms
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"
_SNIFFER_START_TIMEOUT = 1.0
_SNIFFER_STOP_TIMEOUT = 1.0
_CAPTURE_POLL_INTERVAL = 0.01


__all__ = [
    "send_message",
    "DEFAULT_TIMEOUT",
    "BROADCAST_MAC",
    "NetworkError",
]


def _resolve_interface(preferred: Optional[str] = None) -> str:
    """Return *preferred* if given, otherwise guess a usable interface."""

    if preferred:
        return preferred

    # Best-effort pick the first *up* interface that is not the loopback.
    # When Scapy is initialised it populates `conf.ifaces`, which is a mapping
    # with rich metadata – we just iterate over it.
    for iface in conf.ifaces.values():
        if iface.is_up() and not iface.is_loopback:
            return iface.name

    raise NetworkError("Could not find a suitable network interface – use --interface")


@contextmanager
def _capture(timeout: float, **kwargs: Any) -> Iterator[AsyncSniffer]:
    """Start capture before transmission and stop/join it on every exit path."""

    ready = Event()
    cancelled = Event()

    def _started() -> None:
        ready.set()
        # Socket initialization may finish after readiness timed out. Scapy
        # catches KeyboardInterrupt in this worker and closes its sockets.
        # stop() here is not sufficient on 2.6.1: that version resets its stop
        # flag after started_callback returns. Never join from this worker.
        if cancelled.is_set():
            raise KeyboardInterrupt

    # Scapy 2.8+ rejects timeout= here. Response deadlines belong to join().
    sniffer = AsyncSniffer(started_callback=_started, **kwargs)
    try:
        sniffer.start()
        deadline = time.monotonic() + max(_SNIFFER_START_TIMEOUT, timeout)
        while not ready.wait(_CAPTURE_POLL_INTERVAL):
            sniffer.join(timeout=0)  # propagate socket/thread startup failures
            if sniffer.thread is None or not sniffer.thread.is_alive():
                raise NetworkError("Packet capture stopped before it became ready")
            if time.monotonic() >= deadline:
                raise NetworkError("Packet capture did not become ready in time")
        yield sniffer
    finally:
        cancelled.set()
        try:
            if ready.is_set() and sniffer.running:
                try:
                    sniffer.stop(join=False)
                except (Scapy_Exception, OSError):
                    # count=1 may finish between the running check and stop().
                    if sniffer.running:
                        raise
        finally:
            sniffer.join(timeout=_SNIFFER_STOP_TIMEOUT)
            if sniffer.thread is not None and sniffer.thread.is_alive():
                raise NetworkError("Packet capture did not stop in time")


def send_message(
    payload: bytes,
    interface: Optional[str] = None,
    dest_mac: str = BROADCAST_MAC,
    timeout: float = DEFAULT_TIMEOUT,
    ether_type: int | None = None,
    response_match: Callable[[Any], bool] | None = None,
):
    """Send *payload* on *interface* to *dest_mac* and wait for a reply.

    Returns a Scapy packet instance or ``None`` when *timeout* expires.
    """

    iface = _resolve_interface(interface)
    if ether_type is None:
        ether_type = ether_type_for_payload(payload)
    src_mac = get_if_hwaddr(iface)

    frame = Ether(src=src_mac, dst=dest_mac, type=ether_type) / Raw(load=payload)

    _LOG.debug("Sending %d-byte frame on %s (0x%04x → %s)", len(payload), iface, ether_type, dest_mac)

    # The reply can come from *any* PLA, so we only filter on EtherType (and
    # destination MAC == our MAC).  If the caller specified a unicast dest MAC
    # we also accept that as the source in the reply.
    def _match(pkt):  # type: ignore[override]
        if Ether not in pkt:  # pragma: no cover – defensive
            return False
        if pkt.type != ether_type:
            return False
        if pkt[Ether].dst.lower() != src_mac.lower():
            return False
        # When we addressed a specific adapter, enforce that in the reply.
        if dest_mac != BROADCAST_MAC and pkt[Ether].src.lower() != dest_mac.lower():
            return False
        if response_match is not None and not response_match(pkt):
            return False
        return True

    # Wait until capture is ready, then transmit and wait for one reply.
    # join(timeout) does not stop capture by itself: _capture handles cleanup.
    with _capture(timeout, iface=iface, lfilter=_match, count=1, store=True) as sniffer:
        t_start = time.monotonic()
        sendp(frame, iface=iface, verbose=False)
        sniffer.join(timeout=timeout)

    pkts = sniffer.results  # populated after the capture thread has stopped
    elapsed = time.monotonic() - t_start

    if pkts:
        _LOG.debug("Received %d-byte reply after %.3f s", len(pkts[0]), elapsed)
        return pkts[0]

    _LOG.debug("No reply after %.3fs", timeout)
    return None


# ---------------------------------------------------------------------------
# Platform-specific tweak ------------------------------------------------------
# ---------------------------------------------------------------------------
# On Linux Scapy's libpcap backend buffers packets unless immediate mode is
# enabled – that makes our sub-second timeouts unreliable.  Scapy's raw-socket
# backend, on the other hand, delivers frames right away (similar to the BPF
# backend used by default on macOS).  We therefore disable libpcap when we're
# on Linux, unless the user forces it back via an environment variable.
if platform.system() == "Linux":
    if bool(int(os.getenv("PLA_UTIL_PY_FORCE_PCAP", "0"))):
        conf.use_pcap = True
        _LOG.debug("Running on Linux – forced libpcap backend")
    else:
        conf.use_pcap = False
        _LOG.debug("Running on Linux – disabled libpcap backend (use raw sockets)")


# ---------------------------------------------------------------------------
# Helper that collects **all** replies for a short window
# ---------------------------------------------------------------------------


def send_message_collect(
    payload: bytes,
    interface: Optional[str] = None,
    dest_mac: str = BROADCAST_MAC,
    timeout: float = DEFAULT_TIMEOUT,
    window: float | None = None,
    ether_type: int | None = None,
    response_match: Callable[[Any], bool] | None = None,
):
    """Send *payload* and return a list of reply packets.

    A first reply is waited for up to *timeout* seconds.  If one arrives, we
    continue capturing for *window* seconds (defaults to *timeout*) to collect
    additional confirmations that may come from other adapters.
    """

    if window is None:
        window = timeout

    iface = _resolve_interface(interface)
    if ether_type is None:
        ether_type = ether_type_for_payload(payload)
    src_mac = get_if_hwaddr(iface)

    frame = Ether(src=src_mac, dst=dest_mac, type=ether_type) / Raw(load=payload)

    _LOG.debug(
        "[collect] Sending %d-byte frame on %s (0x%04x → %s)", len(payload), iface, ether_type, dest_mac
    )

    # Arm a sniffer to capture *all* matching packets, first until the first
    # reply (or *timeout*), then for an additional *window* seconds so we can
    # gather confirmations from other adapters.

    # We cannot express this "wait X seconds *after* first match" logic with
    # a single AsyncSniffer, so we use a small helper below.

    def _match(pkt):  # type: ignore[override]
        if Ether not in pkt:
            return False
        if pkt.type != ether_type:
            return False
        if pkt[Ether].dst.lower() != src_mac.lower():
            return False
        if dest_mac != BROADCAST_MAC and pkt[Ether].src.lower() != dest_mac.lower():
            return False
        if response_match is not None and not response_match(pkt):
            return False
        return True

    # ------------------------------------------------------------------
    # Capture helper ----------------------------------------------------
    # ------------------------------------------------------------------
    captured: list[Any] = []  # we will fill this from the sniffer callback

    def _store(pkt):  # type: ignore[override]
        captured.append(pkt)

    # Start sniffer *before* we transmit to avoid races.  We do not rely on
    # the "results" attribute (which is only populated once the sniffer is
    # stopped) but store packets on-the-fly via the callback above.

    with _capture(timeout, iface=iface, lfilter=_match, prn=_store, store=False) as sniffer:
        sendp(frame, iface=iface, verbose=False)

        # Wait for the first confirmation, checking for capture-thread failures.
        deadline = time.monotonic() + timeout
        while not captured:
            sniffer.join(timeout=0)
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not sniffer.running:
                return []
            time.sleep(min(_CAPTURE_POLL_INTERVAL, remaining))

        # First reply seen – keep listening for an additional window.
        deadline = time.monotonic() + window
        while sniffer.running:
            sniffer.join(timeout=0)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(_CAPTURE_POLL_INTERVAL, remaining))

    return captured
