"""Exercise real Scapy capture threads without opening raw network sockets."""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from scapy.automaton import ObjectPipe
from scapy.error import Scapy_Exception
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import AsyncSniffer

LIB_PATH = Path(__file__).resolve().parents[1] / "custom_components/homeplug_av/pla-util-py"
if str(LIB_PATH) not in sys.path:
    sys.path.insert(0, str(LIB_PATH))

from pla_util_py import network

LOCAL_MAC = "00:11:22:33:44:55"
PEER_MAC = "aa:bb:cc:dd:ee:ff"
ETHER_TYPE = 0x88E1


def _reply(*, src=PEER_MAC, dst=LOCAL_MAC, ether_type=ETHER_TYPE, payload=b"reply"):
    return Ether(src=src, dst=dst, type=ether_type) / Raw(load=payload)


@pytest.fixture
def capture(monkeypatch):
    pipe = ObjectPipe("homeplug-test-packets")
    gate = threading.Event()
    gate.set()
    state = SimpleNamespace(
        pipe=pipe,
        gate=gate,
        ready=threading.Event(),
        sniffers=[],
        sent=[],
        timers=[],
        on_send=lambda: None,
        startup_error=None,
        start_error=None,
        socket_error=None,
        capture_error=None,
        stop_race=None,
        release_during_cleanup=False,
    )

    class CaptureSniffer(AsyncSniffer):
        def _run(self, *args, **kwargs):
            if not gate.wait(2):
                raise RuntimeError("Test capture startup gate was not released")
            if state.startup_error is not None:
                raise state.startup_error
            if state.capture_error is not None:
                kwargs["started_callback"]()
                raise state.capture_error
            return super()._run(*args, **kwargs)

        def start(self):
            if state.start_error is not None:
                raise state.start_error
            return super().start()

        def join(self, timeout=None):
            if state.release_during_cleanup and timeout is not None and timeout > 0:
                gate.set()
            return super().join(timeout=timeout)

        def stop(self, join=True):
            if state.stop_race:
                # Simulate count=1 finishing between the running check and stop().
                super().stop(join=True)
                raise state.stop_race
            return super().stop(join=join)

    def factory(**kwargs):
        kwargs.pop("iface")
        callback = kwargs.pop("started_callback", lambda: None)

        def started():
            state.ready.set()
            callback()

        if state.socket_error is not None:
            def fail_socket(**socket_kwargs):
                raise state.socket_error

            sniffer = CaptureSniffer(
                iface="test-interface", L2socket=fail_socket,
                started_callback=started, **kwargs,
            )
        else:
            sniffer = CaptureSniffer(opened_socket=pipe, started_callback=started, **kwargs)
        state.sniffers.append(sniffer)
        return sniffer

    def send(frame, *, iface, verbose):
        assert state.ready.is_set(), "Request sent before capture became ready"
        assert iface == "test-interface"
        assert verbose is False
        state.sent.append(frame)
        state.on_send()

    monkeypatch.setattr(network, "AsyncSniffer", factory)
    monkeypatch.setattr(network, "get_if_hwaddr", lambda iface: LOCAL_MAC)
    monkeypatch.setattr(network, "sendp", send)
    yield state

    # Always clean up, including when a regression causes a test to fail.
    gate.set()
    for timer in state.timers:
        timer.cancel()
        timer.join(timeout=1)
    for sniffer in state.sniffers:
        if sniffer.running:
            try:
                sniffer.stop(join=False)
            except Exception:
                pass
        try:
            sniffer.join(timeout=1)
        except Exception:
            pass
        assert sniffer.thread is None or not sniffer.thread.is_alive()
    pipe.close()


def _request(helper, **kwargs):
    return helper(b"request", interface="test-interface", ether_type=ETHER_TYPE, **kwargs)


def _assert_stopped(capture):
    assert len(capture.sniffers) == 1
    sniffer = capture.sniffers[0]
    assert sniffer.thread is None or not sniffer.thread.is_alive()
    if sniffer.exception is None:
        assert not sniffer.running
    assert "timeout" not in sniffer.kwargs


def test_single_reply_works_with_current_async_sniffer_api(capture):
    reply = _reply()
    capture.on_send = lambda: capture.pipe.send(reply)

    assert _request(network.send_message, timeout=0.1) is reply
    assert bytes(capture.sent[0][Raw]) == b"request"
    _assert_stopped(capture)


@pytest.mark.parametrize("helper", [network.send_message, network.send_message_collect])
def test_no_reply_stops_and_joins_capture(helper, capture):
    started = time.monotonic()

    assert _request(helper, timeout=0.03) in (None, [])

    assert time.monotonic() - started < 1
    assert len(capture.sent) == 1
    _assert_stopped(capture)


@pytest.mark.parametrize("helper", [network.send_message, network.send_message_collect])
@pytest.mark.parametrize("error_type", [OSError, KeyboardInterrupt])
def test_transmit_failure_still_stops_capture(helper, error_type, capture):
    def fail():
        raise error_type("transmission failed")

    capture.on_send = fail

    with pytest.raises(error_type, match="transmission failed"):
        _request(helper, timeout=0.1)

    _assert_stopped(capture)


@pytest.mark.parametrize("helper", [network.send_message, network.send_message_collect])
def test_capture_start_failure_does_not_transmit(helper, capture):
    capture.start_error = RuntimeError("cannot start capture thread")

    with pytest.raises(RuntimeError, match="cannot start capture thread"):
        _request(helper, timeout=0.1)

    assert not capture.sent
    _assert_stopped(capture)


@pytest.mark.parametrize("helper", [network.send_message, network.send_message_collect])
def test_capture_worker_failure_is_propagated_without_transmitting(helper, capture):
    capture.startup_error = PermissionError("raw socket permission denied")

    with pytest.raises(PermissionError, match="raw socket permission denied"):
        _request(helper, timeout=0.1)

    assert not capture.sent
    _assert_stopped(capture)


@pytest.mark.parametrize("helper", [network.send_message, network.send_message_collect])
def test_real_socket_startup_failure_is_propagated(helper, capture):
    capture.socket_error = PermissionError("raw socket permission denied")

    with pytest.raises(PermissionError, match="raw socket permission denied"):
        _request(helper, timeout=0.1)

    assert not capture.sent
    _assert_stopped(capture)


@pytest.mark.parametrize("helper", [network.send_message, network.send_message_collect])
def test_capture_failure_after_readiness_is_propagated(helper, capture):
    capture.capture_error = OSError("capture failed")

    with pytest.raises(OSError, match="capture failed"):
        _request(helper, timeout=0.1)

    _assert_stopped(capture)


@pytest.mark.parametrize("helper", [network.send_message, network.send_message_collect])
def test_delayed_capture_readiness_precedes_transmit(helper, capture):
    capture.gate.clear()
    timer = threading.Timer(0.03, capture.gate.set)
    capture.timers.append(timer)
    timer.start()
    reply = _reply()
    capture.on_send = lambda: capture.pipe.send(reply)

    result = _request(helper, timeout=0.1)

    assert result is reply or result == [reply]
    _assert_stopped(capture)


@pytest.mark.parametrize("helper", [network.send_message, network.send_message_collect])
def test_late_start_after_readiness_timeout_is_cancelled(helper, capture, monkeypatch):
    monkeypatch.setattr(network, "_SNIFFER_START_TIMEOUT", 0.02, raising=False)
    capture.gate.clear()
    # The cleanup join releases the gate only after readiness has timed out.
    capture.release_during_cleanup = True

    with pytest.raises(network.NetworkError, match="capture.*ready"):
        _request(helper, timeout=0.01)

    assert not capture.sent
    _assert_stopped(capture)


@pytest.mark.parametrize("helper", [network.send_message, network.send_message_collect])
def test_packet_filters_ignore_unrelated_frames(helper, capture):
    reply = _reply(payload=b"accepted")
    packets = [
        Raw(load=b"not Ethernet"),
        _reply(ether_type=0x0800),
        _reply(dst="00:11:22:33:44:66"),
        _reply(src="aa:bb:cc:dd:ee:00"),
        _reply(payload=b"wrong command"),
        reply,
    ]
    capture.on_send = lambda: [capture.pipe.send(packet) for packet in packets]

    result = _request(
        helper,
        timeout=0.1,
        dest_mac=PEER_MAC,
        response_match=lambda packet: bytes(packet[Raw]) == b"accepted",
    )

    assert result is reply or result == [reply]
    _assert_stopped(capture)


def test_collect_captures_multiple_broadcast_replies(capture):
    replies = [_reply(), _reply(src="aa:bb:cc:dd:ee:01")]
    capture.on_send = lambda: [capture.pipe.send(reply) for reply in replies]

    assert _request(network.send_message_collect, timeout=0.1, window=0.02) == replies
    _assert_stopped(capture)


def test_collect_window_continues_after_first_reply(capture):
    first = _reply()
    second = _reply(src="aa:bb:cc:dd:ee:01")

    def send():
        capture.pipe.send(first)
        timer = threading.Timer(0.06, lambda: capture.pipe.send(second))
        capture.timers.append(timer)
        timer.start()

    capture.on_send = send

    assert _request(network.send_message_collect, timeout=0.03, window=0.1) == [first, second]
    _assert_stopped(capture)


@pytest.mark.parametrize("error", [Scapy_Exception("Not running"), OSError("socket closed")])
def test_stop_race_does_not_turn_timeout_into_error(capture, error):
    capture.stop_race = error

    assert _request(network.send_message_collect, timeout=0.01) == []
    _assert_stopped(capture)


def test_zero_timeout_still_cleans_up_capture(capture):
    assert _request(network.send_message, timeout=0) is None
    _assert_stopped(capture)


@pytest.mark.parametrize("helper", [network.send_message, network.send_message_collect])
def test_capture_uses_monotonic_time(helper, capture, monkeypatch):
    def wall_clock_must_not_be_used():
        raise AssertionError("Wall clock used for capture deadline")

    monkeypatch.setattr(
        network,
        "time",
        SimpleNamespace(
            monotonic=time.monotonic,
            sleep=time.sleep,
            time=wall_clock_must_not_be_used,
        ),
    )

    assert _request(helper, timeout=0.01) in (None, [])
    _assert_stopped(capture)
