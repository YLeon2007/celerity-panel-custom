"""Real multiplexed pipe frames: no threads, network, root or deadline reset."""
from contextlib import contextmanager
import os
import subprocess
import sys
import time
import unittest

import coordinated_restore as c


@contextmanager
def pipes(body, durations=(.8, .8, .8)):
    pairs = [os.pipe() for _ in durations]
    writers = [writer for _, writer in pairs]
    code = 'import os,time\nfds='+repr(writers)+'\n'+body+'\ntime.sleep(2)'
    child = subprocess.Popen([sys.executable, '-c', code], pass_fds=writers,
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for writer in writers:
        os.close(writer)
    start = time.monotonic()
    wires = [c.Wire(reader, -1, start+duration) for (reader, _), duration in zip(pairs, durations)]
    try:
        yield wires
    finally:
        if child.poll() is None:
            child.terminate()
        child.wait(timeout=3)
        assert child.stderr is not None
        stderr = child.stderr.read()
        child.stderr.close()
        for reader, _ in pairs:
            os.close(reader)
        if stderr:
            raise AssertionError(stderr.decode())


class MultiplexCodec(unittest.TestCase):
    def test_partial_first_frame_does_not_block_other_ready_frames(self):
        body = '''os.write(fds[0], b'{"x":')
os.write(fds[1], b'{"x":1}\\n')
os.write(fds[2], b'{"x":2}\\n')
time.sleep(.06)
os.write(fds[0], b'0}\\n')'''
        with pipes(body) as wires:
            deadlines = [wire.deadline for wire in wires]
            replies = list(c.Wire.receive_many(wires))
            self.assertEqual(replies[-1], (wires[0], {'x': 0}))
            self.assertEqual({value['x'] for _, value in replies}, {0, 1, 2})
            self.assertEqual([wire.deadline for wire in wires], deadlines)

    def test_pending_eof_interrupts_partial_and_silent_peers(self):
        with pipes("os.write(fds[0], b'{'); time.sleep(.04); os.close(fds[2])") as wires:
            started = time.monotonic()
            with self.assertRaisesRegex(c.Refusal, 'CHANNEL_EOF'):
                list(c.Wire.receive_many(wires))
            self.assertLess(time.monotonic()-started, .6)
            self.assertEqual(wires[0].buffer, b'{')

    def test_completed_eof_remains_watched_while_other_peers_are_silent(self):
        with pipes("os.write(fds[0], b'{}\\n'); time.sleep(.04); os.close(fds[0])") as wires:
            started = time.monotonic()
            replies = c.Wire.receive_many(wires)
            self.assertEqual(next(replies), (wires[0], {}))
            with self.assertRaisesRegex(c.Refusal, 'OTHER_CHANNEL_LOST'):
                list(replies)
            self.assertLess(time.monotonic()-started, .6)

    def test_completed_peer_unsolicited_frame_is_not_an_additional_reply(self):
        with pipes("os.write(fds[0], b'{}\\n'); time.sleep(.04); os.write(fds[0], b'{}\\n')") as wires:
            replies = c.Wire.receive_many(wires)
            self.assertEqual(next(replies), (wires[0], {}))
            with self.assertRaisesRegex(c.Refusal, 'OTHER_CHANNEL_LOST'):
                list(replies)

    def test_earliest_original_deadline_still_bounds_completed_peer(self):
        with pipes("os.write(fds[0], b'{}\\n')", durations=(.15, .8, .8)) as wires:
            deadlines = [wire.deadline for wire in wires]
            started = time.monotonic()
            with self.assertRaisesRegex(c.Refusal, 'CHANNEL_TIMEOUT'):
                list(c.Wire.receive_many(wires))
            self.assertLess(time.monotonic()-started, .6)
            self.assertEqual([wire.deadline for wire in wires], deadlines)

    def test_rejects_bad_frame_before_waiting_for_silent_peers(self):
        cases = {
            'pipelined': b'{}\n{}\n',
            'malformed': b'{\n',
            'array': b'[]\n',
            'duplicate': b'{"x":1,"x":2}\n',
            'constant': b'{"x":NaN}\n',
            'oversized': b'x'*131073,
        }
        for name, raw in cases.items():
            body = "raw="+("b'x'*131073" if name == 'oversized' else repr(raw))+"\nwhile raw:\n n=os.write(fds[1],raw); raw=raw[n:]"
            with self.subTest(case=name), pipes(body) as wires:
                started = time.monotonic()
                with self.assertRaises((c.Refusal, ValueError)):
                    list(c.Wire.receive_many(wires))
                self.assertLess(time.monotonic()-started, .6)


if __name__ == '__main__':
    unittest.main()
