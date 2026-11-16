"""Unit tests for the MYP helper module (myp.py). Run: python -m unittest -v"""
import unittest
import myp


class TestMYP(unittest.TestCase):
    def test_header_size(self):
        self.assertEqual(myp.HEADER.size, 9)

    def test_magic(self):
        self.assertEqual(myp.build(myp.PING, 1)[:2], b"MP")

    def test_round_trip(self):
        r = myp.parse(myp.build(myp.DATA, 7, "hello", myp.FLAG_ACK))
        self.assertEqual((r["type"], r["seq"], r["flags"], r["payload"]),
                         (myp.DATA, 7, myp.FLAG_ACK, b"hello"))

    def test_empty_payload(self):
        r = myp.parse(myp.build(myp.PING, 1))
        self.assertEqual((r["length"], r["payload"]), (0, b""))

    def test_length_field(self):
        self.assertEqual(myp.parse(myp.build(myp.DATA, 1, "abc"))["length"], 3)

    def test_bad_length(self):
        pkt = myp.build(myp.DATA, 1, "abc", length=99)
        self.assertEqual(myp.parse(pkt)["length"], 99)
        self.assertEqual(myp.parse(pkt)["payload"], b"abc")

    def test_flags(self):
        r = myp.parse(myp.build(myp.DATA, 1, "x", myp.FLAG_ACK | myp.FLAG_URGENT))
        self.assertEqual(r["flags"], 0x03)

    def test_seq_big_endian(self):
        self.assertEqual(myp.build(myp.PING, 0x0102)[5:7], b"\x01\x02")

    def test_names(self):
        self.assertEqual([myp.NAMES[i] for i in range(1, 7)],
                         ["LOGIN", "LOGIN_OK", "DATA", "PING", "PONG", "BYE"])

    def test_short_packet(self):
        with self.assertRaises(ValueError):
            myp.parse(b"MP\x01")

    def test_bad_magic(self):
        with self.assertRaises(ValueError):
            myp.parse(b"XX" + myp.build(myp.PING, 1)[2:])


if __name__ == "__main__":
    unittest.main()
