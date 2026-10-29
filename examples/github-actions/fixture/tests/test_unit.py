"""Ordinary checks deliberately do not replace the separate cash invariant."""

from decimal import Decimal
import unittest

from src.cash import closing_cash


class CashTests(unittest.TestCase):
    def test_no_activity(self):
        self.assertEqual(closing_cash(Decimal("100"), Decimal("0"), Decimal("0")), Decimal("100"))
