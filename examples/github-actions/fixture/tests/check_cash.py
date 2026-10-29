"""Mandatory invariant catches a deposit-sign defect missed by the unit example."""

from decimal import Decimal

from src.cash import closing_cash

opening, deposits, fees = map(Decimal, ("100", "20", "5"))
closing = closing_cash(opening, deposits, fees)
assert closing - opening == deposits - fees
