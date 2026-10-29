"""Fictional arithmetic for the CI gate example; not a trading or tax model."""


def closing_cash(opening, deposits, fees):
    return opening + deposits - fees
