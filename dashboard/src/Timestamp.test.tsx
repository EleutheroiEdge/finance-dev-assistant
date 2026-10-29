import { afterEach, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { Timestamp } from "./Timestamp";

afterEach(cleanup);

it.each([
  ["2026-10-29T00:14:21.916226+00:00", "2026-10-29 00:14 UTC"],
  ["2026-10-28T20:14:21.916226-04:00", "2026-10-29 00:14 UTC"],
  ["2026-10-29T05:44:59.999999+05:30", "2026-10-29 00:14 UTC"],
  ["2027-01-01T00:00:00Z", "2027-01-01 00:00 UTC"],
])("formats %s in UTC without rounding up or losing the exact tooltip", (value, expected) => {
  render(<Timestamp value={value} />);
  const time = screen.getByText(expected);
  expect(time).toHaveAttribute("title", value);
  expect(time).toHaveAttribute("datetime", value);
});

it("shows missing or malformed times as unknown instead of crashing", () => {
  render(<><Timestamp value="invalid" /><Timestamp value="" /></>);
  expect(screen.getAllByText("Unknown time")).toHaveLength(2);
  expect(screen.getByTitle("invalid")).not.toHaveAttribute("datetime");
});
