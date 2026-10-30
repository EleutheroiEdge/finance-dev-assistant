import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { Updates } from "./Updates";
import type { UpdateStatus } from "./api";

afterEach(cleanup);
const value: UpdateStatus = {status: "not checked", installed_version: "0.5.0", latest_version: null,
  checked_at: null, stale: false, install_method: "pipx", upgrade_command: "pipx upgrade finledgerpoli",
  editable_install: false, can_upgrade: true, update_check: "off", checks_disabled_by_environment: false};

it("shows an unchecked version honestly and offers no browser install action", () => {
  render(<Updates value={value} />);
  expect(screen.getByRole("heading", {name: "Package updates"})).toBeInTheDocument();
  expect(screen.getAllByText("Not checked")).toHaveLength(3);
  expect(screen.getByText("pipx upgrade finledgerpoli")).toBeInTheDocument();
  expect(screen.queryByRole("button")).toBeNull();
  expect(screen.queryByRole("link")).toBeNull();
});

it("renders a cached newer version, its age and an environment override", () => {
  render(<Updates value={{...value, status: "update-available", latest_version: "0.6.0", stale: true,
    checked_at: "2026-10-29T12:00:00Z", checks_disabled_by_environment: true}} />);
  expect(screen.getByText("Update available")).toBeInTheDocument();
  expect(screen.getByText("0.6.0")).toBeInTheDocument();
  expect(screen.getByText(/cached result may be out of date/)).toBeInTheDocument();
  expect(screen.getByText("Disabled by environment")).toBeInTheDocument();
});
