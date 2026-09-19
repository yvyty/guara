# Tray manual QA checklist

Run this per desktop before claiming the row in `docs/tray.md` is verified.
Tray chrome, hotkeys, and login items are OS behaviour, so an automated test
cannot replace it. Record the OS version, the commit, and any screenshot in the
PR that flips a row.

Decision for v0.1: Linux and Windows tray verification is deferred rather than
claimed. Those rows in `docs/tray.md` stay "needs QA", and this checklist is what
closes them later. macOS is launch-tested only (the process starts and stays up);
its interactive rows are also unchecked, so nothing here should be read as a
passed test yet.

## Shared setup

```sh
cargo build -p guara-tray
mkdir -p /tmp/guara-qa && printf 'a needle in a haystack\n' > /tmp/guara-qa/note.txt
printf 'stub\n' > /tmp/guara-qa/invoice.pdf.exe
./target/debug/guara-tray /tmp/guara-qa
```

## Checklist

| # | Step | Expected |
| - | ---- | -------- |
| 1 | Launch the app | Tray icon appears; no window flashes on start |
| 2 | Hover the icon | Tooltip reads `Guará: Idle | N path(s) indexed across 1 root(s)` |
| 3 | Press the hotkey (macOS `Cmd+Shift+G`, Linux/Windows `Ctrl+Shift+G`) | Palette window opens focused |
| 4 | Type `needle`, press Enter | `note.txt` listed, footer shows hit count and elapsed ms |
| 5 | Select the hit and press `o` | `$EDITOR` opens the file; with `EDITOR` unset, the OS opener runs |
| 6 | Press `s` on `invoice.pdf.exe` | Scan reports `suspicious`; the tray icon turns red (threat state) |
| 7 | Close the palette (`Esc` or hotkey) | Window hides; tray icon stays; no orphan window in the task switcher |
| 8 | Click a recent query | Search re-runs with that query |
| 9 | Click "Pin current root", quit the app, relaunch | The pinned scope is still listed (read from `<config_dir>/tray.json`) |
| 10 | Toggle "Start at login" on | A login item is registered: LaunchAgent (macOS), `.desktop` in `~/.config/autostart` (Linux), registry Run key (Windows) |
| 11 | Relaunch the shell and check the menu | The item is checked, because the preference persisted |
| 12 | Toggle "Start at login" off, re-check the OS login items | The entry is gone |
| 13 | Right-click the tray icon → Quit | Process exits; the icon disappears |
| 14 | Reply to nothing with the app left running for an hour (idle check) | No busy loop: CPU stays near zero with no palette activity |

## Known limitations to confirm, not to fix here

- Windows and Linux tray rendering, autostart, and hotkeys are unverified.
- The palette does not yet use the daemon socket; it links the shared library.
- Screenshots for each OS live in the release PR, not in the repository.