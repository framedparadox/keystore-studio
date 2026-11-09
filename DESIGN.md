# Keystore Studio design rules

One visual language, defined once. If a rule here and a view disagree, fix the view.

## 1. Tokens, not hex
All color comes from the `@theme` block in `src/index.css`. Use semantic utilities
(`text-ink`, `bg-surface`, `border-line`, `bg-brand`), never `text-[#0F172A]`.

| Role | Tokens |
| --- | --- |
| Text | `ink` (headings) · `ink-2` (body) · `muted` · `faint` (helper text, the quietest text allowed) · `subtle` (decorative icons, disabled, placeholders: **never text**, it is 2.6:1 on white) |
| Surfaces | `chrome` (sidebar) · `canvas` (page) · `surface` (cards, tables) · `surface-2` / `surface-3` (table headers, wells, hover) |
| Borders | `line` (default) · `line-strong` (inputs, dashed drop targets) |
| Brand | `brand` (links, icons, focus) · `brand-deep` (primary buttons) · `brand-soft` (selected) · `brand-tint` (hover wash) |
| Status | `success` / `warning` / `danger` (text, and the background of anything with `on-accent` text or glyphs on it), their `-tint` (badge backgrounds) and `-fill` (meters, bars, dots: never behind text, white on them is under 4.5:1); `serious-fill` sits between warning and danger in charts. Status color is only for status and always ships with an icon or label. |
| On accent | `on-accent` — text and glyphs on a solid `brand` or status background (white in light, black in dark). Never `text-white`. |
| Scrim | `scrim` — dialog and palette backdrops, always with an opacity modifier |
| Terminal | `term-bg`, `term-fg`, `term-cmd`, `term-dim` — always dark, whatever the theme |

### Dark theme
Settings → General → Appearance: System, Light or Dark. Dark is pure black (`canvas` and `chrome`
#000, cards one step above), set as `data-theme="dark"` on `<html>` and defined in `src/index.css` by
overriding the same tokens. Each token keeps its role, so no component needs a `dark:` variant:
`ink` is still the strongest text, and the `-deep` brand tones get lighter because on black,
stronger contrast means lighter. Depth comes from borders; `shadow-card` is off.

### Contrast
Text meets WCAG AA (4.5:1; 3:1 from 18.66px bold) against its real background, and icon-only
controls meet 3:1. With the tokens above that means: `faint` or darker for any text, white only on
`brand`, `brand-deep` or a status text tone. Disabled controls are exempt.

## 2. One accent
`brand` is the only accent hue. Cards are not individually color-coded; icons are `text-brand`.

## 3. Shape and elevation
`rounded-control` (6px) for buttons, inputs, badges and rows · `rounded-card` (10px) for cards and tiles ·
`rounded-panel` (12px) for dialogs. `rounded-full` only for dots, meters and the score ring.
`shadow-card` on resting surfaces, `shadow-pop` on menus, dialogs, toasts and hovered tiles.

## 4. Type scale
Page title 22px semibold · card title 14px semibold · body 13px · table header 11.5px uppercase `faint` ·
caption/badge 11–12px · code `font-mono`. KPI values 28px semibold; one hero figure per page at most.
Number columns use `tabular-nums`; standalone big numbers do not.

Four more sizes are in use, each for one role only: dialog and error titles 16px semibold · StatStrip figures 18px
semibold · the score ring's figure 30px semibold (the page's hero figure) · the sidebar wordmark 15px semibold. Any other
size is a bug: use the scale above.

## 4a. Shape
Radii come from the theme only: `rounded-control` (6px) for buttons, inputs, badges, chips and rows; `rounded-card`
(10px) for cards and tiles; `rounded-panel` (12px) for dialogs. The small keycaps and the legend swatches use Tailwind's
`rounded-sm` (4px) and `rounded-xs` (2px). No other arbitrary radius.

## 5. Components
Build pages from `src/components/ui.tsx`:

- Layout: `Page`, `PageHeader`, `Card`, `CardHeader`, `SectionLabel`
- Actions: `Button` (primary / secondary / ghost / danger), `IconButton` (always labelled), `Menu` (dropdown rendered
  in a portal; flips upward near the bottom of the window, so table rows never clip it)
- Data: `DataTable` (sortable columns, sticky header, footer, empty state; `hideBelow` is measured on the table with a
  container query, not on the window, so a navigator or the sidebar never pushes the row actions out of view),
  `DescriptionList`, `KeyValueTable`, `Badge`, `EmptyState`, `CodeBlock` (with copy), `CopyButton`, `PathText` (a file
  path on one line: the folder truncates, the file name stays, full path in the tooltip, copy button)
- Figures: `KpiCard`, `StatStrip` (a row of small figures in one card; on Keystores and Certificates it is the
  summary under the table, named with `label`), `Meter`, `SegmentedBar`,
  `BarList`, `ColumnChart`, `ScoreRing`
- Inputs: `TextInput`, `TextArea`, `Select`, `Checkbox`, `PasswordInput` (show/hide), `SearchInput`, `Segmented`,
  `OptionList` (radio rows with a hint and a tag, for choosing an output format), `Field`; the `.field` / `.label`
  classes for anything custom
- Feedback: `Alert` (info / success / warning / danger; `onDismiss` adds a close button and the caller decides how long
  it stays closed: dashboard notices stay closed for the session, a locked-keystores notice per keystore), `Spinner`, `Kbd`
- Overlays: `Modal` (pass `busy` while an operation runs so it cannot be dismissed; dialogs stack, and only the top one
  answers Escape; focus is trapped inside and returns to the opener on close; the title labels the dialog),
  `useToast()` (app-wide, optional action such as *Undo* or *Show in folder*; toasts sit below dialogs, so a dialog
  that stays open after an action shows the outcome inline), `useConfirm()` (promise-based; supports a third
  "alternate" choice such as *Don't save*; with `danger: true` the focus starts on Cancel), `Menu` items move with the
  arrow keys, Home and End

Certificates render with `src/components/CertificateView.tsx` (`CertificateDetails`, `ChainView`, `ExtensionsList`,
`TrustBanner`, `WarningList`). Keystore entries use the atoms in `src/components/entry.tsx` (`EntryIcon`, `EntryNameCell`,
`EntryTypeIconCell`, `LockCell` / `LockIcon`, `AlgorithmCell`, `ExpiryCell`, `AgeCell`, `HealthBadge`, `HealthIcon`) so
every table reads the same.

The Keystores and Certificates tables share one column order: Type (icon) · Lock status (icon) · Alias or Certificate ·
Algorithm · Expires · Status (icon) · row actions. Icon-only headers use `IconHeader` (the label is the tooltip and the
screen-reader name); icon-only cells are `role="img"` with an `aria-label` and a matching `title`. Every status has its
own glyph (healthy, renew, expires soon, expired, weak; locked, unlocked, no key), so none relies on color alone. A
certificate has no private key, so its lock is a dash. The name column takes the room left and truncates (full text in
the tooltip), so the table never scrolls sideways. As the table narrows, columns give way in a fixed order: Algorithm
(below `lg`); then Type and Lock (below `md`), whose tile and lock badge move into the name cell
(`EntryNameCell icon="narrow"`); then Expires (below `sm`). Status and the row actions always stay. With the navigator
open at the smallest window the keystore table is about 430px wide.

Entry types are told apart by glyph and tile, never by status color: key pair = round key on a `brand-tint` tile,
certificate = badged document on a white tile (a shield for a CA on the Certificates page), secret key = square key on
a grey tile. Lock state is status: `warning` when locked, `success` when unlocked. Where there is no Lock column (the
navigator, pickers) a key pair wears it as a badge on `EntryIcon`. Use `EntryIcon` everywhere an entry is listed;
never draw a type icon by hand. Derived numbers
(days to expiry, key age, health, findings, buckets, summary) come from `src/lib/metrics.ts`, never computed inline.
Add a variant to a primitive rather than restyling one-off.

## 6. Page layout
App shell: 240px `Sidebar` (grouped nav: Overview · Inventory (Keystores, Certificates, Workspaces) · Tools · Security,
Settings in the footer; it collapses to a 64px icon rail from the button beside the logo, and while it is collapsed a
chevron-right at the start of the `Header` expands it again) +
`Header` (breadcrumb, undo/redo, command palette, vault lock, terminal, Open, New keystore). Under Tools, Convert
lists every conversion beneath it (collapsible) so each one is a click away. Every page:
`Page` → `PageHeader` → content on a 12-column grid with `gap-4`. Lists of records are tables, not card grids.
Every page has an empty state that offers the next useful action.

Keystores is a two-pane workspace instead: a navigator on the left (every open keystore as a tree of its entries,
grouped by type, filterable, with recent files below and a type legend at the foot) and the selected keystore on the
right (header, entry table, then the `StatStrip` summary). The navigator scrolls, so any number of keystores fits; it can be hidden.

## 7. Interaction
- Interactive cards use `<Card interactive>`; inner buttons stop propagation.
- Every icon-only button has an `aria-label`; important controls carry a `data-testid` for the E2E suite.
- Focus ring is global (`:focus-visible`); never remove it.
- Destructive or overwriting actions confirm first (`useConfirm({ danger: true })`) and offer undo where possible.
- Errors are shown where they happen (inline `Alert` in dialogs, `toast.error` otherwise). Never `alert()`, `confirm()`
  or `prompt()`: WKWebView returns at once without showing anything; use `Modal` and `useConfirm()`.
- A destructive choice is never the default: `useConfirm({ danger: true })` focuses Cancel, so Enter cannot delete,
  overwrite or quit by accident.
- A dialog that keeps its state while closed resets it in `useLayoutEffect` when it opens (or is keyed by what it
  edits). A passive `useEffect` runs after the dialog is on screen and can wipe what was typed into it first.
- Long operations show a `Spinner` and disable their trigger; dialogs pass `busy`.
- Table rows are clickable and keyboard-focusable; row actions sit in the last column (quick icons + `Menu`).
- Key pairs open locked (Settings can turn this off). Anything that uses a private key — inspect, export, copy, CSR,
  sign, renew, rotate — goes through `store.ensureKeyAccess(keystoreId, entryIds, then)`, which asks for the key
  password in the shared unlock dialog and runs `then` once the keys are usable. Renaming, labelling and deleting do
  not need the key. Never check `entry.locked` alone; use `store.isKeyLocked(entry)`.

## 8. Terminal
Anywhere a task has a command-line equivalent, show a `<TerminalHint command="…" />`. It never runs on its
own — it opens the terminal (`Ctrl+\``) with the command pre-filled for the user to review and press Enter.

## 9. Files and state
- File dialogs go through `src/lib/files.ts` (`pickFile`, `pickSavePath`); window-wide drops through
  `useWindowFileDrop`, and every path is routed by `store.openFiles()` (keystores → Keystores, certificate files and
  PKCS#7 certificate bundles → Certificates, keys, CSRs, CRLs and CMS signatures → Examine, archives → CA & Signing).
- Certificates opened on their own live in the store (`certificates`, `addCertificates`, `removeCertificates`), keyed
  `cert::<sha256>` (`src/lib/certificates.ts`) so the same certificate is listed once and a workspace can hold it next
  to keystore entries. They are public, so their PEM is persisted with the app state and they come back after a
  restart; removing one from the list never touches its file.
- All backend calls go through the typed `api` in `src/lib/api.ts`; show failures with `errorMessage(err)`.
- Keystore state lives in `src/state/store.tsx`. Mutate keystores only through store actions (`updateKeystore`,
  `addEntries`, `replaceEntry`, …) so undo/redo, dirty tracking and persistence stay correct.
