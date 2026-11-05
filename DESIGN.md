# xkeystore design rules

One visual language, defined once. If a rule here and a view disagree, fix the view.

## 1. Tokens, not hex
All color comes from the `@theme` block in `src/index.css`. Use semantic utilities
(`text-ink`, `bg-surface`, `border-line`, `bg-brand`), never `text-[#0F172A]`.

| Role | Tokens |
| --- | --- |
| Text | `ink` (headings) · `ink-2` (body) · `muted` · `faint` (helper text) · `subtle` (icons, disabled) |
| Surfaces | `chrome` (sidebar) · `canvas` (page) · `surface` (cards, tables) · `surface-2` / `surface-3` (table headers, wells, hover) |
| Borders | `line` (default) · `line-strong` (inputs, dashed drop targets) |
| Brand | `brand` (links, icons, focus) · `brand-deep` (primary buttons) · `brand-soft` (selected) · `brand-tint` (hover wash) |
| Status | `success` / `warning` / `danger` (text), their `-tint` (badge backgrounds) and `-fill` (meters, bars); `serious-fill` sits between warning and danger in charts. Status color is only for status and always ships with an icon or label. |
| Terminal | `term-bg`, `term-fg` — the only dark surface in the app |

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

## 5. Components
Build pages from `src/components/ui.tsx`:

- Layout: `Page`, `PageHeader`, `Card`, `CardHeader`, `SectionLabel`
- Actions: `Button` (primary / secondary / ghost / danger), `IconButton` (always labelled), `Menu` (dropdown rendered
  in a portal; flips upward near the bottom of the window, so table rows never clip it)
- Data: `DataTable` (sortable columns, sticky header, footer, empty state), `DescriptionList`, `KeyValueTable`,
  `Badge`, `EmptyState`, `CodeBlock` (with copy), `CopyButton`
- Figures: `KpiCard`, `Meter`, `SegmentedBar`, `BarList`, `ColumnChart`, `ScoreRing`
- Inputs: `TextInput`, `TextArea`, `Select`, `Checkbox`, `PasswordInput` (show/hide), `SearchInput`, `Segmented`,
  `Field`; the `.field` / `.label` classes for anything custom
- Feedback: `Alert` (info / success / warning / danger), `Spinner`, `Kbd`
- Overlays: `Modal` (pass `busy` while an operation runs so it cannot be dismissed), `useToast()` (app-wide,
  optional action such as *Undo* or *Show in folder*), `useConfirm()` (promise-based; supports a third
  "alternate" choice such as *Don't save*)

Certificates render with `src/components/CertificateView.tsx` (`CertificateDetails`, `ChainView`, `ExtensionsList`,
`TrustBanner`, `WarningList`). Keystore entries use the atoms in `src/components/entry.tsx` (`EntryNameCell`,
`AlgorithmCell`, `ExpiryCell`, `AgeCell`, `HealthBadge`, `LabelList`) so every table reads the same. Derived numbers
(days to expiry, key age, health, findings, buckets, summary) come from `src/lib/metrics.ts`, never computed inline.
Add a variant to a primitive rather than restyling one-off.

## 6. Page layout
App shell: 240px `Sidebar` (grouped nav: Overview · Inventory · Tools · Security, Settings in the footer) +
`Header` (breadcrumb, undo/redo, command palette, vault lock, terminal, Open, New keystore). Every page:
`Page` → `PageHeader` → content on a 12-column grid with `gap-4`. Lists of records are tables, not card grids.
Every page has an empty state that offers the next useful action.

## 7. Interaction
- Interactive cards use `<Card interactive>`; inner buttons stop propagation.
- Every icon-only button has an `aria-label`; important controls carry a `data-testid` for the E2E suite.
- Focus ring is global (`:focus-visible`); never remove it.
- Destructive or overwriting actions confirm first (`useConfirm({ danger: true })`) and offer undo where possible.
- Errors are shown where they happen (inline `Alert` in dialogs, `toast.error` otherwise) — never `alert()`.
- Long operations show a `Spinner` and disable their trigger; dialogs pass `busy`.
- Table rows are clickable and keyboard-focusable; row actions sit in the last column (quick icons + `Menu`).

## 8. Terminal
Anywhere a task has a command-line equivalent, show a `<TerminalHint command="…" />`. It never runs on its
own — it opens the terminal (`Ctrl+\``) with the command pre-filled for the user to review and press Enter.

## 9. Files and state
- File dialogs go through `src/lib/files.ts` (`pickFile`, `pickSavePath`); window-wide drops through
  `useWindowFileDrop`, and every path is routed by `store.openFiles()` (keystores → Keystores, certificates and
  keys → Examine, archives → CA & Signing).
- All backend calls go through the typed `api` in `src/lib/api.ts`; show failures with `errorMessage(err)`.
- Keystore state lives in `src/state/store.tsx`. Mutate keystores only through store actions (`updateKeystore`,
  `addEntries`, `replaceEntry`, …) so undo/redo, dirty tracking and persistence stay correct.
