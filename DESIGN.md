# xkeystore design rules

One visual language, defined once. If a rule here and a view disagree, fix the view.

## 1. Tokens, not hex
All color comes from the `@theme` block in `src/index.css`. Use semantic utilities
(`text-ink`, `bg-surface`, `border-line`, `bg-brand`), never `text-[#0F172A]`.

| Role | Tokens |
| --- | --- |
| Text | `ink` (headings) · `ink-2` (body) · `muted` · `faint` (helper text) · `subtle` (icons, disabled) |
| Surfaces | `chrome` (app frame) · `canvas` (page) · `surface` (cards) · `surface-2` / `surface-3` (wells, hover) |
| Borders | `line` (default) · `line-strong` (inputs, dashed drop targets) |
| Brand | `brand` (links, icons, focus) · `brand-deep` (primary buttons) · `brand-soft` (selected) · `brand-tint` (hover wash) |
| Status | `success` / `danger` and their `-tint` pairs. Status color is only for status. |
| Terminal | `term-bg`, `term-fg` — the only dark surface in the app |

## 2. One accent
`brand` is the only accent hue. Cards are not individually color-coded; icons are `text-brand`.

## 3. Shape scale
`rounded-control` (12px) for inputs/chips/rows · `rounded-card` (20px) for cards · `rounded-panel` (24px) for
page-level containers and dialogs · `rounded-full` for buttons and badges.

## 4. Type scale
Page title 28px bold · card title 15px semibold · body 12.5–13px · caption/badge 11px · code `font-mono`.
Section labels are 13px uppercase `faint`.

## 5. Components
Build pages from `src/components/ui.tsx` — `PageHeader`, `Card`, `Button` (primary / secondary / ghost),
`Badge`. Add a variant there rather than restyling one-off.

## 6. Page layout
Every page: `px-8 py-6` scroll container → `PageHeader` (title, one-line description, actions on the right) →
content in a 12-col-style grid with `gap-4`. One primary button per page header.

## 7. Interaction
- Interactive cards use `<Card interactive>`; inner buttons stop propagation.
- Every icon-only button has an `aria-label`.
- Focus ring is global (`:focus-visible`); never remove it.
- Destructive or overwriting actions confirm first.

## 8. Terminal
Anywhere a task has a command-line equivalent, show a `<TerminalHint command="…" />`. It never runs on its
own — it opens the terminal (`Ctrl+\``) with the command pre-filled for the user to review and press Enter.

## 9. File intake
Drop targets use `useFileDrop` + `DropZone`; parsing lives in `src/lib/importFile.ts`, not in views.
