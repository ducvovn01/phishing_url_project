# Accessibility and responsive layout

Evidence for the A3 rubric item "design, responsive layout and accessibility". The frontend is in
`frontend/`. Everything under "Automated checks" runs with `npm test`. The section "To record by
hand" lists what a person must still measure in a real browser.

Target: WCAG 2.2 level AA.

## Checklist

| Item | What was checked | Result |
| --- | --- | --- |
| a. Headings, landmarks, skip link | One h1 per page (home, session, 404, error fallback); h2 for every section below it, no skipped levels. Landmarks: `header`, `nav` (labelled "Main"), `main`, `footer`. The skip link is the first focusable element and moves to `main` (`tabIndex -1`). | Pass |
| b. Keyboard and focus | Tab order follows the DOM: skip link, nav, form, results, signal list, chart table toggles. Signal cards are native buttons (Enter and Space). Buttons get a 2px `#212121` outline; nav buttons a 2px white outline on the blue header; the analysis panel, tables and scroll regions a 2px outline. Links had only the browser default ring. | Fixed: links now get a 2px `currentColor` outline (`MuiLink` in `src/theme.js`). The chart data tables can scroll sideways but could not be focused, so a keyboard user could not scroll them; each is now a labelled region with `tabIndex 0`. |
| c. Touch targets | Signal cards are full width and over 44px tall. Medium buttons are 37px and small buttons ("Show full address", "Try again") 31px tall, so they met 24px but not 44px on phones. Inline text links are exempt (WCAG 2.5.8). | Fixed: every MUI `Button` has `minHeight: 44` below the `sm` breakpoint (600px). |
| d. Contrast | Every text, icon, chart mark and focus pair (table below). The disabled "Analysing..." button text was 1.84:1. | Fixed: `palette.action.disabled` is now `#555555` (5.64:1). Red and green are unchanged. |
| e. Form and announcements | Visible label "Paste a URL to check". MUI links the helper and error text with `aria-describedby` and sets `aria-invalid`. Loading is an `<output>` (status). Results move focus once, to the verdict heading; errors move focus once, to the alert title. A validation error after pressing Enter in the field was not announced, because focus did not move. | Fixed: the helper and error text is an `aria-live="polite"` region. Note: the error state is `role="alert"` and also receives focus, so some screen readers read it twice. Kept, because the focus move is what lets keyboard users continue from the error. |
| f. Reduced motion | The loading tips stop rotating under `prefers-reduced-motion: reduce`, and the charts skip animation (x-charts honours the setting). The spinners, button ripples and MUI transitions did not stop. | Fixed: `CssBaseline` sets animation and transition durations to 0.01ms under `prefers-reduced-motion: reduce`. |
| g. Colour is never the only signal | Verdicts have an icon and words; signal direction has a chip with words and an icon, and highlights use wavy (raises risk) or double (lowers risk) underlines; charts have axis captions, a legend with numbers, an `aria-label` summary and a data table; the trust meter has a dark marker; the session table has an icon and words. | Pass |
| h. Layout at 360, 768 and 1280px, long URLs, zoom | Grid cells have `min-width: 0`, URLs use `overflow-wrap: anywhere`, every table sits in a horizontal scroll region, the header wraps. Tests check these with a 2048 character URL whose host has 1000 letters. | Pass in tests. Not yet checked in a real browser at 360, 768 and 1280px, at 200% zoom or with a 200% root font size: see "To record by hand". |
| i. Language and metadata | `<html lang="en">`; titles "Check a URL", the verdict, "This session", "Page not found" and "Something went wrong", each followed by "Phishing URL Checker"; the viewport meta is `width=device-width, initial-scale=1.0` with no zoom limit. | Pass |

## Automated checks

All run with `npm test` (Vitest, jsdom).

| Check | File | Result |
| --- | --- | --- |
| axe-core (vitest-axe 0.1.0, axe-core 4.14.0) on home idle, loading, success (phishing and legitimate, with the weight chart loaded), error (busy and unreachable), session empty, session with three checks (both charts loaded), 404. The `color-contrast` rule is off because jsdom cannot compute colours; contrast is checked below. | `src/test/a11y.test.jsx` | 9 states, 0 violations |
| A 2048 character URL with a 1000 letter host wraps (`overflow-wrap: anywhere`) and every results grid cell has `min-width: 0` | `src/test/a11y.test.jsx` | Pass |
| The session table sits in a focusable scroll region with `overflow-x: auto`, and long links wrap | `src/test/a11y.test.jsx` | Pass |
| Each chart data table sits in a focusable, labelled scroll region | `WeightChart.test.jsx`, `VerdictDonut.test.jsx`, `TrustScoreBars.test.jsx` | Pass |
| Text, icon, chart and focus contrast pairs, plus the error alert as rendered | `src/theme.test.js` | Pass |
| Reduced motion CSS is in the global styles | `src/theme.test.js` | Pass |
| Field error is linked, `aria-invalid`, and a polite live region | `src/components/UrlForm.test.jsx` | Pass |
| Skip link, focus moves, `aria-pressed`, plain text URLs, no web storage | existing tests in `src/` | Pass |

## Contrast

Ratios are computed with MUI's `getContrastRatio`. Colours with transparency are first blended
onto their background. Limits: 4.5:1 for text, 3:1 for large text, icons, chart marks and focus
indicators.

| Pair | Ratio | Limit |
| --- | --- | --- |
| Disabled button text on disabled background (before: MUI default `rgba(0,0,0,0.26)`) | 1.84:1 | 4.5:1 |
| Disabled button text on disabled background (after: `#555555`) | 5.64:1 | 4.5:1 |
| Verdict and note text on phishing tint | 14.12:1 | 4.5:1 |
| Verdict and note text on legitimate tint | 14.35:1 | 4.5:1 |
| Secondary text on phishing tint | 6.51:1 | 4.5:1 |
| Secondary text on legitimate tint | 6.62:1 | 4.5:1 |
| Phishing icon, border, underline on phishing tint | 5.74:1 | 3:1 |
| Legitimate icon, border, underline on legitimate tint | 7.02:1 | 3:1 |
| Selected highlight outline and focus outline on phishing tint | 14.12:1 | 3:1 |
| Selected highlight outline and focus outline on legitimate tint | 14.35:1 | 3:1 |
| Signal card text on paper | 16.15:1 | 4.5:1 |
| Quoted signal text and loading tip on grey.100 | 14.82:1 | 4.5:1 |
| Focus outline on grey.100 | 14.82:1 | 3:1 |
| Helper text and footer on page | 7.45:1 | 4.5:1 |
| Error helper text on page | 4.98:1 | 4.5:1 |
| Focused field border on page | 5.74:1 | 3:1 |
| Header and nav text on app bar | 5.74:1 | 4.5:1 |
| Nav focus outline on app bar | 5.74:1 | 3:1 |
| Skip link on paper | 5.74:1 | 4.5:1 |
| Error alert text on alert background (as rendered) | 10.77:1 | 4.5:1 |
| Error alert icon on alert background | 4.39:1 | 3:1 |
| Focus outline on alert background | 14.25:1 | 3:1 |
| Phishing chart bar on page | 6.56:1 | 3:1 |
| Legitimate chart bar on page | 7.89:1 | 3:1 |
| Faded phishing chart bar on page | 3.50:1 | 3:1 |
| Faded legitimate chart bar on page | 3.39:1 | 3:1 |
| Chart axis, tick and bar labels on page | 16.15:1 | 4.5:1 |
| Trust score reference line on page | 7.45:1 | 3:1 |
| Focus outline on page | 16.15:1 | 3:1 |

## To record by hand

These need a real browser. Fill in the rows; do not copy numbers from elsewhere.

### Lighthouse

Run on a production build (`npm run build`, then `npm run preview`). Stop the dev server first: both use port 5173, and `npm run preview` will not start while the port is taken.

| Page | Device | Accessibility | Best practices | Performance | Date | Browser and version |
| --- | --- | --- | --- | --- | --- | --- |
| / | Desktop | | | | | |
| / | Mobile | | | | | |
| /session | Desktop | | | | | |
| /session | Mobile | | | | | |

### Layout

| Check | 360px | 768px | 1280px | Notes |
| --- | --- | --- | --- | --- |
| No horizontal page scroll, home with a result | | | | |
| No horizontal page scroll, 2048 character URL | | | | |
| No horizontal page scroll, session with charts | | | | |
| 200% browser zoom | | | | |
| Root font size 200% | | | | |

### Keyboard only walkthrough

| Step | Works (yes or no) | Notes |
| --- | --- | --- |
| Tab to the skip link and use it | | |
| Type a URL, submit with Enter, focus lands on the verdict | | |
| Submit an invalid URL, the error is announced and the field keeps focus | | |
| Select and deselect a signal from the list with Enter and Space | | |
| Open and close each chart data table, scroll it with the arrow keys | | |
| Go to This session, read the table, clear the session, focus lands on the heading | | |
| Every focused element shows a visible outline | | |

### Screen reader

| Screen reader and version | Browser and version | Flow checked | Problems found |
| --- | --- | --- | --- |
| | | | |
