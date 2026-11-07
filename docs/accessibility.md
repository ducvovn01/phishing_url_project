# Accessibility and responsive layout

Evidence for the A3 rubric item "design, responsive layout and accessibility". The frontend is in
`frontend/`. Everything under "Automated checks" runs with `npm test`. The section "Recorded by
hand" holds what was measured in a real browser on 3 November 2026.

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
| h. Layout at 360, 768 and 1280px, long URLs, zoom | Grid cells have `min-width: 0`, URLs use `overflow-wrap: anywhere`, every table sits in a horizontal scroll region, the header wraps. Tests check these with a 2048 character URL whose host has 1000 letters. | Pass in tests. Checked in a real browser at 360, 768 and 1280px: no horizontal scroll. Two failures remain, at 200% zoom on a 360px screen and at a 200% root font size at 360px: see "Recorded by hand", Layout. Not fixed. |
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

## Recorded by hand

These need a real browser. Recorded on 3 November 2026.

### Lighthouse

Run with Lighthouse 12.8.2 (command line) against the production build in `frontend/dist`, served on localhost with `serve -s`. It ran in headless Chromium 141 in a cloud container, not in a desktop browser, and no backend was running. The `/session` rows are the empty session page (no checks, so no charts); the charts were checked in the layout and keyboard sections below.

| Page | Device | Accessibility | Best practices | Performance | Date | Browser and version |
| --- | --- | --- | --- | --- | --- | --- |
| / | Desktop | 100 | 100 | 100 | 2026-11-03 | HeadlessChrome 141 (Lighthouse 12.8.2) |
| / | Mobile | 100 | 100 | 94 | 2026-11-03 | HeadlessChrome 141 (Lighthouse 12.8.2) |
| /session | Desktop | 100 | 100 | 100 | 2026-11-03 | HeadlessChrome 141 (Lighthouse 12.8.2) |
| /session | Mobile | 100 | 100 | 96 | 2026-11-03 | HeadlessChrome 141 (Lighthouse 12.8.2) |

### Layout

Checked in Microsoft Edge 156 (Chromium) on Windows against the dev server. The browser would not shrink its window, so each width was tested in a same-origin iframe of that width, and "No horizontal page scroll" means `scrollWidth` was not larger than `clientWidth` on the page. Browser zoom of 200% was emulated by halving the viewport (360px becomes 180px, 768px becomes 384px, 1280px becomes 640px). Root font size 200% was set on the `html` element. "Home with a result" used https://www.wikipedia.org, the session page held two checks with both charts drawn.

| Check | 360px | 768px | 1280px | Notes |
| --- | --- | --- | --- | --- |
| No horizontal page scroll, home with a result | Pass | Pass | Pass | Also no scroll on home before a result. |
| No horizontal page scroll, 2048 character URL | Pass | Pass | Pass | |
| No horizontal page scroll, session with charts | Pass | Pass | Pass | |
| 200% browser zoom | Fail | Pass | Pass | Fails at the 180px emulated viewport on the result view (page 238px wide, viewport 165px) and with the 2048 character URL (228px). Home and session are fine. 180px is far below the 320px width WCAG 1.4.10 uses. |
| Root font size 200% | Fail | Pass | Pass | At 360px the verdict heading "Likely legitimate" is 27px wider than the viewport (372px against 345px), and the 2048 character URL view is 6px wider (351px against 345px). Home and session are fine. Not fixed. |

### Keyboard only walkthrough

Done with real key presses in Microsoft Edge 156 against the dev server.

| Step | Works (yes or no) | Notes |
| --- | --- | --- |
| Tab to the skip link and use it | Yes | First Tab stop in an automated Tab run on a fresh load, and Enter moves focus to the main content. |
| Type a URL, submit with Enter, focus lands on the verdict | Yes | Focus lands on the verdict heading, with a visible outline. |
| Submit an invalid URL, the error is announced and the field keeps focus | Yes | The field keeps focus, is marked `aria-invalid`, and the message is in the polite live region and the field's `aria-describedby`. Not heard with a screen reader. |
| Select and deselect a signal from the list with Enter and Space | Yes | Enter selects (`aria-pressed` true), Space deselects, Space selects again. The highlight in the URL follows. |
| Open and close each chart data table, scroll it with the arrow keys | Yes | All three toggles (result page, results donut, trust score bars) open and close with Enter, and each table is a labelled stop reached with Tab. The tables were short enough that nothing needed scrolling, so the arrow keys scrolled the page instead; scrolling inside a long table was not tested. |
| Go to This session, read the table, clear the session, focus lands on the heading | Yes | The checked links table is a labelled stop. After Clear session, focus lands on the "This session" heading. |
| Every focused element shows a visible outline | Yes | Checked on the home page and the controls above: links and buttons have a 1.6px solid outline, the text field shows a 1.6px blue border instead of an outline. |

### Screen reader

Checked by hand by a team member (Vinh) with a screen reader on the running app, who reported that it works with no problems. The reader used and the exact announcements were not recorded, so this is a pass/no-issues result without a per-check log. The keyboard and markup checks above are separate evidence and are not a substitute.
