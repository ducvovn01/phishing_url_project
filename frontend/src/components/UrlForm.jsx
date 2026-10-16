import { useRef, useState } from 'react'
import { Box, Button, CircularProgress, Stack, TextField, Typography } from '@mui/material'
import ContentPasteIcon from '@mui/icons-material/ContentPaste'
import { validateUrl } from '../validation/urlRules.js'

const HELPER_TEXT = 'Only the text of the link is checked. The page is never opened.'
const CLIPBOARD_FALLBACK = "Couldn't read your clipboard. Click the box and press Ctrl+V (Cmd+V on Mac)."

export default function UrlForm({ onSubmit, loading = false, serverError = null, onClear }) {
  const inputRef = useRef(null)
  const [value, setValue] = useState('')
  const [validationError, setValidationError] = useState(null)
  // After the first failed submit, validate on every change so the error clears once fixed.
  const [liveValidation, setLiveValidation] = useState(false)
  // The serverError object the user has edited past; a new serverError object shows again.
  const [dismissedServerError, setDismissedServerError] = useState(null)
  const [clipboardMessage, setClipboardMessage] = useState('')

  const shownServerError = serverError && serverError !== dismissedServerError ? serverError.message : null
  const errorMessage = validationError ?? shownServerError

  function updateValue(next) {
    setValue(next)
    setDismissedServerError(serverError)
    setClipboardMessage('')
    if (liveValidation) setValidationError(validateUrl(next).message)
  }

  function handleSubmit(event) {
    event.preventDefault()
    if (loading) return
    const result = validateUrl(value)
    if (!result.valid) {
      setValidationError(result.message)
      setLiveValidation(true)
      inputRef.current?.focus()
      return
    }
    setValidationError(null)
    onSubmit(result.value)
  }

  async function handlePaste() {
    try {
      const text = await navigator.clipboard.readText()
      updateValue(text)
      inputRef.current?.focus()
    } catch {
      // Covers no Clipboard API, permission denied and insecure contexts alike.
      setClipboardMessage(CLIPBOARD_FALLBACK)
    }
  }

  function handleClear() {
    setValue('')
    setValidationError(null)
    setLiveValidation(false)
    setDismissedServerError(serverError)
    setClipboardMessage('')
    inputRef.current?.focus()
    onClear?.()
  }

  return (
    <Box component="form" noValidate onSubmit={handleSubmit} aria-busy={loading}>
      <Stack spacing={2}>
        <TextField
          id="url-input"
          name="url"
          label="Paste a URL to check"
          value={value}
          onChange={(e) => updateValue(e.target.value)}
          inputRef={inputRef}
          autoComplete="off"
          fullWidth
          error={Boolean(errorMessage)}
          helperText={errorMessage ?? HELPER_TEXT}
          slotProps={{
            htmlInput: { spellCheck: false, inputMode: 'url', autoCapitalize: 'none', autoCorrect: 'off' },
          }}
        />
        <Stack direction="row" spacing={1} useFlexGap sx={{ flexWrap: 'wrap' }}>
          <Button
            type="submit"
            variant="contained"
            disabled={loading}
            startIcon={loading ? <CircularProgress size={16} color="inherit" aria-hidden="true" /> : null}
          >
            {loading ? 'Analysing...' : 'Analyse URL'}
          </Button>
          <Button variant="outlined" startIcon={<ContentPasteIcon />} onClick={handlePaste}>
            Paste from clipboard
          </Button>
          {value !== '' && (
            <Button variant="text" onClick={handleClear}>
              Clear
            </Button>
          )}
        </Stack>
        {/* <output> has the implicit status role, so screen readers announce the message. */}
        <Typography component="output" variant="body2" sx={{ display: 'block' }}>
          {clipboardMessage}
        </Typography>
      </Stack>
    </Box>
  )
}
