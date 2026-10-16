import { useCallback, useEffect, useReducer, useRef } from 'react'
import { analyseUrl } from '../api/index.js'
import { normaliseError } from '../api/errors.js'

const initialState = { status: 'idle', result: null, error: null, submittedValue: null }

function reducer(state, action) {
  switch (action.type) {
    case 'submit':
      return { status: 'loading', result: null, error: null, submittedValue: action.value }
    case 'success':
      return { ...state, status: 'success', result: action.result }
    case 'error':
      return { ...state, status: 'error', error: action.error }
    case 'reset':
      return initialState
    default:
      return state
  }
}

/** Runs one analysis at a time; only the latest request may change the state. */
export default function useAnalysis({ onSuccess } = {}) {
  const [state, dispatch] = useReducer(reducer, initialState)
  const latestRequest = useRef(0)
  const onSuccessRef = useRef(onSuccess)
  useEffect(() => {
    onSuccessRef.current = onSuccess
  })

  const submit = useCallback(async (value) => {
    const request = ++latestRequest.current
    dispatch({ type: 'submit', value })
    try {
      const result = await analyseUrl(value)
      if (request !== latestRequest.current) return
      dispatch({ type: 'success', result })
      onSuccessRef.current?.(result)
    } catch (err) {
      if (request !== latestRequest.current) return
      // Already an ApiError from the API layer; normalising again is a no-op that guards against leaks.
      dispatch({ type: 'error', error: normaliseError(err) })
    }
  }, [])

  const reset = useCallback(() => {
    latestRequest.current++ // drop any request still in flight
    dispatch({ type: 'reset' })
  }, [])

  return { state, submit, reset }
}
