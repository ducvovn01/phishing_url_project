import { useCallback, useMemo, useRef, useState } from 'react'
import { SessionContext } from './useSession.js'

/** Keeps this session's results in memory only (contract section 6.5): a refresh clears them. */
export function SessionProvider({ children }) {
  const [results, setResults] = useState([])
  const nextId = useRef(1)

  const addResult = useCallback((result) => {
    const entry = { id: nextId.current++, checkedAt: new Date(), result }
    setResults((current) => [...current, entry])
  }, [])

  const clear = useCallback(() => setResults([]), [])

  const value = useMemo(() => ({ results, addResult, clear }), [results, addResult, clear])
  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
}
