import { createContext, useContext } from 'react'

export const SessionContext = createContext(null)

/** @returns {{ results: { id: number, checkedAt: Date, result: object }[], addResult: (result: object) => void, clear: () => void }} */
export function useSession() {
  const session = useContext(SessionContext)
  if (!session) throw new Error('useSession must be used inside SessionProvider')
  return session
}
