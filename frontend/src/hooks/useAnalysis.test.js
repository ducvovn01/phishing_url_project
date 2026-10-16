import { act, renderHook, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, test, vi } from 'vitest'
import { analyseUrl } from '../api/index.js'
import { ApiError } from '../api/errors.js'
import useAnalysis from './useAnalysis.js'

vi.mock('../api/index.js', () => ({ analyseUrl: vi.fn(), getHealth: vi.fn() }))

function deferred() {
  let resolve
  let reject
  const promise = new Promise((res, rej) => {
    resolve = res
    reject = rej
  })
  return { promise, resolve, reject }
}

const RESULT = { label: 'legitimate', analysed_url: 'example.com' }

beforeEach(() => {
  analyseUrl.mockReset()
})

describe('useAnalysis', () => {
  test('goes idle, loading, success and reports the result once', async () => {
    const pending = deferred()
    analyseUrl.mockReturnValue(pending.promise)
    const onSuccess = vi.fn()
    const { result } = renderHook(() => useAnalysis({ onSuccess }))
    expect(result.current.state).toEqual({ status: 'idle', result: null, error: null, submittedValue: null })

    act(() => {
      result.current.submit('example.com')
    })
    expect(result.current.state).toMatchObject({ status: 'loading', submittedValue: 'example.com' })
    expect(analyseUrl).toHaveBeenCalledWith('example.com')

    await act(async () => pending.resolve(RESULT))
    expect(result.current.state).toMatchObject({ status: 'success', result: RESULT, error: null })
    expect(onSuccess).toHaveBeenCalledTimes(1)
    expect(onSuccess).toHaveBeenCalledWith(RESULT)
  })

  test('the error path stores the ApiError', async () => {
    const error = new ApiError('service_busy', { retryAfterSeconds: 5 })
    analyseUrl.mockRejectedValue(error)
    const onSuccess = vi.fn()
    const { result } = renderHook(() => useAnalysis({ onSuccess }))
    await act(async () => result.current.submit('example.com'))
    expect(result.current.state).toMatchObject({ status: 'error', error, result: null, submittedValue: 'example.com' })
    expect(onSuccess).not.toHaveBeenCalled()
  })

  test('a slow stale response is ignored', async () => {
    const slow = deferred()
    const fast = deferred()
    analyseUrl.mockReturnValueOnce(slow.promise).mockReturnValueOnce(fast.promise)
    const onSuccess = vi.fn()
    const { result } = renderHook(() => useAnalysis({ onSuccess }))

    act(() => {
      result.current.submit('first.com')
      result.current.submit('second.com')
    })
    await act(async () => fast.resolve({ ...RESULT, analysed_url: 'second.com' }))
    await act(async () => slow.resolve({ ...RESULT, analysed_url: 'first.com' }))

    expect(result.current.state.result.analysed_url).toBe('second.com')
    expect(result.current.state.submittedValue).toBe('second.com')
    expect(onSuccess).toHaveBeenCalledTimes(1)
  })

  test('a stale error is ignored too', async () => {
    const slow = deferred()
    analyseUrl.mockReturnValueOnce(slow.promise).mockResolvedValueOnce(RESULT)
    const { result } = renderHook(() => useAnalysis())
    act(() => {
      result.current.submit('first.com')
    })
    await act(async () => result.current.submit('second.com'))
    await act(async () => slow.reject(new ApiError('internal_error')))
    expect(result.current.state.status).toBe('success')
  })

  test('reset returns to idle and drops the request in flight', async () => {
    const pending = deferred()
    analyseUrl.mockReturnValue(pending.promise)
    const { result } = renderHook(() => useAnalysis())
    act(() => {
      result.current.submit('example.com')
    })
    act(() => result.current.reset())
    await act(async () => pending.resolve(RESULT))
    await waitFor(() => expect(result.current.state.status).toBe('idle'))
  })
})
