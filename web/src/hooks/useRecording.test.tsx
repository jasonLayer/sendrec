import { act, renderHook } from '@testing-library/react'
import { afterEach, expect, it, vi } from 'vitest'
import { useRecording } from './useRecording'

afterEach(() => {
  Object.defineProperty(window, 'parent', { value: window, configurable: true })
  sessionStorage.clear()
  window.history.replaceState({}, '', '/')
})

it('announces real recording only to the capture parent and clears on pause, stop, reset and unmount', () => {
  const postMessage = vi.fn()
  Object.defineProperty(window, 'parent', { value: { postMessage }, configurable: true })
  window.history.replaceState({}, '', '/?capture_parent=https%3A%2F%2Fapp.majorgtm.com')
  const { result, unmount } = renderHook(() => useRecording(780, vi.fn(), vi.fn()))
  for (const state of ['countdown', 'recording', 'paused', 'recording', 'stopped'] as const) {
    act(() => result.current.setState(state))
    expect(postMessage).toHaveBeenLastCalledWith({ type: 'sendrec:recording-state', active: state === 'recording' }, 'https://app.majorgtm.com')
  }
  act(() => result.current.setState('recording'))
  act(() => result.current.reset())
  expect(postMessage).toHaveBeenLastCalledWith({ type: 'sendrec:recording-state', active: false }, 'https://app.majorgtm.com')
  act(() => result.current.setState('recording'))
  unmount()
  expect(postMessage).toHaveBeenLastCalledWith({ type: 'sendrec:recording-state', active: false }, 'https://app.majorgtm.com')
})
