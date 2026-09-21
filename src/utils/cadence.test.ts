import { describe, it, expect } from 'vitest'
import dayjs from 'dayjs'
import type { TFunction } from 'i18next'
import { isPastCadence, formatNextDue } from './cadence'

// Returns the key itself (with interpolation options appended) so assertions
// can check which branch fired without a real i18next instance.
const fakeT = ((key: string, opts?: Record<string, unknown>) =>
  opts ? `${key}:${JSON.stringify(opts)}` : key) as TFunction

// The single overdue definition shared by the overdue toast, the toast
// reconciler, and the dayGLANCE auto-schedule. The null/undefined cases encode
// real states: no cadence configured, and never-completed (elapsed null) —
// neither may ever count as overdue, or a fresh chore would toast on creation.
describe('isPastCadence', () => {
  it('is false without a cadence', () => {
    expect(isPastCadence(null, 10)).toBe(false)
    expect(isPastCadence(undefined, 10)).toBe(false)
    expect(isPastCadence(0, 10)).toBe(false)
  })

  it('is false for a never-completed chore (elapsed null)', () => {
    expect(isPastCadence(7, null)).toBe(false)
    expect(isPastCadence(7, undefined)).toBe(false)
  })

  it('is false while within cadence', () => {
    expect(isPastCadence(7, 0)).toBe(false)
    expect(isPastCadence(7, 6.9)).toBe(false)
  })

  it('is true at and past the cadence boundary', () => {
    expect(isPastCadence(7, 7)).toBe(true)
    expect(isPastCadence(7, 30)).toBe(true)
    expect(isPastCadence(1, 1)).toBe(true)
  })
})

describe('formatNextDue', () => {
  it('is null-safe', () => {
    expect(formatNextDue(fakeT, null, 5, dayjs().toISOString())).toBe('')
    expect(formatNextDue(fakeT, 7, null, dayjs().toISOString())).toBe('')
    expect(formatNextDue(fakeT, 7, 5, null)).toBe('')
  })

  it('agrees with isPastCadence at the boundary instead of using its own < 0 check', () => {
    const lastCompletedAt = dayjs().subtract(7, 'day').toISOString()
    expect(formatNextDue(fakeT, 7, 7, lastCompletedAt)).toBe('nextDue.dueNow')
  })

  it('derives today/tomorrow from calendar days, not the fractional elapsed remainder', () => {
    const tomorrow = dayjs().subtract(6, 'day').toISOString()
    expect(formatNextDue(fakeT, 7, 6.9, tomorrow)).toBe('nextDue.tomorrow')

    const today = dayjs().subtract(7, 'day').toISOString()
    expect(formatNextDue(fakeT, 7, 6.9, today)).toBe('nextDue.today')
  })

  it('reports whole day counts further out', () => {
    const lastCompletedAt = dayjs().subtract(2, 'day').toISOString()
    expect(formatNextDue(fakeT, 7, 2, lastCompletedAt)).toBe('nextDue.inDays:{"count":5}')
  })
})
