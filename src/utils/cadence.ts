import dayjs from 'dayjs'
import type { TFunction } from 'i18next'
import relativeTime from 'dayjs/plugin/relativeTime'

dayjs.extend(relativeTime)

/**
 * Returns elapsed / target, unclamped. Values < 1 = within cadence, >= 1 = overdue.
 * Bar width clamps this to 100% in the UI; color uses the unclamped value.
 */
export function getFillRatio(elapsedDays: number, targetDays: number): number {
  return elapsedDays / targetDays
}

/**
 * Fraction of the cadence elapsed at which a chore is considered to "need
 * attention" — i.e. it has aged into the amber zone, a little before it's
 * actually due. Used by the "Soon" filter.
 */
export const ATTENTION_RATIO = 0.75

/**
 * True when a chore has a cadence and has aged into the amber/red zone
 * (ratio >= ATTENTION_RATIO). Chores without a cadence, or never completed,
 * have no colour and never qualify.
 */
export function needsAttention(targetCadenceDays: number | null, elapsedDays: number | null): boolean {
  if (targetCadenceDays === null || elapsedDays === null) return false
  return getFillRatio(elapsedDays, targetCadenceDays) >= ATTENTION_RATIO
}

/**
 * True when a chore has aged past its full cadence — the strict "overdue"
 * threshold (ratio >= 1), as opposed to needsAttention's earlier amber zone.
 * Chores without a cadence, or never completed (elapsed null), never qualify.
 *
 * This is the single overdue definition shared by the overdue toast, the
 * toast reconciler that dismisses it once a completion lands, and the
 * dayGLANCE auto-schedule — so they can never drift apart.
 */
export function isPastCadence(
  targetCadenceDays: number | null | undefined,
  elapsedDays: number | null | undefined,
): boolean {
  if (!targetCadenceDays || elapsedDays == null) return false
  return elapsedDays >= targetCadenceDays
}

/**
 * Within cadence (ratio 0→1): green → amber.
 * Overdue (ratio 1→2+): amber → red. Full red at 2× overdue.
 *
 * This means red = actually overdue, not merely approaching the deadline.
 */
export function getCadenceColor(ratio: number): string {
  if (ratio < 1) {
    return interpolateHex('#22c55e', '#f59e0b', ratio)
  } else {
    const t = Math.min(ratio - 1, 1)
    return interpolateHex('#f59e0b', '#ef4444', t)
  }
}

function interpolateHex(a: string, b: string, t: number): string {
  const ra = parseInt(a.slice(1, 3), 16)
  const ga = parseInt(a.slice(3, 5), 16)
  const ba = parseInt(a.slice(5, 7), 16)
  const rb = parseInt(b.slice(1, 3), 16)
  const gb = parseInt(b.slice(3, 5), 16)
  const bb = parseInt(b.slice(5, 7), 16)
  const r = Math.round(ra + (rb - ra) * t)
  const g = Math.round(ga + (gb - ga) * t)
  const bv = Math.round(ba + (bb - ba) * t)
  return `#${r.toString(16).padStart(2, '0')}${g.toString(16).padStart(2, '0')}${bv.toString(16).padStart(2, '0')}`
}

export function formatElapsed(t: TFunction, elapsedDays: number | null, lastCompletedAt: string | null): string {
  if (elapsedDays === null || lastCompletedAt === null) return t('elapsed.never')
  const diffMinutes = dayjs().diff(dayjs(lastCompletedAt), 'minute')
  if (diffMinutes < 1) return t('elapsed.justNow')
  if (diffMinutes < 60) return t('elapsed.minutesAgo', { count: diffMinutes })
  if (elapsedDays < 1) {
    const diffHours = Math.floor(diffMinutes / 60)
    return t('elapsed.hoursAgo', { count: diffHours })
  }
  const calendarDaysAgo = dayjs().startOf('day').diff(dayjs(lastCompletedAt).startOf('day'), 'day')
  if (calendarDaysAgo === 1) return t('elapsed.yesterday')
  return t('elapsed.daysAgo', { count: calendarDaysAgo })
}

export function formatNextDue(
  t: TFunction,
  targetCadenceDays: number | null,
  elapsedDays: number | null,
  lastCompletedAt: string | null,
): string {
  if (elapsedDays === null || targetCadenceDays === null || lastCompletedAt === null) return ''
  if (isPastCadence(targetCadenceDays, elapsedDays)) return t('nextDue.dueNow')
  const dueDate = dayjs(lastCompletedAt).add(targetCadenceDays, 'day')
  const daysUntil = dueDate.startOf('day').diff(dayjs().startOf('day'), 'day')
  if (daysUntil === 0) return t('nextDue.today')
  if (daysUntil === 1) return t('nextDue.tomorrow')
  return t('nextDue.inDays', { count: daysUntil })
}
