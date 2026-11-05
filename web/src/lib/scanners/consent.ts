export type ExternalScanBlockedReason =
  | 'feature_disabled'
  | 'not_link'
  | 'sensitive_url'
  | null

export type ExternalScanDecision = {
  requested: boolean
  send: boolean
  blockedReason: ExternalScanBlockedReason
}

export function canRunExternalScan(input: {
  mode: 'link' | 'message'
  featureEnabled: boolean
  sensitive: boolean
}): boolean {
  return (
    input.mode === 'link' &&
    input.featureEnabled &&
    !input.sensitive
  )
}

export function resolveExternalScanRequest(input: {
  mode: 'link' | 'message'
  featureEnabled: boolean
  sensitive: boolean
}): ExternalScanDecision {
  let blockedReason: ExternalScanBlockedReason = null
  if (!input.featureEnabled) blockedReason = 'feature_disabled'
  else if (input.mode !== 'link') blockedReason = 'not_link'
  else if (input.sensitive) blockedReason = 'sensitive_url'

  const requested = blockedReason === null

  return {
    requested,
    send: requested,
    blockedReason,
  }
}
