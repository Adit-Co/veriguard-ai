import { useCallback, useEffect, useRef, useState } from 'react'
import { isFirebaseConfigured } from '../firebase/config'
import { communityErrorMessage, getCommunityContext } from './communityService'
import type { CommunityContext } from './types'
import { normalizeCommunityUrl } from './url'

type CommunityContextState = {
  status: 'idle' | 'loading' | 'ready' | 'error'
  normalizedUrl: string | null
  context: CommunityContext | null
  error: string | null
}

const IDLE: CommunityContextState = {
  status: 'idle',
  normalizedUrl: null,
  context: null,
  error: null,
}

export function useCommunityContext(url: string | null, enabled = true) {
  const [state, setState] = useState<CommunityContextState>(IDLE)
  const requestId = useRef(0)
  const active = enabled && isFirebaseConfigured && Boolean(url)

  const load = useCallback(async (forceRefresh = false) => {
    if (!active || !url) {
      setState(IDLE)
      return
    }

    const current = ++requestId.current
    let normalizedUrl: string

    try {
      normalizedUrl = normalizeCommunityUrl(url)
    } catch (error) {
      if (current !== requestId.current) return
      setState({
        status: 'error',
        normalizedUrl: null,
        context: null,
        error: error instanceof Error ? error.message : 'URL tidak dapat dipetakan.',
      })
      return
    }

    setState({
      status: 'loading',
      normalizedUrl,
      context: null,
      error: null,
    })

    try {
      const context = await getCommunityContext(
        normalizedUrl,
        forceRefresh ? { forceRefresh: true } : {},
      )
      if (current !== requestId.current) return
      setState({ status: 'ready', normalizedUrl, context, error: null })
    } catch (error) {
      if (current !== requestId.current) return
      setState({
        status: 'error',
        normalizedUrl,
        context: null,
        error: communityErrorMessage(error),
      })
    }
  }, [active, url])

  useEffect(() => {
    if (!active || !url) {
      requestId.current += 1
      return
    }

    // oxlint-disable-next-line react/set-state-in-effect
    void load()
    return () => {
      requestId.current += 1
    }
  }, [active, load, url])

  const refresh = useCallback(() => load(true), [load])

  const effectiveState = !active ? IDLE : state
  return { ...effectiveState, refresh }
}
