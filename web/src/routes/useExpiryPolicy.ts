import { useEffect, useState } from 'react'
import { getPublicConfig } from '@/lib/api/config'
import { expiryPolicyOf, SAFE_EXPIRY_POLICY, type ExpiryPolicy } from './expiryPolicy'

/** The deployment's expiration policy: the safe value first, the server's once /api/config answers. */
export function useExpiryPolicy(): ExpiryPolicy {
  const [policy, setPolicy] = useState<ExpiryPolicy>(SAFE_EXPIRY_POLICY)
  useEffect(() => {
    let cancelled = false
    void getPublicConfig()
      .then((config) => {
        if (!cancelled) setPolicy(expiryPolicyOf(config))
      })
      .catch(() => {
        /* keep the safe policy: nothing permanent is offered if the config cannot be read */
      })
    return () => {
      cancelled = true
    }
  }, [])
  return policy
}
