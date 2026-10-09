/** Hard limits for adversarial multi-part streams (UR-ADR-015). */
export type DecoderLimits = {
  maxMessageLength: number;
  maxFragmentCount: number;
  maxFragmentLength: number;
  maxUriLength: number;
};

/**
 * Production default; same integers as bcur.
 *
 * Hosts that need another budget pass `new UrDecoder({ limits })`.
 */
export const DEFAULT_LIMITS: DecoderLimits = {
  maxMessageLength: 1_048_576,
  maxFragmentCount: 2000,
  maxFragmentLength: 8192,
  maxUriLength: 8192,
};

export function mergeLimits(partial?: Partial<DecoderLimits>): DecoderLimits {
  return { ...DEFAULT_LIMITS, ...partial };
}
