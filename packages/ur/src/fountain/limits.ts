/** Hard limits for adversarial multi-part streams. */
export type DecoderLimits = {
  maxMessageLength: number;
  maxFragmentCount: number;
  maxFragmentDataLength: number;
  maxBufferParts: number;
  maxReceivedParts: number;
  maxUriLen: number;
};

/**
 * Production default; same integers as bcur 1.0.
 *
 * Hosts that need another budget pass `new Decoder({ limits })`.
 */
export const DEFAULT_LIMITS: DecoderLimits = {
  maxMessageLength: 1_048_576,
  maxFragmentCount: 2000,
  maxFragmentDataLength: 8192,
  maxBufferParts: 4000,
  maxReceivedParts: 8000,
  maxUriLen: 8192,
};

export function mergeLimits(partial?: Partial<DecoderLimits>): DecoderLimits {
  return { ...DEFAULT_LIMITS, ...partial };
}
