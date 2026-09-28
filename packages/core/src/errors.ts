/**
 * Error taxonomy (spec 04 § MossealError codes): mirrors the wasm taxonomy
 * EXACTLY (spec 02 table). Codes are stable and machine-readable; apps must
 * not string-match prose. Default user-presentable messages per code so apps
 * don't have to.
 */
export enum MossealErrorCode {
  MalformedEnvelope = "MALFORMED_ENVELOPE",
  UnsupportedVersion = "UNSUPPORTED_VERSION",
  UnsupportedKind = "UNSUPPORTED_KIND",
  PayloadTooLarge = "PAYLOAD_TOO_LARGE",
  DomainMismatch = "DOMAIN_MISMATCH",
  BadPassword = "BAD_PASSWORD",
  Expired = "EXPIRED",
  StrictTimeUnavailable = "STRICT_TIME_UNAVAILABLE",
  EpochRetired = "EPOCH_RETIRED",
  WasmInitFailed = "WASM_INIT_FAILED",
}

const DEFAULT_MESSAGES: Record<MossealErrorCode, string> = {
  [MossealErrorCode.MalformedEnvelope]:
    "This link is damaged or was not created by this app.",
  [MossealErrorCode.UnsupportedVersion]:
    "This link uses a newer format than this app supports. Update the app.",
  [MossealErrorCode.UnsupportedKind]:
    "This link contains a payload type this app doesn't handle.",
  [MossealErrorCode.PayloadTooLarge]:
    "This link's payload exceeds the size limit.",
  [MossealErrorCode.DomainMismatch]:
    "This link can only be opened on its intended site.",
  [MossealErrorCode.BadPassword]:
    "Wrong password. Please try again.",
  [MossealErrorCode.Expired]:
    "This link has expired.",
  [MossealErrorCode.StrictTimeUnavailable]:
    "Couldn't verify the current time (network unreachable), and this link " +
    "requires a trusted time check.",
  [MossealErrorCode.EpochRetired]:
    "This link was sealed with a revoked key and can no longer be opened.",
  [MossealErrorCode.WasmInitFailed]:
    "Failed to initialize the security module. Try reloading the page.",
};

export class MossealError extends Error {
  readonly code: MossealErrorCode;

  constructor(code: MossealErrorCode, detail?: string) {
    super(detail ? `${DEFAULT_MESSAGES[code]} (${detail})` : DEFAULT_MESSAGES[code]);
    this.name = "MossealError";
    this.code = code;
  }
}

/**
 * Map a wasm JsError message (a bare error-code string from the wasm layer)
 * to a typed MossealError. Unknown codes fall back to MALFORMED_ENVELOPE
 * rather than leaking prose (spec 02: codes are the contract).
 */
export function fromWasmError(err: unknown): MossealError {
  const msg = err instanceof Error ? err.message : String(err);
  const code = msg.trim() as MossealErrorCode;
  if (Object.values(MossealErrorCode).includes(code)) {
    return new MossealError(code);
  }
  // wasm panics or unexpected errors — never expose internals
  return new MossealError(
    MossealErrorCode.MalformedEnvelope,
    "unexpected internal error"
  );
}
