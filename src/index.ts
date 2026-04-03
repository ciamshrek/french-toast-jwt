export { frenchToast } from './sign.js';
export { verify } from './verify.js';
export { createDPoPProof, verifyDPoPProof } from './dpop.js';
export { discoverKeys, clearKeyCache } from './discovery.js';

export type {
  FrenchToastOptions,
  DPoPOptions,
  VerifyOptions,
  VerifyResult,
  ChainLink,
} from './types.js';

export {
  FrenchToastError,
  ExpiryExceededError,
  SubjectMismatchError,
  AudienceMismatchError,
  ChainVerificationError,
  DPoPVerificationError,
  KeyDiscoveryError,
} from './errors.js';

export { FT_TYPE, FT_PARENT_HEADER } from './types.js';
