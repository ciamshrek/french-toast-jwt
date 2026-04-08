import { frenchToast as delegate } from './sign.js';
import { verify } from './verify.js';
import { createDPoPProof, verifyDPoPProof } from './dpop.js';
import { discoverKeys, clearKeyCache } from './discovery.js';

export const frenchToast = {
  delegate,
  verify,
  createDPoPProof,
  verifyDPoPProof,
  discoverKeys,
  clearKeyCache,
};

export default frenchToast;

// Also export individually for destructured imports
export { delegate, verify, createDPoPProof, verifyDPoPProof, discoverKeys, clearKeyCache };

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

export { FT_TYPE, FT_PARENT_HEADER, FT_ISS_HEADER, FT_DEP_HEADER, CHAIN_DELIMITER, DEFAULT_MAX_DEPTH } from './types.js';
