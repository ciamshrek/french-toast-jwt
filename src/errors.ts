export class FrenchToastError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FrenchToastError';
  }
}

export class ExpiryExceededError extends FrenchToastError {
  constructor() {
    super('Token expiry exceeds parent token expiry');
    this.name = 'ExpiryExceededError';
  }
}

export class SubjectMismatchError extends FrenchToastError {
  constructor() {
    super('Subject does not match parent token subject');
    this.name = 'SubjectMismatchError';
  }
}

export class AudienceMismatchError extends FrenchToastError {
  constructor() {
    super('Audience does not match parent token audience');
    this.name = 'AudienceMismatchError';
  }
}

export class ChainVerificationError extends FrenchToastError {
  constructor(message: string, public depth: number) {
    super(`Chain verification failed at depth ${depth}: ${message}`);
    this.name = 'ChainVerificationError';
  }
}

export class DPoPVerificationError extends FrenchToastError {
  constructor(message: string) {
    super(`DPoP verification failed: ${message}`);
    this.name = 'DPoPVerificationError';
  }
}

export class KeyDiscoveryError extends FrenchToastError {
  constructor(issuer: string, message: string) {
    super(`Key discovery failed for ${issuer}: ${message}`);
    this.name = 'KeyDiscoveryError';
  }
}
