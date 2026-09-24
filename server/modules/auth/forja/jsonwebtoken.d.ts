// Forja: minimal typings for the parts of `jsonwebtoken` used by ./forja
// (the package ships no declarations and @types/jsonwebtoken is not installed).
declare module 'jsonwebtoken' {
  import type { KeyObject } from 'node:crypto';

  namespace jwt {
    interface JwtPayload {
      [key: string]: unknown;
      iss?: string;
      sub?: string;
      aud?: string | string[];
      exp?: number;
      nbf?: number;
      iat?: number;
      email?: unknown;
    }
    interface VerifyOptions {
      algorithms?: string[];
      audience?: string | string[];
      issuer?: string;
      clockTimestamp?: number;
    }
    interface SignOptions {
      expiresIn?: number | string;
      algorithm?: string;
    }
    interface DecodeOptions {
      complete?: boolean;
    }
    interface Jwt {
      header: { kid?: string; alg?: string; [key: string]: unknown };
      payload: JwtPayload | string;
      signature: string;
    }
    class JsonWebTokenError extends Error {}
    class TokenExpiredError extends JsonWebTokenError {
      expiredAt: Date;
    }
    function sign(payload: object, secret: string | KeyObject, options?: SignOptions): string;
    function verify(token: string, secret: string | KeyObject, options?: VerifyOptions): JwtPayload | string;
    function decode(token: string, options?: DecodeOptions): Jwt | JwtPayload | string | null;
  }

  export = jwt;
}
