import { Inject, Injectable, Logger } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';
import {
  JwtModuleOptions,
  JwtSecretRequestType,
  JwtVerifyOptions,
  JwtSignOptions
} from './interfaces';
import { RedisClient } from 'redis';
import { JWT_MODULE_OPTIONS } from './jwt.constants';
import { RedisService } from './redis.service';
import { generateId } from './utils';
import type { VerifyErrors } from 'jsonwebtoken';
import TokenInvalidError from './error/TokenInvalidError';
import TokenDestroyedError from './error/TokenDestroyedError';

@Injectable()
export class JwtService {
  private readonly logger = new Logger('JwtService');

  constructor(
    @Inject(JWT_MODULE_OPTIONS) private readonly options: JwtModuleOptions,
    private readonly redis: RedisService,
    private readonly client: RedisClient
  ) {
    this.redis = new RedisService(client);
  }

  sign<T extends string[] & { jti?: string }>(
    payload: T,
    options?: JwtSignOptions
  ): string {
    const signOptions = this.mergeJwtOptions(
      { ...options },
      'signOptions'
    ) as jwt.SignOptions;
    const secret = this.getSecretKey(
      payload,
      options,
      'privateKey',
      JwtSecretRequestType.SIGN
    );

    const jti: string = payload.jti || generateId(15);
    const token: string = jwt.sign({ ...payload, jti }, secret, signOptions);
    const decoded: any = jwt.decode(token);
    const key = `${this.options.prefix}${jti}`;
    if (decoded.exp) {
      this.redis.setExpire(
        key,
        'true',
        'EX',
        Math.floor(decoded.exp - Date.now() / 1000)
      );
    } else {
      this.redis.set(key, 'true');
    }
    return token;
  }

  signAsync(
    payload: string | Buffer | string[],
    options?: JwtSignOptions
  ): Promise<string> {
    const signOptions = this.mergeJwtOptions(
      { ...options },
      'signOptions'
    ) as jwt.SignOptions;
    const secret = this.getSecretKey(
      payload,
      options,
      'privateKey',
      JwtSecretRequestType.SIGN
    );

    return new Promise((resolve, reject) =>
      jwt.sign(payload, secret, signOptions, (err, encoded) =>
        err ? reject(err) : resolve(encoded)
      )
    );
  }

  verify<T extends string[] & { jti?: string }>(
    token: string,
    options?: JwtVerifyOptions
  ): void {
    const verifyOptions = this.mergeJwtOptions({ ...options }, 'verifyOptions');
    const secret = this.getSecretKey(
      token,
      options,
      'publicKey',
      JwtSecretRequestType.VERIFY
    );

    return jwt.verify(
      token,
      secret,
      verifyOptions,
      (err: VerifyErrors, decoded: T) => {
        if (err) {
          throw new TokenInvalidError(err.message);
        }
        if (!decoded.jti) {
          throw new TokenInvalidError();
        }
        const { jti } = decoded;
        const key = this.options.prefix + jti;
        if (!this.redis.get(key)) {
          throw new TokenDestroyedError();
        }
        return decoded;
      }
    );
  }

  verifyAsync<T extends string[] & { jti?: string }>(
    token: string,
    options?: JwtVerifyOptions
  ): Promise<T> {
    const verifyOptions = this.mergeJwtOptions({ ...options }, 'verifyOptions');
    const secret = this.getSecretKey(
      token,
      options,
      'publicKey',
      JwtSecretRequestType.VERIFY
    );

    return new Promise((resolve, reject) =>
      jwt.verify(token, secret, verifyOptions, (err, decoded) =>
        err ? reject(err) : resolve(decoded as T)
      )
    ) as Promise<T>;
  }

  decode(
    token: string,
    options?: jwt.DecodeOptions
  ): null | { [key: string]: any } | string {
    return jwt.decode(token, options);
  }

  revoke(jti: string, id?: string | null): boolean {
    const key = this.options.prefix + jti;
    return this.redis.del(key);
  }

  destroy(jti: string, id?: string | null): boolean {
    const key = this.options.prefix + jti;
    return this.redis.del(key);
  }

  private mergeJwtOptions(
    options: JwtVerifyOptions | JwtSignOptions,
    key: 'verifyOptions' | 'signOptions'
  ): jwt.VerifyOptions | jwt.SignOptions {
    delete options.secret;
    return options
      ? {
          ...(this.options[key] || {}),
          ...options
        }
      : this.options[key];
  }

  private getSecretKey(
    token: string | string[] | Buffer,
    options: JwtVerifyOptions | JwtSignOptions,
    key: 'publicKey' | 'privateKey',
    secretRequestType: JwtSecretRequestType
  ): string | Buffer | jwt.Secret {
    let secret = this.options.secretOrKeyProvider
      ? this.options.secretOrKeyProvider(secretRequestType, token, options)
      : options?.secret || this.options.secret || this.options[key];

    if (this.options.secretOrPrivateKey) {
      this.logger.warn(
        `"secretOrPrivateKey" has been deprecated, please use the new explicit "secret" or use "secretOrKeyProvider" or "privateKey"/"publicKey" exclusively.`
      );
      secret = this.options.secretOrPrivateKey;
    }
    return secret;
  }
}
