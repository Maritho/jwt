import { RedisClient } from 'redis';

export class RedisService {
  private readonly client: RedisClient;

  constructor(client: RedisClient) {
    this.client = client;
  }

  public set(key: string, value: string): boolean {
    return this.client.set(key, value, (err: Error) => {
      if (err) {
        return err;
      }
    });
  }

  public setExpire(
    key: string,
    value: string,
    mode: string,
    duration: number
  ): boolean {
    return this.client.set(key, value, mode, duration, (err: Error) => {
      if (err) {
        return err;
      }
    });
  }

  public del(key: string): boolean {
    return this.client.del(key, (err: Error) => {
      if (err) {
        return err;
      }
    });
  }

  public get(key: string): string | boolean {
    return this.client.get(key, (err: Error | null, reply: string) => {
      if (err) {
        return err;
      }
      return reply;
    });
  }
}
