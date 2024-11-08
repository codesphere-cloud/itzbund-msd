export interface HorizontalScalingAdapter {
  subscribe(
    exchange: string,
    listener: (msg: Record<string, any>) => Promise<void> | void,
  ): void;
  publish(exchange: string, message: Record<string, any>, options?: any): void;
}
