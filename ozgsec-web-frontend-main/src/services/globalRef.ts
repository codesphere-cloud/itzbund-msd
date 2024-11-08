export class GlobalRef<T> {
  public readonly sym: symbol;

  constructor(uniqueName: string, valueFactory?: () => T) {
    this.sym = Symbol.for(uniqueName);
    if ((global as any)[this.sym]) {
      // just do nothing
    } else if (valueFactory) {
      (global as any)[this.sym] = valueFactory();
    }
  }

  get value(): T {
    return (global as any)[this.sym] as unknown as T;
  }

  set value(value: T) {
    (global as any)[this.sym] = value;
  }
}
