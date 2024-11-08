export default class MaxSizeSet<T> {
  private readonly maxSize: number;
  private readonly set: Set<T>;

  constructor(maxSize: number) {
    this.maxSize = maxSize;
    this.set = new Set();
  }

  public add(value: T): void {
    if (this.set.size >= this.maxSize) {
      const first = this.set.values().next().value;
      this.set.delete(first);
    }
    this.set.add(value);
  }

  public has(value: T): boolean {
    return this.set.has(value);
  }
}
