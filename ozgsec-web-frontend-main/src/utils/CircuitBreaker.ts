import { getLogger } from "../services/logger";

const logger = getLogger(__filename);

export default class CircuitBreaker {
  private failures = 0;
  private requestActive: number = 0;
  private state: "open" | "half-open" | "closed" = "closed";
  constructor(
    private readonly maxFailures = 2,
    private readonly resetTimeout = 10_000,
  ) {}

  private handleSuccess() {
    this.requestActive--;
    // the function invocation was successful
    // change the state to open, we can continue doing requests
    this.state = "closed";
    this.failures = 0;
  }

  private handleError(err: unknown) {
    this.requestActive--;
    this.failures++;
    logger.warn(
      { failures: this.failures, maxFailures: this.maxFailures },
      `circuit breaker failure: ${err}`,
    );
    if (this.failures >= this.maxFailures && this.state !== "open") {
      logger.warn("circuit breaker is now open");
      this.state = "open";

      // set a timeout to put the circuit breaker back into the half-open state
      setTimeout(() => {
        this.state = "half-open";
      }, this.resetTimeout);
    }
  }

  /**
   * Decides based on the current state and the active request count,
   * if a new function should be invoked.
   * @returns true if the circuit breaker should do the request
   */
  private shouldDoRequest() {
    // returns true for only a single request if in half open state.
    if (this.state === "closed") {
      return true;
    }
    if (this.state === "half-open" && this.requestActive === 0) {
      logger.info("circuit breaker is half-open - retrying request");
      return true;
    }
    logger.warn("circuit breaker is open - not trying request");
    return false;
  }

  public async run<T>(fn: () => Promise<T>): Promise<T> {
    if (!this.shouldDoRequest()) {
      throw new Error("Circuit breaker is open");
    }

    this.requestActive++;
    try {
      const result = await fn();
      this.handleSuccess();
      return result;
    } catch (e) {
      this.handleError(e);
      throw e;
    }
  }
}
