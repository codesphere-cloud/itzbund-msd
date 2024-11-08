import CircuitBreaker from "./CircuitBreaker";

jest.useFakeTimers();
describe("CircuitBreaker test suite", () => {
  it("should return the result if the function resolves", async () => {
    const circuitBreaker = new CircuitBreaker();
    const result = circuitBreaker.run(() => Promise.resolve("result"));
    await expect(result).resolves.toEqual("result");
  });
  it("should throw an error, if the circuit breaker is already in open state", async () => {
    const circuitBreaker = new CircuitBreaker(1, 100);
    try {
      await circuitBreaker.run(() => Promise.reject("error"));
      await circuitBreaker.run(() => Promise.reject("error"));
    } catch (e) {
      // circuit breaker should be in closed state now.
    }

    await expect(
      circuitBreaker.run(() => Promise.resolve("it should throw nevertheless")),
    ).rejects.toThrowError("Circuit breaker is open");
  });

  it("should retry the request after the reset timeout interval", async () => {
    const circuitBreaker = new CircuitBreaker(1, 100);
    try {
      await circuitBreaker.run(() => Promise.reject("error"));
      await circuitBreaker.run(() => Promise.reject("error"));
    } catch (e) {
      // circuit breaker should be in closed state now.
    }

    jest.runAllTimers();

    await expect(
      circuitBreaker.run(() => Promise.resolve("it should resolve")),
    ).resolves.toEqual("it should resolve");
  });
});
