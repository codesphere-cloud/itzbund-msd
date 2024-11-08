import { config } from "../config";
import { wait } from "../utils/common";

const fetchWithTimeout = (
  timeoutMS: number,
  input: RequestInfo | URL,
  requestId: string,
  init?: RequestInit | undefined,
) => {
  return new Promise<Response>(async (resolve, reject) => {
    const controller = new AbortController();
    const timeout = setTimeout(() => {
      controller.abort();
      console.error(
        { requestId },
        `fetchWithTimeout: request to ${input} timed out after ${timeoutMS}ms`,
      );
    }, timeoutMS);
    // spread the provided parameters.
    // this will overwrite the signal if another one is provided.
    let response: Response;
    try {
      response = await fetch(input, {
        signal: controller.signal,
        redirect: "follow",
        ...init,
        headers: {
          "X-Request-ID": requestId,
          ...init?.headers,
        },
      });
      clearTimeout(timeout);
      resolve(response);
    } catch (e) {
      // clear the timeout even if there is an error.
      clearTimeout(timeout);
      reject(e);
    }
  });
};

export const httpClientFactory =
  (timeoutMS: number, maxRetries: number, timeoutBetweenRetriesMS = 500) =>
  (
    request: RequestInfo | URL,
    // needs always to be defined! This makes our logs more readable.
    requestId: string,
    init?: RequestInit | undefined,
  ): Promise<Response> => {
    // capture the tries variable inside the closure
    // this way we can avoid using it as a parameter of the api fn itself.
    let tries = 0;

    const retry = async (
      request: RequestInfo | URL,
      init?: RequestInit | undefined,
    ): Promise<Response> => {
      try {
        const response = await fetchWithTimeout(
          timeoutMS,
          request,
          requestId,
          init,
        );

        return response;
      } catch (error) {
        if (tries < maxRetries) {
          tries++;
          console.warn(
            { err: error },
            `api call: ${request} failed, retrying: ${tries}/${maxRetries}`,
          );
          await wait(timeoutBetweenRetriesMS);
          return retry(request, init);
        }
        throw error;
      }
    };
    return retry(request, init);
  };

export const clientHttpClient = httpClientFactory(
  config.clientTimeout,
  config.clientRetries,
);

export type HttpClient = ReturnType<typeof httpClientFactory>;
