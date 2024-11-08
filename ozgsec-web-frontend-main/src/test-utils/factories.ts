export const buildResponseMock = () => {
  return {
    status: jest.fn().mockReturnThis(),
    json: jest.fn(),
  };
};
export const buildJSONResponse = (
  data: any,
  headers = {
    "Content-Type": "application/json",
  },
) => {
  return Promise.resolve(
    new Response(JSON.stringify(data), {
      headers,
    }),
  );
};

export const mockFetch = (response: Promise<Response>) => {
  const mock = jest.fn(() => response);
  global.fetch = mock;
  return [mock, response] as const;
};
