import { useState } from "react";

export default function useRequest() {
  const [loading, setLoading] = useState<{
    isLoading: boolean;
    isError: boolean;
    isSuccess: boolean;
    error: unknown | null;
  }>({
    isLoading: false,
    isError: false,
    error: null,
    isSuccess: false,
  });

  return {
    run: async (request: Promise<any>) => {
      setLoading({
        isLoading: true,
        isError: false,
        error: null,
        isSuccess: false,
      });
      try {
        const response = await request;
        if (response instanceof Response && !response.ok) {
          throw response;
        }
        setLoading({
          isLoading: false,
          isError: false,
          error: null,
          isSuccess: true,
        });
        return response;
      } catch (error) {
        setLoading({
          isLoading: false,
          isError: true,
          error,
          isSuccess: false,
        });
        throw error;
      }
    },
    isLoading: loading.isLoading,
    isError: loading.isError,
    error: loading.error,
    isSuccess: loading.isSuccess,
  };
}
