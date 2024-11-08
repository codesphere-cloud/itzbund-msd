import { useState } from "react";

export default function useLoading(isLoading = false, err = "") {
  const [loading, setLoading] = useState({
    isLoading,
    key: "",
    err,
    success: false,
  });

  return {
    loading: (key: string = "") =>
      setLoading({ isLoading: true, err: "", key, success: false }),
    success: () =>
      setLoading({ isLoading: false, err: "", key: "", success: true }),
    error: (err: string, key = "") =>
      setLoading({ isLoading: false, err, key, success: false }),
    isLoading: loading.isLoading,
    errorMessage: loading.err,
    errored: !!loading.err,
    key: loading.key,
    successed: loading.success,
    run: async <T>(fn: Promise<T>, key: string = ""): Promise<T | null> => {
      setLoading({ isLoading: true, err: "", key, success: false });
      try {
        const result = await fn;
        setLoading({ isLoading: false, err: "", key, success: true });
        return result;
      } catch (err: any) {
        setLoading({ isLoading: false, err: err.message, key, success: false });
        return null;
      }
    },
  };
}
