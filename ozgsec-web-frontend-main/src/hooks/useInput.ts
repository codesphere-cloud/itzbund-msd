import { useCallback, useState } from "react";

export default function useInput(initialValue?: string) {
  const [value, setValue] = useState(initialValue || "");

  const onChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement> | string) => {
      if (typeof e === "string") {
        setValue(e);
        return;
      }
      setValue(e.target.value);
    },
    [],
  );

  return { value, onChange };
}
