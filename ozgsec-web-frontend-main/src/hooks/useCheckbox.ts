import { useCallback, useState } from "react";

export default function useCheckbox(initialValue?: boolean) {
  const [value, setValue] = useState(initialValue || false);

  const onChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement> | boolean | void) => {
      if (typeof e === "undefined") {
        setValue((prev) => !prev);
        return;
      }
      if (typeof e === "boolean") {
        setValue(e);
        return;
      }
      setValue(e.target.checked);
    },
    [],
  );

  return { value, onChange, checked: value };
}
