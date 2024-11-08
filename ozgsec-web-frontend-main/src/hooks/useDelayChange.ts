import { useEffect, useState } from "react";

export default function useDelayChange<T>(
  inputStateVar: T,
  delay = 500,
  shouldDelayTransition: (oldValue: T, newValue: T) => boolean = () => true,
) {
  const [outputStateVar, setOutputStateVar] = useState(inputStateVar);

  useEffect(() => {
    if (!shouldDelayTransition(outputStateVar, inputStateVar)) {
      setOutputStateVar(inputStateVar);
      return;
    }
    const timer = setTimeout(() => {
      setOutputStateVar(inputStateVar);
    }, delay);
    return () => clearTimeout(timer);
  }, [inputStateVar, delay, shouldDelayTransition, outputStateVar]);

  return outputStateVar;
}
