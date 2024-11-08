import { FunctionComponent } from "react";

interface Props {
  color?: string;
  size?: number;
}
const Spinner: FunctionComponent<Props> = ({ color, size }) => {
  return (
    <svg
      width={(size ?? 35) + 2}
      height={(size ?? 35) + 2}
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 100 100"
      preserveAspectRatio="xMidYMid"
    >
      <circle
        cx="50"
        cy="50"
        fill="none"
        stroke={color ?? "currentColor"}
        strokeWidth="10"
        r={size ?? 35}
        strokeDasharray="164.93361431346415 56.97787143782138"
      >
        <animateTransform
          attributeName="transform"
          type="rotate"
          repeatCount="indefinite"
          dur="1s"
          values="0 50 50;360 50 50"
          keyTimes="0;1"
        ></animateTransform>
      </circle>
    </svg>
  );
};

export default Spinner;
