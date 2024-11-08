import React, { forwardRef } from "react";
import { classNames } from "../../utils/common";
import Button from "./Button";

interface Props {
  loading?: boolean;
  disabled?: boolean;
  active?: boolean;
  RightIcon?: React.ReactNode;
  LeftIcon?: React.ReactNode;
}
// eslint-disable-next-line react/display-name
const OutlineButton = forwardRef<
  HTMLButtonElement,
  Props &
    React.DetailedHTMLProps<
      React.ButtonHTMLAttributes<HTMLButtonElement>,
      HTMLButtonElement
    >
>((props, ref) => {
  const { active, disabled, ...rest } = props;
  return (
    <Button
      className={classNames(
        "transition-all flex flex-row items-center gap-3 rounded-sm text-textblack border border-hellgrau-80 p-2 px-3 focus:bg-deepblue-50 hover:bg-dunkelblau-100 hover:text-white bg-white",
        props.disabled &&
          "opacity-50 cursor-not-allowed hover:bg-dunkelblau-100",
        props.active && "bg-dunkelblau-100",

        props.className,
      )}
      {...rest}
      ref={ref}
    />
  );
});

export default OutlineButton;
