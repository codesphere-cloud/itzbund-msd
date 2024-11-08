import React, { forwardRef } from "react";
import { classNames } from "../../utils/common";
import Spinner from "./Spinner";

interface Props {
  loading?: boolean;
  disabled?: boolean;
  RightIcon?: React.ReactNode;
  LeftIcon?: React.ReactNode;
  additionalClasses?: string;
}

const Button =
  // eslint-disable-next-line react/display-name
  forwardRef<
    HTMLButtonElement,
    Props &
      React.DetailedHTMLProps<
        React.ButtonHTMLAttributes<HTMLButtonElement>,
        HTMLButtonElement
      >
  >((props, ref) => {
    const {
      loading,
      disabled,
      RightIcon,
      LeftIcon,
      additionalClasses,
      ...rest
    } = props;

    return (
      <button
        ref={ref}
        className={classNames(
          "transition-all rounded-sm flex justify-between flex-row items-center gap-3 p-2 px-5",
          "bg-white focus:bg-dunkelblau-50 hover:bg-dunkelblau-100 hover:text-white border border-hellgrau-80 hover:border-dunkelblau-100",
          props.disabled && "opacity-50 cursor-not-allowed",
          additionalClasses,
        )}
        {...rest}
        onClick={(e) => {
          if (props.disabled) {
            e.preventDefault();
            e.stopPropagation();
            return;
          }
          props.onClick?.(e);
        }}
      >
        {props.loading ? (
          <div className="-my-2 -mx-1">
            <Spinner size={35} />
          </div>
        ) : (
          props.LeftIcon && <div>{props.LeftIcon}</div>
        )}
        <div className={classNames(loading && "hidden sm:block")}>
          {props.children}
        </div>
        {props.RightIcon && <div>{props.RightIcon}</div>}
      </button>
    );
  });

export default Button;
