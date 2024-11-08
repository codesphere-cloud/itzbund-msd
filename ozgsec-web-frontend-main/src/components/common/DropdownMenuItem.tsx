"use client";

import { Item } from "@radix-ui/react-dropdown-menu";
import { ComponentProps, FunctionComponent, ReactNode } from "react";
import { classNames } from "../../utils/common";
import Spinner from "./Spinner";

const DropdownMenuItem: FunctionComponent<
  ComponentProps<typeof Item> & {
    Icon?: ReactNode;
    active?: boolean;
    loading?: boolean;
  }
> = (props) => {
  const { Icon, active, loading, ...rest } = props;
  return (
    <Item
      className={classNames(
        "lg:px-2 px-2 py-1 cursor-pointer transition-color flex flex-row gap-2 mx-1 my-1  focus:bg-blau-20 text-textblack  relative focus:outline-none",
        props.active && "bg-blau-100 focus:text-textblack text-white",
      )}
      {...rest}
    >
      {loading ? (
        <div className="left-0 top-0.5">
          <Spinner size={30} />
        </div>
      ) : (
        Icon && <div className="">{props.Icon}</div>
      )}
      {props.children}
    </Item>
  );
};

export default DropdownMenuItem;
