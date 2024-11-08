import { CheckboxItem, ItemIndicator } from "@radix-ui/react-dropdown-menu";
import React, { ComponentProps, FunctionComponent } from "react";
import { classNames } from "../../utils/common";

const DropdownMenuCheckboxItem: FunctionComponent<
  ComponentProps<typeof CheckboxItem> & { Icon: React.ReactNode }
> = (props) => {
  const { Icon, ...rest } = props;
  return (
    <CheckboxItem
      className={classNames(
        "px-5 pl-10 text-sm py-1 cursor-pointer mx-1 my-1 rounded-sm focus:bg-dunkelblau-100 focus:text-white text-textblack relative focus:outline-none",
        props.checked && "bg-dunkelblau-100 text-white",
      )}
      {...rest}
    >
      <ItemIndicator className="absolute opacity-75 left-2">
        {Icon}
      </ItemIndicator>
      {props.children}
    </CheckboxItem>
  );
};

export default DropdownMenuCheckboxItem;
