"use client";

import { Content } from "@radix-ui/react-dropdown-menu";

import { forwardRef } from "react";

// eslint-disable-next-line react/display-name
const DropdownMenuContent = forwardRef<any, any>((props, ref) => {
  return (
    <Content
      ref={ref}
      sideOffset={5}
      className="DropdownMenuContent text-sm border-3 border-hellgrau-40 overflow-hidden bg-white py-1 z-50 text-white"
      {...props}
    ></Content>
  );
});

export default DropdownMenuContent;
