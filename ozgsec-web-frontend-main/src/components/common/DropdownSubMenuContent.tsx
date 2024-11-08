import { Content, SubContent } from "@radix-ui/react-dropdown-menu";

import { ComponentProps, FunctionComponent } from "react";

const DropdownSubMenuContent: FunctionComponent<
  ComponentProps<typeof Content>
> = (props) => {
  return (
    <SubContent
      className="DropdownMenuContent overflow-hidden border-3 border-gray-200 bg-white py-1 z-50  text-white"
      {...props}
    ></SubContent>
  );
};

export default DropdownSubMenuContent;
