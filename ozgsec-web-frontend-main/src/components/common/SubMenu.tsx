import { faChevronRight } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import React, { FunctionComponent } from "react";
import DropdownSubMenuContent from "./DropdownSubMenuContent";
import DropdownMenuItem from "./DropdownMenuItem";
import { classNames } from "../../utils/common";

interface Props {
  Button: React.ReactNode;
  Menu: React.ReactNode;
}

const SubMenu: FunctionComponent<Props> = ({ Button, Menu }) => {
  return (
    <DropdownMenu.Sub>
      <DropdownMenu.SubTrigger className="hover:outline-none">
        <div
          className={classNames(
            "lg:px-2 px-2 py-1 cursor-pointer transition-color flex flex-row gap-2 mx-1 my-1 items-center justify-between hover:border-none hover:outline-none hover:bg-blau-20 focus:bg-blau-20 text-textblack  relative focus:outline-none",
          )}
        >
          {Button}
          <FontAwesomeIcon
            fontSize={15}
            className={"opacity-75"}
            icon={faChevronRight}
          />
        </div>
      </DropdownMenu.SubTrigger>
      <DropdownMenu.Portal>
        <DropdownSubMenuContent>{Menu}</DropdownSubMenuContent>
      </DropdownMenu.Portal>
    </DropdownMenu.Sub>
  );
};

export default SubMenu;
