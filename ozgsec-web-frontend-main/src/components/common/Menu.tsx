"use client";

import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import React, { FunctionComponent, useEffect } from "react";
import DropdownMenuContent from "./DropdownMenuContent";

interface Props {
  Button: React.ReactNode;
  Menu: React.ReactNode;
  disabled?: boolean;
}

const Menu: FunctionComponent<Props> = ({ Button, Menu, disabled }) => {
  const buttonRef = React.useRef<HTMLButtonElement>(null);
  const [width, setWidth] = React.useState(0);
  useEffect(() => {
    if (buttonRef.current) {
      setWidth(buttonRef.current.clientWidth);
    }
  }, []);
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger ref={buttonRef} asChild disabled={disabled}>
        {Button}
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenuContent>
          <div
            style={{
              minWidth: width,
            }}
          >
            {Menu}
          </div>
        </DropdownMenuContent>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
};

export default Menu;
