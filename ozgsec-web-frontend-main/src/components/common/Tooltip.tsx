"use client";

import * as Popover from "@radix-ui/react-popover";
import { FunctionComponent, PropsWithChildren } from "react";

interface Props {
  tooltip: string | JSX.Element;
}
const Tooltip: FunctionComponent<PropsWithChildren<Props>> = (props) => {
  return (
    <Popover.Root>
      <div
        className="flex flex-row items-center justify-center"
        onClick={(e) => e.stopPropagation()}
      >
        <Popover.Trigger aria-label="Hilfe öffnen">
          {props.children}
        </Popover.Trigger>
      </div>
      <Popover.Portal>
        <Popover.Content
          className="TooltipContent text-sm lg:w-72 w-56 bg-white border-3 border-hellgrau-40 z-200 m-1 text-textblack p-2"
          sideOffset={5}
        >
          {props.tooltip}
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
};

export default Tooltip;
