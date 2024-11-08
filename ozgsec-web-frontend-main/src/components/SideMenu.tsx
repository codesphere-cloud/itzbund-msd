import React, { FunctionComponent } from "react";
import { classNames } from "../utils/common";
import Button from "./common/Button";
import * as Portal from "@radix-ui/react-portal";
import Image from "next/image";

interface Props {
  isOpen: boolean;
  children: React.ReactNode;
  onClose: () => void;
}
const SideMenu: FunctionComponent<Props> = ({ isOpen, children, onClose }) => {
  const [visible, setVisible] = React.useState(false);
  React.useEffect(() => {
    setTimeout(() => setVisible(true), 0);
  }, []);

  if (!visible) {
    return null;
  }
  return (
    <Portal.Root>
      <div
        className={classNames(
          "fixed bottom-0 text-base left-0 right-0 transition-all z-100 top-0 border-t-6 border-t-bund",
          isOpen
            ? "pointer-events-auto opacity-100"
            : "pointer-events-none opacity-0",
        )}
      >
        <div
          className={classNames(
            "bg-hellgrau-40 w-full absolute flex flex-col right-0 top-0 bottom-0 transition-all",
            isOpen ? "translate-x-0" : "translate-x-full",
          )}
        >
          <Image
            className="absolute opacity-50 z-0 top-1/2 right-0 -translate-y-1/2"
            width={350}
            height={200}
            priority
            src={"/assets/Adler_Ausschnitt_1.svg"}
            alt="Bundesadler"
          />
          <div className="p-8 relative z-10 flex right-0 top-0 flex-row justify-start">
            <Button
              onClick={onClose}
              LeftIcon={
                <svg
                  xmlns="http://www.w3.org/2000/svg"
                  className="w-5 fill-current"
                  viewBox="0 0 14 14"
                >
                  <path
                    d="m8.4 7 5.4-5.4a.2.2 0 0 0 0-.3l-1-1a.2.2 0 0 0-.4 0L7 5.5 1.6.2a.2.2 0 0 0-.3 0l-1 1a.2.2 0 0 0 0 .4L5.5 7 .2 12.4a.2.2 0 0 0 0 .3l1 1a.2.2 0 0 0 .4 0L7 8.5l5.4 5.4a.2.2 0 0 0 .3 0l1-1a.2.2 0 0 0 0-.4Z"
                    data-name="close"
                  />
                </svg>
              }
            >
              Schließen
            </Button>
          </div>
          <div className="overflow-y-auto relative z-10 p-8 pt-0 overflow-x-hidden flex-1">
            {children}
          </div>
        </div>
      </div>
    </Portal.Root>
  );
};

export default SideMenu;
