import { faTimes } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import * as Dialog from "@radix-ui/react-dialog";
import React, { FunctionComponent } from "react";
import Button from "./Button";

interface Props {
  isOpen: boolean;
  onClose: () => void;
  children: React.ReactNode;
  title: string;
}
const Modal: FunctionComponent<Props> = (props) => {
  return (
    <Dialog.Root
      open={props.isOpen}
      onOpenChange={() => {
        props.onClose();
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="DialogOverlay z-100 bg-black/50" />
        <Dialog.Content className="DialogContent z-300 bg-white rounded-sm text-textblack">
          <div className="flex flex-row mb-5 justify-between">
            <Dialog.Title className="DialogTitle text-xl font-bold mb-2">
              {props.title}
            </Dialog.Title>
            <Dialog.Close asChild>
              <Button aria-label="Close">
                <div className="flex flex-row items-center">
                  <FontAwesomeIcon className="-mb-0" icon={faTimes} />
                </div>
              </Button>
            </Dialog.Close>
          </div>
          <div className="py-4">{props.children}</div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
};

export default Modal;
