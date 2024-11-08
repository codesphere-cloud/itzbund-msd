import React, {
  DragEventHandler,
  FunctionComponent,
  PropsWithChildren,
  useRef,
  useState,
} from "react";
import { classNames } from "../../utils/common";

interface Props {
  onDrop: (files: FileList) => void;
}

export const DragAndDrop: FunctionComponent<PropsWithChildren<Props>> = ({
  onDrop,
  children,
}) => {
  const [drag, setDrag] = useState(false);

  const fileSelector = useRef<HTMLInputElement>(null);

  const handleDragOver: DragEventHandler = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };
  const handleDragEnter: DragEventHandler = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.dataTransfer.items && e.dataTransfer.items.length > 0) {
      setDrag(true);
    }
  };
  const handleDragLeave: DragEventHandler = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDrag(false);
  };
  const handleDrop: DragEventHandler = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDrag(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      onDrop(e.dataTransfer.files);
      e.dataTransfer.clearData();
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      onDrop(e.target.files);
    }
  };

  return (
    <div
      onDrop={handleDrop}
      onDragLeave={handleDragLeave}
      onDragOver={handleDragOver}
      onDragEnter={handleDragEnter}
      onClick={() => fileSelector.current?.click()}
      className={classNames(
        "draganddrop hover:bg-hellgrau-60 rounded-md cursor-pointer transition-all w-full relative border-2 border-dashed border-dunkelgrau-100 flex flex-col justify-center items-center",
        drag && "bg-hellgrau-60",
      )}
    >
      <input
        onChange={handleFileChange}
        ref={fileSelector}
        className="hidden"
        type={"file"}
        multiple
        value={[]}
      />
      {children}
    </div>
  );
};
export default DragAndDrop;
