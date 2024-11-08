import React, { FunctionComponent } from "react";

interface Props {
  progress: number; // number between 0 and 1
}
const Progressbar: FunctionComponent<Props> = (props) => {
  return (
    <div className="flex-1 flex-row flex items-center p-1 h-10 border">
      <div
        className="bg-lightning-500 h-full transition-all"
        style={{
          width: `${props.progress * 100}%`,
        }}
      />
    </div>
  );
};

export default Progressbar;
