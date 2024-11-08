import React, { FunctionComponent, useEffect, useState } from "react";

const MIN_TEXTAREA_HEIGHT = 32;

interface Props
  extends Omit<React.TextareaHTMLAttributes<HTMLTextAreaElement>, "onChange"> {
  onChange: (newString: string) => void;
  value: string;
  className?: string;
}
const Textarea: FunctionComponent<Props> = (props) => {
  const textareaRef = React.useRef<HTMLTextAreaElement>(null);
  const [minHeight, setMinHeight] = useState(MIN_TEXTAREA_HEIGHT);
  useEffect(() => {
    if (!textareaRef.current) return;
    // Reset height - important to shrink on delete
    textareaRef.current.style.height = "inherit";
    // Set height
    setMinHeight(
      Math.max(textareaRef.current.scrollHeight, MIN_TEXTAREA_HEIGHT),
    );
  }, [props.value]);

  return (
    <textarea
      {...props}
      onChange={(e) => props.onChange(e.target.value)}
      ref={textareaRef}
      style={{
        minHeight,
        resize: "none",
      }}
    />
  );
};

export default Textarea;
