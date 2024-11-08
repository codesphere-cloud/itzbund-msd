import { faCheck } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { FunctionComponent, useState } from "react";
import { classNames } from "../../utils/common";

interface Props {
  checked: boolean;
  onChange: () => void;
}
const Checkbox: FunctionComponent<Props> = (props) => {
  const [focused, setFocused] = useState(false);
  return (
    <div
      onClick={(e) => {
        e.stopPropagation();
        props.onChange();
      }}
      className={classNames(
        "w-5 h-5 flex rounded-sm flex-row cursor-pointer items-center border  justify-center",
        props.checked
          ? "bg-blau-100 border-blau-100"
          : "border-dunkelgrau-80 bg-white",
        focused ? "outline outline-blau-100" : "",
      )}
    >
      <input
        aria-label="Auswählen"
        type={"checkbox"}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
        checked={props.checked}
        onChange={props.onChange}
        className={"opacity-0 absolute pointer-events-none"}
      />
      {props.checked && (
        <FontAwesomeIcon className="text-white h-3 w-3" icon={faCheck} />
      )}
    </div>
  );
};

export default Checkbox;
