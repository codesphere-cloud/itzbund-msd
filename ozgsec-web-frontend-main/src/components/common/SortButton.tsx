import { IconProp } from "@fortawesome/fontawesome-svg-core";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { FunctionComponent } from "react";
import { classNames } from "../../utils/common";

export const SortButton: FunctionComponent<{
  sortKey: "uri";
  onSort: (key: "uri") => void;
  active: boolean;
  getIcon: () => IconProp;
}> = ({ sortKey: key, onSort, active, getIcon }) => {
  return (
    <button
      onClick={() => {
        onSort(key);
      }}
      className={classNames("ml-2 transition-all w-8 h-8 text-white")}
    >
      <FontAwesomeIcon icon={getIcon()} />
    </button>
  );
};
