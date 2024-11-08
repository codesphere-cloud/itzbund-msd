import { FunctionComponent, PropsWithChildren } from "react";
import { classNames } from "../utils/common";

interface Props {
  color: string;
  title: string;
}
const CollectionDataPill: FunctionComponent<PropsWithChildren<Props>> = (
  props,
) => {
  return (
    <div
      style={{
        borderColor: props.color,
      }}
      className={classNames(
        "flex items-center border-2 bg-white rounded-sm text-textblack px-2 py-1",
      )}
    >
      {props.children}
    </div>
  );
};

export default CollectionDataPill;
