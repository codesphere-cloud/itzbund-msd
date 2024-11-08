import { Collection } from "@prisma/client";
import { FunctionComponent } from "react";
import { classNames } from "../utils/common";
import { DTO } from "../utils/server";

interface Props extends DTO<Collection> {
  onClick?: (id: number) => void;
  selected: boolean;
}
const CollectionPill: FunctionComponent<Props> = ({
  id,
  color,
  title,
  onClick,
  selected,
}) => {
  return (
    <div
      onClick={() => {
        onClick?.(id);
      }}
      className={classNames(
        "flex bg-white border-2 cursor-pointer flex-row items-center  text-sm px-2 rounded-sm",
      )}
      style={{ borderColor: selected ? color : undefined }}
    >
      {title}
    </div>
  );
};

export default CollectionPill;
