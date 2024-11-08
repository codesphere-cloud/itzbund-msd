import { FunctionComponent, useMemo } from "react";
import { PaginateResult } from "../../types";
import { classNames } from "../../utils/common";

const buildArray = (length: number, currentPage: number) => {
  if (length === 0) {
    return [];
  }
  const res = [];
  for (
    let i = Math.max(0, currentPage - 2);
    i < Math.min(currentPage + 3, length + 1);
    i++
  ) {
    res.push(i);
  }
  return res;
};
type Props = Omit<PaginateResult<any>, "data"> & {
  onPageChange: (page: number) => void;
};
const Pagination: FunctionComponent<Props> = (props) => {
  const lastPage = Math.floor(props.total / props.pageSize);
  const pages = useMemo(
    () => buildArray(lastPage, props.page),
    [props.page, lastPage],
  );

  return (
    <div>
      {props.page > 2 && (
        <button
          onClick={() => props.onPageChange(0)}
          className={classNames(
            "page-box px-3 py-1 mx-1 mr-5 rounded-sm border border-hellgrau-100 transition-all hover:bg-dunkelblau-100 hover:border-bund hover:text-white",
          )}
        >
          1
        </button>
      )}
      {pages.map((i) => {
        return (
          <button
            onClick={() => props.onPageChange(i)}
            className={classNames(
              "page-box px-3 py-1 mx-1 rounded-sm border transition-all hover:bg-dunkelblau-100 hover:border-bund hover:text-white",
              i === props.page
                ? "bg-dunkelblau-100 border-bund text-white"
                : "border-hellgrau-100",
            )}
            key={i}
          >
            {i + 1}
          </button>
        );
      })}
      {props.page + 2 < lastPage && (
        <button
          onClick={() =>
            props.onPageChange(Math.floor(props.total / props.pageSize))
          }
          className={classNames(
            "ml-5 page-box px-3 py-1 rounded-sm mx-1 border border-hellgrau-100 transition-all hover:bg-dunkelblau-100 hover:border-bund hover:text-white",
          )}
        >
          {Math.floor(props.total / props.pageSize) + 1}
        </button>
      )}
    </div>
  );
};

export default Pagination;
