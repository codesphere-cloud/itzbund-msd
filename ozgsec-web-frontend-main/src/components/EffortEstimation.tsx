import { FunctionComponent } from "react";
import { classNames } from "../utils/common";

type Color = "red" | "orange" | "green";

const colorMapping: { [key in Color]: string } = {
  red: "bg-red-500",
  orange: "bg-orange-500",
  green: "bg-lightning-500",
};

export type EffortEstimationItem = { title: string; color: Color };
interface Props {
  items: Array<EffortEstimationItem>;
}
const EffortEstimation: FunctionComponent<Props> = (props) => {
  return (
    <div>
      <b>Resourcenabschätzung</b>
      <div>
        {props.items.map((item) => (
          <div key={item.title} className="flex mt-5 flex-row">
            <div
              className={classNames(
                colorMapping[item.color],
                "w-4 h-4 rounded-sm mr-2",
              )}
            />
            <span className="leading-5 relative bottom-0.5">{item.title}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default EffortEstimation;
