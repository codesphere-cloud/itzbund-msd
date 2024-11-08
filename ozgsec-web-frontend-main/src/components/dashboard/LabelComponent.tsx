import { FunctionComponent } from "react";
import { VictoryLabel, VictoryTooltip } from "victory";
import { tailwindColors } from "../../utils/view";

export const LabelComponent: FunctionComponent<any & { fill: string }> = (
  props,
) => {
  if (props.data?.length - 1 === +(props.index ?? 0)) {
    return (
      <VictoryLabel
        {...props}
        textAnchor={"end"}
        verticalAnchor={"middle"}
        dy={0}
        renderInPortal={true}
        dx={30}
        backgroundStyle={{
          fill: tailwindColors.deepblue["600"],
        }}
        style={{
          fontSize: 10,
          fill: props.fill,
        }}
      />
    );
  }
  return (
    <VictoryTooltip
      {...props}
      constrainToVisibleArea
      style={{
        fill: props.fill,
        fontSize: 10,
      }}
      flyoutPadding={2.5}
      flyoutStyle={{
        stroke: "none",
        fill: tailwindColors.deepblue["600"],
      }}
      dx={0}
      dy={-1.55}
      pointerLength={0}
    />
  );
};
