import { FunctionComponent } from "react";
import { withNotAvailable } from "../../../decorators/withNotAvailable";
import Content from "./content";

const title = "Datenschutz - OZG-Security-Challenge 2023";
const description = "Datenschutzhinweise des Auftritts";
export const metadata = {
  title,
  description,
  openGraph: {
    title,
    description,
    type: "website",
  },
  alternates: {
    canonical: "/datenschutz",
  },
};

interface Props {
  displayNotAvailable: boolean;
}
const Privacy: FunctionComponent<Props> = ({ displayNotAvailable }) => {
  return <Content displayNotAvailable={displayNotAvailable} />;
};

export default withNotAvailable(Privacy);
