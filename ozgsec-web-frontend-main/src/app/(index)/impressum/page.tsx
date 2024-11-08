import { FunctionComponent } from "react";
import { withNotAvailable } from "../../../decorators/withNotAvailable";
import Content from "./content";

const title = "Impressum - OZG-Security-Challenge 2023";
const description = "Impressum des Auftritts";

export const metadata = {
  title,
  description,
  openGraph: {
    title,
    description,
    type: "website",
  },
  alternates: {
    canonical: "/impressum",
  },
};

interface Props {
  displayNotAvailable: boolean;
}
const Imprint: FunctionComponent<Props> = ({ displayNotAvailable }) => {
  return <Content displayNotAvailable={displayNotAvailable} />;
};

export default withNotAvailable(Imprint);
