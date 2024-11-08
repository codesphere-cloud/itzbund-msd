import { FunctionComponent } from "react";
import IndexContent from "../../components/IndexContent";
import { withNotAvailable } from "../../decorators/withNotAvailable";
import { Metadata } from "next";

export const metadata: Metadata = {
  title: "OZG-Security-Challenge 2023",
  description:
    "OZG Security Schnelltest einer Webseite in Bezug auf IT-Sicherheitsmaßnahmen und Best-Practices",
  openGraph: {
    title: "OZG-Security-Challenge 2023",
    description:
      "OZG Security Schnelltest einer Webseite in Bezug auf IT-Sicherheitsmaßnahmen und Best-Practices",
    type: "website",
  },
  alternates: {
    canonical: "/",
  },
};

const Index: FunctionComponent<{ displayNotAvailable: boolean }> = ({
  displayNotAvailable,
}) => {
  return <IndexContent displayNotAvailable={displayNotAvailable} />;
};

export default withNotAvailable(Index);
