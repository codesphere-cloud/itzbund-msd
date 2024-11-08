import { redirect } from "next/navigation";
import { FunctionComponent } from "react";
import InfoContent from "../../../components/InfoContent";
import { withNotAvailable } from "../../../decorators/withNotAvailable";
import { Metadata } from "next";

const title =
  "Die OZG-Security-Challenge 2023: Gemeinsam zu mehr IT-Sicherheit";
const description = "";

export const metadata: Metadata = {
  title,
  description,
  openGraph: {
    title,
    description,
    type: "website",
  },
  alternates: {
    canonical: "/info",
  },
};

interface Props {
  displayNotAvailable: boolean;
}
const page: FunctionComponent<Props> = ({ displayNotAvailable }) => {
  if (displayNotAvailable) {
    return redirect("/");
  }
  return <InfoContent displayNotAvailable={displayNotAvailable} />;
};

export default withNotAvailable(page);
