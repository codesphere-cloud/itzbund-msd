import { faClose, faCopy } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { ShareLink } from "@prisma/client";
import Link from "next/link";
import { FunctionComponent } from "react";
import { DTO } from "../utils/server";
import { secretToShareLink, w } from "../utils/view";
import { toast } from "./Toaster";

interface Props {
  shareLink: DTO<ShareLink>;
  onDelete: (shareLink: DTO<ShareLink>) => Promise<void>;
}
const ShareLinkItem: FunctionComponent<Props> = ({ shareLink, onDelete }) => {
  return (
    <div
      className="text-textblack text-sm flex-row flex justify-between items-center p-2 px-3"
      key={shareLink.secret}
    >
      <Link href={secretToShareLink(shareLink.secret)}>
        {secretToShareLink(shareLink.secret)}
      </Link>
      <div className="flex flex-row ml-5 items-center gap-2">
        <button
          onClick={() => {
            navigator.clipboard.writeText(
              w()?.location.host + secretToShareLink(shareLink.secret),
            );
            toast({
              msg: "Link wurde in die Zwischenablage kopiert",
              type: "info",
            });
          }}
          title="Link kopieren"
          type="button"
          className="mr-2"
        >
          <FontAwesomeIcon icon={faCopy} />
        </button>
        <button type="button" onClick={() => onDelete(shareLink)}>
          <FontAwesomeIcon icon={faClose} />
        </button>
      </div>
    </div>
  );
};

export default ShareLinkItem;
