import { faFile } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { FunctionComponent, ReactNode } from "react";

interface Props {
  ReferenceTitle?: ReactNode;
  ImplementationIcon?: ReactNode;
  ImplementationTitle?: ReactNode;
}
const DescriptionAdditional: FunctionComponent<Props> = (props) => {
  if (!props.ReferenceTitle && !props.ImplementationTitle) {
    return null;
  }
  return (
    <div>
      {props.ReferenceTitle !== undefined && (
        <div className="mb-6">
          <b>Referenz</b>
          <div className="flex items-center mt-2 flex-row">
            <FontAwesomeIcon icon={faFile} />
            <div className="ml-2">{props.ReferenceTitle}</div>
          </div>
        </div>
      )}
      {props.ImplementationTitle !== undefined && (
        <div>
          <b>Umsetzung</b>
          <div className="flex items-center mt-2 flex-row">
            {props.ImplementationIcon}
            <div className="ml-2">{props.ImplementationTitle}</div>
          </div>
        </div>
      )}
    </div>
  );
};

export default DescriptionAdditional;
