import { faTrash } from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { FormEvent, FunctionComponent, useState } from "react";
import useLoading from "../hooks/useLoading";
import DragAndDrop from "./common/DragAndDrop";
import FormInput from "./common/FormInput";
import Button from "./common/Button";
import OutlineButton from "./common/OutlineButton";
import { sanitizeURI } from "../utils/common";

const AddDomainForm: FunctionComponent<{
  onNewDomain: (domain: string) => Promise<void>;
  onFileFormSubmit: (files: File[]) => Promise<void>;
}> = ({ onNewDomain, onFileFormSubmit }) => {
  const [newDomain, setNewDomain] = useState("");
  const createRequest = useLoading();

  const [f, setFiles] = useState<File[]>([]);

  const request = useLoading();

  const handleAddRecord = async (e: FormEvent) => {
    e.preventDefault();
    const domain = sanitizeURI(newDomain);
    if (!domain) {
      createRequest.error("Bitte geben Sie eine gültige Domain ein.");
      return;
    }
    createRequest.loading();
    try {
      await onNewDomain(newDomain);
      setNewDomain("");
      createRequest.success();
    } catch (err) {
      createRequest.error(
        "Leider ist ein Fehler aufgetreten. Bitte überprüfen Sie den Domainnamen.",
      );
    }
  };

  const handleFileFormSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    try {
      request.loading();
      await onFileFormSubmit(f);
      setFiles([]);
      request.success();
    } catch (e: any) {
      request.error(e.toString());
    }
  };

  const handleDrop = (files: FileList) => {
    setFiles((prev) => prev?.concat(Array.from(files)));
  };

  return (
    <>
      <form
        onSubmit={handleAddRecord}
        className="flex flex-col md:flex-row gap-2 text-base pt-2 border-t-deepblue-200 items-end mt-5"
      >
        <div className="flex-1 w-full">
          <FormInput
            onChange={setNewDomain}
            label={`Einzelne Domain hinzufügen`}
            value={newDomain}
            placeholder="example.com"
          />
        </div>
        <div className="flex flex-row items-end">
          <Button type="submit" loading={createRequest.isLoading}>
            Hinzufügen
          </Button>
        </div>
      </form>
      {createRequest.isLoading && (
        <span className="text-gray-600 block text-right mt-2">
          Domain wird hinzugefügt & gescanned...
        </span>
      )}
      {createRequest.successed && (
        <span className="text-gruen-100 block text-right text-lg mt-2">
          Domain erfolgreich hinzugefügt.
        </span>
      )}
      {createRequest.errored && (
        <span className="text-rot-100 block text-right mt-2">
          {createRequest.errorMessage}
        </span>
      )}

      <div>
        <form
          onSubmit={handleFileFormSubmit}
          className="pt-8 hidden md:flex text-base"
        >
          <div className="flex flex-col flex-1">
            <div className="flex-col flex">
              <span className="mb-1">Liste importieren</span>
              <DragAndDrop onDrop={handleDrop}>
                {f.length > 0 ? (
                  <div className="flex flex-col justify-start items-start flex-1 w-full p-2">
                    {f.map((file) => (
                      <div
                        key={file.name}
                        className="flex text-sm mb-2 flex-row w-full justify-between items-center"
                      >
                        <span className="">{file.name}</span>
                        <OutlineButton
                          onClick={(e) => {
                            e.stopPropagation();
                            setFiles((prev) =>
                              prev.filter((f) => f.name !== file.name),
                            );
                          }}
                        >
                          <FontAwesomeIcon className="" icon={faTrash} />
                        </OutlineButton>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="flex flex-col">
                    <span className="text-sm px-4 mb-2 font-bold">
                      Datei hierher ziehen oder klicken zum hochladen.
                    </span>
                    <span className="text-sm px-4">
                      Die CSV-Datei darf nur eine Domain pro Zeile und keine
                      Spaltenbeschreibung enthalten (charset=utf-8).
                    </span>
                  </div>
                )}
              </DragAndDrop>
            </div>
            <div className="flex flex-row gap-2 justify-end mt-5">
              {f.length > 0 && (
                <Button loading={request.isLoading} type="submit">
                  Domains in der Liste hinzufügen
                </Button>
              )}
            </div>
          </div>
        </form>
        {request.successed && (
          <span className="text-gruen-100 text-right w-full block mt-2">
            Domains werden im Hintergrund dem System hinzugefügt
          </span>
        )}
        {request.errored && (
          <span className="text-rot-100 text-right text-sm mt-3 block">
            {request.errorMessage}
          </span>
        )}
      </div>
    </>
  );
};

export default AddDomainForm;
