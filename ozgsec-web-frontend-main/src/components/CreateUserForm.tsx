import React, { FunctionComponent, useState } from "react";
import useLoading from "../hooks/useLoading";
import { FeatureFlag, ICreateUserDTO } from "../types";
import Button from "./common/Button";

import FormInput from "./common/FormInput";
import Checkbox from "./common/Checkbox";
import { featureFlagMapper } from "../messages";

interface Props {
  onCreateUser: (form: ICreateUserDTO) => Promise<string>; // should return the password of the user
}
const CreateUserForm: FunctionComponent<Props> = ({ onCreateUser }) => {
  const createRequest = useLoading();

  const [username, setUsername] = useState("");
  const [featureFlags, setFeatureFlags] = useState<
    Record<FeatureFlag, boolean>
  >({
    [FeatureFlag.collections]: false,
  });
  const [userPassword, setUserPassword] = useState("");
  const onSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    try {
      setUserPassword("");
      createRequest.loading();
      const password = await onCreateUser({
        username,
        featureFlags,
      });
      setUserPassword(password);
      // reset the form
      setUsername("");
      setFeatureFlags({
        [FeatureFlag.collections]: false,
      });

      createRequest.success();
    } catch (e: any) {
      createRequest.error(e.toString());
    }
  };
  return (
    <div>
      <form onSubmit={onSubmit} className="pt-10  flex">
        <div className="flex flex-col gap-5 flex-1">
          <FormInput
            label="Nutzername *"
            validator={(value) => {
              if (value.length === 0) {
                return "Bitte trage einen Nutzernamen ein.";
              }
              return true;
            }}
            onChange={setUsername}
            value={username}
          />
          <span className="font-bold mt-6">Erlaubte Funktionen</span>
          {Object.entries(FeatureFlag).map(([key, value]) => {
            return (
              <div className="flex flex-row items-center gap-4" key={key}>
                <Checkbox
                  key={key}
                  checked={featureFlags[value]}
                  onChange={() => {
                    setFeatureFlags((flags) => ({
                      ...flags,
                      [value]: !flags[value],
                    }));
                  }}
                />
                <span>{featureFlagMapper[value]}</span>
              </div>
            );
          })}

          <div className="flex flex-row text-base justify-end mt-5">
            <Button loading={createRequest.isLoading} type="submit">
              Nutzer anlegen
            </Button>
          </div>
        </div>
      </form>

      {createRequest.errored && (
        <span className="text-rot-100 absolute text-sm mt-3 block">
          {createRequest.errorMessage}
        </span>
      )}
      {userPassword && (
        <div className="mt-5 text-right rounded-sm text-base bg-blau-100 px-4 py-2">
          <p className="text-white">
            Nutzer wurde mit folgendem initialen Password angelegt:{" "}
            <span className="font-bold text-white whitespace-nowrap">
              {userPassword}
            </span>
          </p>
        </div>
      )}
    </div>
  );
};

export default CreateUserForm;
