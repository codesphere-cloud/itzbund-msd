import React, { FunctionComponent, useState } from "react";
import useLoading from "../hooks/useLoading";
import { FeatureFlag, ICreateUserDTO, IUserPutDTO } from "../types";
import Button from "./common/Button";

import FormInput from "./common/FormInput";
import Checkbox from "./common/Checkbox";
import { featureFlagMapper } from "../messages";
import UserRepresentation from "@keycloak/keycloak-admin-client/lib/defs/userRepresentation";
import { User } from "@prisma/client";

interface Props {
  onSubmit: (form: IUserPutDTO) => Promise<void>; // should return the password of the user
  user: User & UserRepresentation;
}
const EditUserForm: FunctionComponent<Props> = (props) => {
  const submitRequest = useLoading();

  const [username, setUsername] = useState(props.user.username ?? "");
  const [featureFlags, setFeatureFlags] = useState<
    Record<FeatureFlag, boolean>
  >(props.user.featureFlags as Record<FeatureFlag, boolean>);

  const onSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    try {
      submitRequest.loading();
      await props.onSubmit({
        id: props.user.id,
        username,
        featureFlags,
      });

      // reset the form
      setUsername("");
      setFeatureFlags({
        [FeatureFlag.collections]: false,
      });

      submitRequest.success();
    } catch (e: any) {
      submitRequest.error(e.toString());
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
            <Button loading={submitRequest.isLoading} type="submit">
              Speichern
            </Button>
          </div>
        </div>
      </form>

      {submitRequest.errored && (
        <span className="text-rot-100 absolute text-sm mt-3 block">
          {submitRequest.errorMessage}
        </span>
      )}
    </div>
  );
};

export default EditUserForm;
