"use client";
import {
  faEllipsisVertical,
  faQuestionCircle,
} from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

import { FunctionComponent, useEffect, useState } from "react";
import CreateUserForm from "../../../components/CreateUserForm";
import PageTitle from "../../../components/PageTitle";
import Button from "../../../components/common/Button";
import Menu from "../../../components/common/Menu";
import Modal from "../../../components/common/Modal";
import Tooltip from "../../../components/common/Tooltip";
import { classNames } from "../../../utils/common";

import { signIn } from "next-auth/react";

import UserRepresentation from "@keycloak/keycloak-admin-client/lib/defs/userRepresentation";
import { User } from "@prisma/client";
import DropdownMenuItem from "../../../components/common/DropdownMenuItem";
import { clientHttpClient } from "../../../services/clientHttpClient";
import { ICreateUserDTO, IUserPutDTO } from "../../../types";
import EditUserForm from "../../../components/EditUserForm";

interface Props {
  error: boolean;
  users: Array<
    UserRepresentation &
      User & { id: string; targetsCount: number; totalImprovements: number }
  >;
}

const Content: FunctionComponent<Props> = (props) => {
  const [isOpen, setIsOpen] = useState(false);
  const [editUser, setEditUser] = useState<
    | (UserRepresentation &
        User & { id: string; targetsCount?: number; totalImprovements: number })
    | null
  >(null);
  const [users, setUser] = useState(props.users);

  const handleCreateUser = async (form: ICreateUserDTO) => {
    const { username } = form;
    if (username.length === 0) {
      throw new Error("Bitte trage einen Nutzernamen ein.");
    }
    const createUserDTO = { username, featureFlags: form.featureFlags };

    const res = await clientHttpClient("/api/v1/users", crypto.randomUUID(), {
      method: "POST",
      body: JSON.stringify(createUserDTO),
    });
    if (!res.ok) {
      throw res;
    }
    const body = await res.json();
    const user: User = body.user;

    setUser((users) => [
      { ...user, targetsCount: 0, totalImprovements: 0 },
      ...users,
    ]);
    return body.password;
  };

  useEffect(() => {
    if (props.error) {
      signIn("keycloak");
    }
  }, [props.error]);

  const handleDelete = async (id: string) => {
    const res = await clientHttpClient(
      `/api/v1/users/${id}`,
      crypto.randomUUID(),
      {
        method: "DELETE",
      },
    );
    if (!res.ok) {
      throw res;
    }
    setUser((users) => users.filter((user) => user.id !== id));
  };

  const handleUpdateUser = async (form: IUserPutDTO) => {
    const { id, username } = form;
    if (username.length === 0) {
      throw new Error("Bitte trage einen Nutzernamen ein.");
    }

    const res = await clientHttpClient(
      `/api/v1/users/${id}`,
      crypto.randomUUID(),
      {
        method: "PUT",
        body: JSON.stringify(form),
      },
    );
    if (!res.ok) {
      throw res;
    }
    const updatedUser = await res.json();

    setUser((users) =>
      users.map((user) => {
        if (user.id === id) {
          return {
            ...updatedUser,
            targetsCount: user.targetsCount,
            totalImprovements: user.totalImprovements,
          };
        }
        return user;
      }),
    );
    setEditUser(null);
  };

  return (
    <>
      <div className="flex-1">
        <div className="lg:flex lg:flex-row w-full flex-wrap  items-start justfy-between">
          <div className="flex-1">
            <div className=" mb-10 gap-2 flex flex-row items-center">
              <PageTitle
                className="text-2xl  mb-0 font-bold"
                stringRep="Nutzerverwaltung"
              >
                Nutzerverwaltung
              </PageTitle>
              <Tooltip
                tooltip={`         
    In der Nutzerverwaltung lassen sich die Nutzer des Systems
    einsehen, verwalten und löschen.`}
              >
                <div className="text-dunkelgrau-100">
                  <FontAwesomeIcon icon={faQuestionCircle} />
                </div>
              </Tooltip>
            </div>
          </div>
          <Button type="button" loading={false} onClick={() => setIsOpen(true)}>
            Nutzer erstellen
          </Button>
        </div>
        <div className="-mx-1.5">
          <table className="w-full text-left overflow-hidden border-separate border-spacing-1.5">
            <thead className="hidden lg:table-header-group">
              <tr className="bg-dunkelblau-100  text-sm text-white text-left">
                <th className="p-2 px-4 py-4">Nutzername</th>
                <th className="p-2 px-4 py-4">Domains</th>
                <th className="p-2 px-4 py-4">Einzelverbesserungen</th>
                <th className="p-2 whitespace-nowrap py-4">Aktionen</th>
              </tr>
            </thead>
            <tbody>
              <tr className="flex bg-hellgrau-60 flex-col lg:table-row relative mt-3">
                <td className="p-2 px-4">Gesamt</td>
                <td className="p-2 px-4">
                  {users.reduce((acc, curr) => acc + curr.targetsCount, 0)}
                </td>
                <td className="p-2 px-4">
                  {users.reduce((acc, curr) => acc + curr.totalImprovements, 0)}
                </td>
                <td className="p-2 px-4"></td>
              </tr>
              {users.map((user, i) => (
                <tr
                  className={classNames(
                    "flex flex-col lg:table-row relative mt-3",
                    i % 2 !== 0 ? "bg-blau-20/40" : "bg-dunkelblau-20/20",
                  )}
                  key={user.id}
                >
                  <td className="p-2 px-4">{user.username}</td>
                  <td className="p-2 px-4">{user.targetsCount ?? ""}</td>
                  <td className="p-2 px-4">{user.totalImprovements ?? ""}</td>
                  <td className="p-2 w-20 absolute lg:static top-0 right-0 text-right">
                    <div className="flex flex-row justify-end">
                      <Menu
                        Button={
                          <Button className="p-2 px-4 h-8 w-8 flex flex-row items-center justify-center">
                            <FontAwesomeIcon icon={faEllipsisVertical} />
                          </Button>
                        }
                        Menu={
                          <>
                            <DropdownMenuItem onClick={() => setEditUser(user)}>
                              Bearbeiten
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              onClick={() => handleDelete(user.id)}
                            >
                              Löschen
                            </DropdownMenuItem>
                          </>
                        }
                      />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <Modal
        title="Nutzer erstellen"
        isOpen={isOpen}
        onClose={() => setIsOpen(false)}
      >
        <CreateUserForm onCreateUser={handleCreateUser} />
      </Modal>
      <Modal
        title="Nutzer bearbeiten"
        isOpen={Boolean(editUser)}
        onClose={() => setEditUser(null)}
      >
        {editUser && (
          <EditUserForm user={editUser} onSubmit={handleUpdateUser} />
        )}
      </Modal>
    </>
  );
};

export default Content;
