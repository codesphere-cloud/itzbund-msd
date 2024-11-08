"use client";
import {
  faArrowRight,
  faEllipsisVertical,
  faQuestionCircle,
} from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { Collection, ShareLink } from "@prisma/client";

import Link from "next/link";
import { FunctionComponent, useState } from "react";
import CollectionForm from "../../../components/CollectionForm";
import CollectionPill from "../../../components/CollectionPill";
import EditCollectionForm from "../../../components/EditCollectionForm";
import PageTitle from "../../../components/PageTitle";
import ShareLinkItem from "../../../components/ShareLinkItem";
import Button from "../../../components/common/Button";
import Menu from "../../../components/common/Menu";
import Modal from "../../../components/common/Modal";
import Tooltip from "../../../components/common/Tooltip";
import { clientHttpClient } from "../../../services/clientHttpClient";
import { classNames } from "../../../utils/common";
import { DTO } from "../../../utils/server";
import DropdownMenuItem from "../../../components/common/DropdownMenuItem";

interface Props {
  collections: Array<DTO<Collection & { shareLinks: Array<DTO<ShareLink>> }>>;
}
const Content: FunctionComponent<Props> = (props) => {
  const [collections, setCollections] = useState(props.collections);
  const [isOpen, setIsOpen] = useState(false);

  const [selectedCollection, selectCollection] = useState<DTO<
    Collection & { shareLinks: Array<DTO<ShareLink>> }
  > | null>(null);

  const handleCollectionCreate = async (collection: {
    title: string;
    color: string;
  }) => {
    const res = await clientHttpClient(
      `/api/v1/collections`,
      crypto.randomUUID(),
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(collection),
      },
    );

    if (!res.ok) {
      throw res;
    }
    const coll = await res.json();
    setCollections((prev) => {
      return prev.concat(coll);
    });
    setIsOpen(false);
  };

  const destroy = async (id: number) => {
    const res = await clientHttpClient(
      `/api/v1/collections/${id}`,
      crypto.randomUUID(),
      {
        method: "DELETE",
      },
    );

    if (!res.ok) {
      throw res;
    }
    setCollections((prev) => {
      return prev.filter((c) => c.id !== id);
    });
  };

  const handleUpdateCollection = async (collection: {
    id: number;
    color: string;
    title: string;
  }) => {
    const res = await clientHttpClient(
      `/api/v1/collections/${collection.id}`,
      crypto.randomUUID(),
      {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(collection),
      },
    );

    if (!res.ok) {
      throw res;
    }
    const coll = await res.json();
    setCollections((prev) => {
      return prev.map((c) => {
        if (c.id === coll.id) {
          return coll;
        }
        return c;
      });
    });
    selectCollection(null);
  };

  const handleGenerateLink = async (collectionId: number) => {
    const res = await clientHttpClient(
      `/api/v1/collections/${collectionId}/share`,
      crypto.randomUUID(),
      {
        method: "POST",
      },
    );
    if (!res.ok) {
      throw res;
    }
    const shareLink = await res.json();
    setCollections((prev) => {
      return prev.map((c) => {
        if (c.id === collectionId) {
          return {
            ...c,
            shareLinks: c.shareLinks.concat(shareLink),
          };
        }
        return c;
      });
    });
    // update the selected collection
    selectCollection((prev) => {
      if (prev && prev.id === collectionId) {
        return {
          ...prev,
          shareLinks: prev.shareLinks.concat(shareLink),
        };
      }
      return prev;
    });
  };

  const handleShareLinkDelete = async (shareLink: DTO<ShareLink>) => {
    const res = await clientHttpClient(
      `/api/v1/sharelink/${shareLink.secret}`,
      crypto.randomUUID(),
      {
        method: "DELETE",
      },
    );
    if (!res.ok) {
      throw res;
    }
    setCollections((prev) => {
      return prev.map((c) => {
        if (c.id === shareLink.collectionId) {
          return {
            ...c,
            shareLinks: c.shareLinks.filter(
              (sl) => sl.secret !== shareLink.secret,
            ),
          };
        }
        return c;
      });
    });
    // update the selected collection
    selectCollection((prev) => {
      if (prev && prev.id === shareLink.collectionId) {
        return {
          ...prev,
          shareLinks: prev.shareLinks.filter(
            (sl) => sl.secret !== shareLink.secret,
          ),
        };
      }
      return prev;
    });
  };

  return (
    <>
      <div className="flex-1">
        <div className="lg:flex lg:flex-row w-full flex-wrap  items-start justfy-between mb-12 lg:mb-0">
          <div className="flex-1">
            <div className=" mb-10 gap-2 flex flex-row items-center">
              <PageTitle
                className="text-2xl  mb-0 font-bold"
                stringRep="Gruppen"
              >
                Gruppen
              </PageTitle>
              <Tooltip
                tooltip={`Gruppen dienen der Sortierung einzelner Domains. Es ist möglich Gruppen direkt miteinander zu vergleichen.`}
              >
                <div className="text-dunkelgrau-100">
                  <FontAwesomeIcon icon={faQuestionCircle} />
                </div>
              </Tooltip>
            </div>
          </div>
          <Button type="button" loading={false} onClick={() => setIsOpen(true)}>
            Gruppe hinzufügen
          </Button>
        </div>

        <table className="w-full text-left overflow-hidden border-separate border-spacing-2">
          <thead className="hidden lg:table-header-group">
            <tr className="text-sm rounded-t-md bg-dunkelblau-100 text-left text-white">
              <th className="p-2 py-4">Titel</th>
              <th className="p-2 py-4">Domains</th>
              <th className="p-2 py-4">
                Link für externen, lesenden Zugriff ohne Account
              </th>
              <th className="p-2 py-4">Aktionen</th>
            </tr>
          </thead>
          <tbody>
            {collections.map((collection, i, arr) => {
              return (
                <tr
                  className={classNames(
                    "mt-3 lg:table-row relative p-1 lg:p-0 flex flex-col flex-wrap justify-between rounded-md lg:mt-0 lg:rounded-none",
                    " group/collection-item",
                    i !== arr.length - 1 && "border-b",
                    "border-b-deepblue-300 transition-all",
                    i % 2 !== 0 ? "bg-blau-20/40" : "bg-dunkelblau-20/20",
                  )}
                  key={collection.id}
                >
                  <td className="p-2 text-sm">
                    <div className="flex">
                      <CollectionPill selected {...collection} />
                    </div>
                  </td>

                  <td className="p-2 text-sm text-blau-100">
                    <Link
                      href={`/dashboard/targets?collectionIds=${collection.id}`}
                    >
                      Domains der Gruppe ansehen
                      <FontAwesomeIcon className="ml-2" icon={faArrowRight} />
                    </Link>
                  </td>
                  <td
                    className={classNames(
                      "order-2 md:w-auto px-2 w-full",
                      collection.shareLinks.length > 0
                        ? "px-2 "
                        : "hidden md:table-cell",
                    )}
                  >
                    <div className="py-2 flex flex-col gap-2">
                      {collection.shareLinks.map((shareLink) => {
                        return (
                          <ShareLinkItem
                            onDelete={() => handleShareLinkDelete(shareLink)}
                            shareLink={shareLink}
                            key={shareLink.secret}
                          />
                        );
                      })}

                      {collection.shareLinks.length === 0 && (
                        <div className="flex opacity-0 group-hover/collection-item:opacity-100 transition-all text-sm flex-row justify-end">
                          <Button
                            onClick={() => handleGenerateLink(collection.id)}
                          >
                            Link erstellen
                          </Button>
                        </div>
                      )}
                    </div>
                  </td>
                  <td
                    className="text-right lg:static absolute top-0 right-0 p-2"
                    onClick={(e) => e.stopPropagation()}
                  >
                    <div className="flex  flex-row justify-end">
                      <Menu
                        Button={
                          <Button className="w-10 h-10">
                            <FontAwesomeIcon icon={faEllipsisVertical} />
                          </Button>
                        }
                        Menu={
                          <>
                            <DropdownMenuItem
                              onClick={() => selectCollection(collection)}
                            >
                              Bearbeiten / Teilen
                            </DropdownMenuItem>

                            <DropdownMenuItem
                              onClick={() => destroy(collection.id)}
                            >
                              Löschen
                            </DropdownMenuItem>
                          </>
                        }
                      />
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <Modal
        title="Gruppe hinzufügen"
        isOpen={isOpen}
        onClose={() => setIsOpen(false)}
      >
        <CollectionForm onCreate={handleCollectionCreate} />
      </Modal>
      <Modal
        title="Gruppe bearbeiten"
        onClose={() => selectCollection(null)}
        isOpen={Boolean(selectedCollection)}
      >
        {selectedCollection && (
          <EditCollectionForm
            onShareLinkDelete={handleShareLinkDelete}
            onGenerateLink={handleGenerateLink}
            collection={selectedCollection}
            onSubmit={handleUpdateCollection}
          />
        )}
      </Modal>
    </>
  );
};

export default Content;
