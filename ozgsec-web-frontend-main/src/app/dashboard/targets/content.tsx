"use client";

import {
  faCaretDown,
  faCaretUp,
  faQuestionCircle,
} from "@fortawesome/free-solid-svg-icons";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";

import { Collection, Target } from "@prisma/client";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import {
  FunctionComponent,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import AddDomainForm from "../../../components/AddDomainForm";
import CheckStateMenu from "../../../components/CheckStateMenu";
import CollectionPill from "../../../components/CollectionPill";
import PageTitle from "../../../components/PageTitle";
import TargetOverviewForm from "../../../components/TargetOverviewForm";
import TargetTableItem from "../../../components/TargetTableItem";
import Button from "../../../components/common/Button";
import Checkbox from "../../../components/common/Checkbox";
import DropdownMenuItem from "../../../components/common/DropdownMenuItem";
import Menu from "../../../components/common/Menu";
import Modal from "../../../components/common/Modal";
import Pagination from "../../../components/common/Pagination";
import { SortButton } from "../../../components/common/SortButton";
import Tooltip from "../../../components/common/Tooltip";
import { useIsGuest } from "../../../hooks/useIsGuest";
import useLoading from "../../../hooks/useLoading";
import useRefreshOnVisit from "../../../hooks/useRefreshOnVisit";
import { notificationClient } from "../../../notifications/notificationClient";
import {
  NotificationType,
  isDoneNotification,
} from "../../../notifications/notifications";
import { withAuthProvider } from "../../../providers/AuthProvider";
import {
  AccessiblityInspectionType,
  DomainInspectionType,
  HeaderInspectionType,
  InspectionType,
  NetworkInspectionType,
  OrganizationalInspectionType,
  TLSInspectionType,
} from "../../../scanner/scans";
import { clientHttpClient } from "../../../services/clientHttpClient";
import {
  DetailedTarget,
  FeatureFlag,
  IScanSuccessResponse,
  PaginateResult,
  TargetType,
} from "../../../types";
import { classNames } from "../../../utils/common";
import { DTO } from "../../../utils/server";
import { optimisticUpdate } from "../../../utils/view";
import { useIsFeatureEnabled } from "../../../hooks/useFeatureEnabled";
import SubMenu from "../../../components/common/SubMenu";
import CollectionMenuContent from "../../../components/CollectionMenuContent";

const translateDomainType = (type: TargetType) => {
  switch (type) {
    case TargetType.reachable:
      return "Erreichbare Domains";
    case TargetType.unreachable:
      return "Nicht erreichbare Domains";
    case TargetType.all:
      return "Meine Domains";
  }
};

interface Props {
  targets: PaginateResult<DTO<DetailedTarget> & { collections?: number[] }>; // should include array of collection ids the target is in
  // normalized collections map for fast access
  collections: { [collectionId: string]: DTO<Collection> };
}
const Content: FunctionComponent<Props> = (props) => {
  useRefreshOnVisit("targets");
  const [isOpen, setIsOpen] = useState(false);
  const [targets, setTargets] = useState<
    Array<DTO<DetailedTarget> & { collections?: number[] }>
  >(props.targets.data);
  const searchParams = useSearchParams();
  const pathname = usePathname() ?? "";
  const [currentDomainChangeCount, setCurrentDomainChangeCount] = useState(0);
  const [reverseUriBeforeSort, setReverseUriBeforeSort] = useState(false);

  const [selection, setSelection] = useState<{ [uri: string]: boolean }>({});
  const scanAllLoading = useLoading();

  const isGuest = useIsGuest();
  const collectionEnabled = useIsFeatureEnabled(FeatureFlag.collections);
  const scanRequest = useLoading();
  const router = useRouter();

  const viewedDomainType =
    (searchParams?.get("domainType") as TargetType | undefined) ??
    TargetType.all;
  const handleSort = (key: "uri") => {
    // check if we should reverse the order.
    const instructions = { key, direction: 1 as 1 | -1 };
    if (key === sort.key) {
      instructions.direction = (sort.direction * -1) as 1 | -1;
    }
    patchQuery({
      sort: instructions.key,
      sortDirection: instructions.direction.toString(),
    });
  };

  const handleReverseUriBeforeSort = () => {
    const prev = reverseUriBeforeSort;
    patchQuery({
      reverseUriBeforeSort: Number(!prev).toString(),
    });
    setReverseUriBeforeSort(!prev);
  };

  const handleFilterCheckState = (
    key: InspectionType,
    value: 1 | 0 | -1 | undefined,
  ) => {
    if (value === undefined) {
      const { [key]: _, ...query } = Object.fromEntries(searchParams ?? []);
      router.push(`${pathname}?${new URLSearchParams(query).toString()}`);
      return;
    }
    patchQuery({
      [key]: value.toString(),
      page: "0",
    });
  };

  const getIcon = (key: InspectionType | "uri") => {
    if (sort.key === key) {
      return sort.direction === 1 ? faCaretUp : faCaretDown;
    }
    return faCaretUp;
  };

  const patchQuery = useCallback(
    (query: Record<string, string | string[]>) => {
      router.push(
        `${pathname}?${new URLSearchParams({
          ...Object.fromEntries(searchParams ?? []),
          ...(query as Record<string, string>),
        }).toString()}`,
      );

      setCurrentDomainChangeCount(0);
      setSelection({});
    },
    [router, pathname, searchParams],
  );

  useEffect(() => {
    setTargets(props.targets.data);
  }, [props.targets]);

  useEffect(() => {
    const unsub = notificationClient.on(
      NotificationType.DOMAIN_IMPORT_PROGRESS,
      {
        id: "target-page-refresh",
        fn: (n) => {
          if (isDoneNotification(n)) {
            router.refresh();
          }
        },
      },
    );
    return () => unsub();
  }, [router]);
  const deleteTarget = async (uri: string) => {
    // do an optimistic update
    const revert = optimisticUpdate(targets, setTargets, (prev) =>
      prev.filter((d) => d.uri !== uri),
    );
    setSelection((prev) => ({
      ...prev,
      [uri]: false,
    }));
    setCurrentDomainChangeCount((prev) => prev - 1);
    const response = await clientHttpClient(
      `/api/v1/targets/delete`,
      crypto.randomUUID(),
      {
        method: "POST",
        body: JSON.stringify({
          targets: [uri],
        }),
      },
    );
    if (!response.ok) {
      setCurrentDomainChangeCount((prev) => prev + 1);
      revert();
    }
  };

  const selectedTargets = useMemo(
    () =>
      Object.entries(selection)
        .filter(([key, value]) => value)
        .map(([key]) => key),
    [selection],
  );

  const deleteSelection = async () => {
    const response = await clientHttpClient(
      `/api/v1/targets/delete`,
      crypto.randomUUID(),
      {
        method: "POST",
        body: JSON.stringify({
          targets: selectedTargets,
        }),
      },
    );
    if (response.ok) {
      setTargets((prev) =>
        prev.filter((d) => !selectedTargets.includes(d.uri)),
      );
      setCurrentDomainChangeCount((prev) => prev - selectedTargets.length);
      // remove them from the selection
      setSelection((prev) => {
        const newSelection = { ...prev };
        selectedTargets.forEach((uri) => {
          newSelection[uri] = false;
        });
        return newSelection;
      });
    }
  };

  const scanTarget = async (uri: string) => {
    scanRequest.loading(uri);

    const response = await clientHttpClient(
      `/api/v2/scan?site=${uri}&refresh=true`,
      crypto.randomUUID(),
    );

    if (response.ok) {
      const data: DTO<DetailedTarget & { collections: number[] }> =
        await response.json();
      // inject it into the domains
      setTargets((prev) => {
        return prev.map((d) => {
          if (d.uri === data.uri) {
            return data;
          }
          return d;
        });
      });
      scanRequest.success();
    } else {
      setTargets((prev) => {
        const index = prev.findIndex((d) => d.uri === uri);
        if (index === -1) {
          return prev;
        }
        const newDomains = [...prev];
        newDomains[index] = {
          ...newDomains[index],
          lastScan: Date.now(),
          errorCount: (newDomains[index].errorCount || 0) + 1,
        };
        return newDomains;
      });
      scanRequest.error("Fehler beim Scannen der Domain.", uri);
    }
  };

  const handleSearch = async (value: string) => {
    patchQuery({ search: value, page: "0" });
  };

  const handleAddRecord = async (target: string) => {
    const res = await clientHttpClient(`/api/v1/targets`, crypto.randomUUID(), {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ target, collectionIds: collectionIds }),
    });

    if (!res.ok) {
      throw res;
    }
    const detailedDomain = await res.json();
    setCurrentDomainChangeCount((prev) => prev + 1);
    setTargets((prev) => [...prev, detailedDomain]);
  };

  const handleAddToCollection = async (
    target: DTO<{ uri: string }[]>,
    collectionId: number,
  ) => {
    const uris = target.map((d) => d.uri);
    // do an optimistic update.
    const revert = optimisticUpdate(targets, setTargets, (prev) => {
      return prev.map((d) => {
        if (uris.includes(d.uri)) {
          return {
            ...d,
            collections: (d.collections ?? []).concat(collectionId),
          };
        }
        return d;
      });
    });

    const res = await clientHttpClient(
      `/api/v1/collections/${collectionId}/targets`,
      crypto.randomUUID(),
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(target),
      },
    );

    if (!res.ok) {
      // revert the optimistic update
      revert();
      throw res;
    }
  };

  const handleRemoveFromCollection = async (
    target: DTO<Target[]>,
    collectionId: number,
  ) => {
    const uris = target.map((d) => d.uri);
    // do an optimistic update
    const revert = optimisticUpdate(targets, setTargets, (prev) => {
      return prev.map((d) => {
        if (uris.includes(d.uri)) {
          return {
            ...d,
            collections: (d.collections ?? []).filter(
              (c) => c !== collectionId,
            ),
          };
        }
        return d;
      });
    });

    const res = await clientHttpClient(
      `/api/v1/collections/${collectionId}/targets/delete`,
      crypto.randomUUID(),
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(target),
      },
    );

    if (!res.ok) {
      revert();
      throw res;
    }
  };

  const handleFileFormSubmit = async (files: File[]) => {
    const formData = new FormData();
    files.forEach((file) => {
      formData.append("files", file);
    });

    const res = await clientHttpClient("/api/v1/targets", crypto.randomUUID(), {
      method: "POST",
      body: formData,
    });
    if (!res.ok) {
      throw res;
    }
  };

  const collectionIds = useMemo(() => {
    const collections =
      (searchParams?.get("collectionIds") as string | string[]) ?? [];

    return (Array.isArray(collections) ? collections : collections.split(","))
      .map((c) => +c)
      .filter((c) => c > 0);
  }, [searchParams]);

  const handleCollectionFilterToggle = useCallback(
    (collectionId: number) => {
      if (collectionIds.includes(collectionId)) {
        patchQuery({
          collectionIds: collectionIds
            .filter((c) => c !== collectionId)
            .map((c) => c.toString()),
        });
      } else {
        patchQuery({
          collectionIds: collectionIds
            .concat(collectionId)
            .map((c) => c.toString()),
        });
      }
    },
    [collectionIds, patchQuery],
  );

  const handleGroupCollectionClick = (c: DTO<Collection>) => {
    // check if all targets belong to that collection
    const selectedTargets = targets.filter((t) => selection[t.uri]);
    const allInCollection = selectedTargets.every((t) =>
      t.collections?.includes(c.id),
    );

    if (allInCollection) {
      return handleRemoveFromCollection(selectedTargets, c.id);
    }

    return handleAddToCollection(selectedTargets, c.id);
  };

  const sort = {
    key: searchParams?.get("sort") as
      | "uri"
      | keyof IScanSuccessResponse["result"],
    direction: parseInt(searchParams?.get("sortDirection") as string) as 1 | -1,
  };

  return (
    <>
      <div className="flex-1">
        <div className="lg:flex lg:flex-row w-full flex-wrap  items-start justfy-between mb-12 lg:mb-0">
          <div className="flex-1">
            <div className=" mb-10 gap-2 flex flex-row items-center">
              <PageTitle
                className="text-2xl  mb-0 font-bold"
                stringRep="Domainübersicht"
              >
                Domainübersicht
              </PageTitle>
              <Tooltip
                tooltip={`         
            Auf der Domainübersicht finden Sie alle Testergebnisse für Ihre
            Domains auf einen Blick. Hier können Sie schnell und einfach
            vergleichen, wie gut die verschiedenen Domains in Bezug auf die
            verschiedenen ausgeführten Sicherheitstest abschneiden.`}
              >
                <div className="text-dunkelgrau-100">
                  <FontAwesomeIcon icon={faQuestionCircle} />
                </div>
              </Tooltip>
            </div>
          </div>
          {!isGuest && (
            <Button
              type="button"
              loading={false}
              onClick={() => setIsOpen(true)}
            >
              Domains hinzufügen
            </Button>
          )}
        </div>
        <div className="">
          <div className="w-full">
            <div className="">
              <div className="">
                <div className="text-black mb-8">
                  <TargetOverviewForm onSearch={handleSearch} />
                </div>
              </div>
              <div className="flex flex-wrap py-2 gap-2 flex-row border-deepblue-50">
                {!isGuest && (
                  <>
                    <Menu
                      disabled={selectedTargets.length === 0}
                      Button={
                        <Button
                          additionalClasses="flex-1 whitespace-nowrap"
                          disabled={selectedTargets.length === 0}
                          RightIcon={<FontAwesomeIcon icon={faCaretDown} />}
                        >
                          Gruppenaktionen ({selectedTargets.length})
                        </Button>
                      }
                      Menu={
                        <>
                          <DropdownMenuItem
                            loading={scanAllLoading.isLoading}
                            onClick={async () => {
                              scanAllLoading.loading();
                              try {
                                await Promise.all(
                                  selectedTargets.map((d) => scanTarget(d)),
                                );
                              } finally {
                                scanAllLoading.success();
                              }
                            }}
                          >
                            Erneut scannen
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={deleteSelection}>
                            <div>Löschen</div>
                          </DropdownMenuItem>
                          {collectionEnabled && (
                            <SubMenu
                              Menu={
                                <CollectionMenuContent
                                  collections={props.collections}
                                  onCollectionClick={handleGroupCollectionClick}
                                />
                              }
                              Button={<>Zu Gruppe hinzufügen</>}
                            />
                          )}
                        </>
                      }
                    />
                  </>
                )}
                <Menu
                  Button={
                    <Button
                      additionalClasses="flex-1 whitespace-nowrap"
                      RightIcon={<FontAwesomeIcon icon={faCaretDown} />}
                    >
                      Zeige: {translateDomainType(viewedDomainType)} (
                      {props.targets.total + currentDomainChangeCount})
                    </Button>
                  }
                  Menu={
                    <>
                      {Object.values(TargetType).map((type) => (
                        <DropdownMenuItem
                          key={type}
                          active={type === viewedDomainType}
                          loading={scanAllLoading.isLoading}
                          onClick={async () => {
                            patchQuery({ domainType: type, page: "0" });
                          }}
                        >
                          <div>{translateDomainType(type)}</div>
                        </DropdownMenuItem>
                      ))}
                    </>
                  }
                />

                {collectionEnabled &&
                  Object.keys(props.collections).length > 0 && (
                    <Menu
                      Button={
                        <Button
                          additionalClasses="whitespace-nowrap flex-1"
                          RightIcon={<FontAwesomeIcon icon={faCaretDown} />}
                        >
                          Filter nach Gruppen
                        </Button>
                      }
                      Menu={
                        <CollectionMenuContent
                          collections={props.collections}
                          selectedCollections={collectionIds}
                          onCollectionClick={(c) =>
                            handleCollectionFilterToggle(c.id)
                          }
                        />
                      }
                    ></Menu>
                  )}

                {Object.keys(Object.fromEntries(searchParams ?? [])).length >
                  0 && (
                  <Button
                    additionalClasses="flex-1 whitespace-nowrap"
                    onClick={() => {
                      router.push(pathname);
                    }}
                  >
                    Filter zurücksetzen
                  </Button>
                )}
              </div>

              {collectionIds.length > 0 && (
                <div className="flex flex-row py-2 border-deepblue-100 items-center">
                  <div className="flex flex-wrap flex-row gap-2 px-5 items-center pl-4 justify-start">
                    {collectionIds.map((c) => {
                      const col = props.collections[c.toString()];
                      if (!col) {
                        return null;
                      }
                      return <CollectionPill selected key={col.id} {...col} />;
                    })}
                  </div>
                </div>
              )}
            </div>
            <div className="flex mb-6 flex-row justify-end">
              <a
                className="font-normal hover:text-white hover:no-underline"
                download={"domain-export.csv"}
                href={`/api/v1/targets/export?${searchParams.toString()}`}
              >
                <Button>Exportieren</Button>
              </a>
            </div>
            <div className="-mx-1.5">
              <table className="w-full border-separate border-spacing-1.5">
                <thead className="sticky hidden lg:table-header-group table-header z-20">
                  <tr className="text-sm border-b-deepblue-50 text-left bg-dunkelblau-100">
                    <th className="p-2 pr-0 text-center">
                      {!isGuest && targets.length > 0 && (
                        <Checkbox
                          checked={
                            selectedTargets.length > 0 &&
                            selectedTargets.length === targets.length
                          }
                          onChange={() => {
                            setSelection((prev) => {
                              return targets.reduce(
                                (acc, domain) => {
                                  acc[domain.uri] = !Boolean(prev[domain.uri]);
                                  return acc;
                                },
                                {} as Record<string, boolean>,
                              );
                            });
                          }}
                        />
                      )}
                    </th>
                    <th className="p-2">
                      <div>
                        <span className="text-white">Domain</span>
                        <SortButton
                          sortKey="uri"
                          onSort={handleSort}
                          active={sort.key === "uri"}
                          getIcon={() => getIcon("uri")}
                        />
                        <button
                          onClick={handleReverseUriBeforeSort}
                          className={classNames(
                            "ml-0 transition-all font-normal border px-1 border-white/20 text-white",
                            reverseUriBeforeSort
                              ? "bg-white/20 text-black"
                              : "bg-transparent",
                          )}
                        >
                          Nach Subdomains sortieren
                        </button>
                      </div>
                    </th>
                    <th className="p-2">
                      <CheckStateMenu
                        onChange={handleFilterCheckState}
                        inspectionType={
                          OrganizationalInspectionType.ResponsibleDisclosure
                        }
                      />
                    </th>
                    <th className="p-2">
                      <div>
                        <CheckStateMenu
                          onChange={handleFilterCheckState}
                          inspectionType={TLSInspectionType.TLSv1_3}
                        />
                      </div>
                    </th>
                    <th className="p-2">
                      <div>
                        <CheckStateMenu
                          onChange={handleFilterCheckState}
                          inspectionType={
                            TLSInspectionType.DeprecatedTLSDeactivated
                          }
                        />
                      </div>
                    </th>
                    <th className="p-2">
                      <div>
                        <CheckStateMenu
                          onChange={handleFilterCheckState}
                          inspectionType={HeaderInspectionType.HSTS}
                        />
                      </div>
                    </th>
                    <th className="p-2">
                      <div>
                        <CheckStateMenu
                          onChange={handleFilterCheckState}
                          inspectionType={DomainInspectionType.DNSSec}
                        />
                      </div>
                    </th>
                    <th className="p-2">
                      <div>
                        <CheckStateMenu
                          onChange={handleFilterCheckState}
                          inspectionType={
                            AccessiblityInspectionType.ProvidesEnglishWebsiteVersion
                          }
                        />
                      </div>
                    </th>
                    <th className="p-2">
                      <div>
                        <span className="whitespace-nowrap text-white">
                          Aktionen
                        </span>
                      </div>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {targets.map((target, i) => {
                    return (
                      <TargetTableItem
                        collections={props.collections}
                        onToggleCollection={(collection) => {
                          if (
                            target.collections &&
                            target.collections.includes(+collection.id)
                          ) {
                            return handleRemoveFromCollection(
                              [target],
                              collection.id,
                            );
                          }
                          return handleAddToCollection([target], collection.id);
                        }}
                        destroy={(uri) => deleteTarget(uri)}
                        scanRequest={scanRequest}
                        scan={(uri) => scanTarget(uri)}
                        key={target.uri}
                        target={target}
                        selected={Boolean(selection[target.uri])}
                        classNames={classNames(
                          "transition-all",
                          selection[target.uri]
                            ? "bg-dunkelblau-20"
                            : i % 2 !== 0
                              ? "bg-blau-20/40"
                              : "bg-dunkelblau-20/20",
                        )}
                        onSelect={(target) => {
                          setSelection((prev) => {
                            if (prev[target.uri] === undefined) {
                              prev[target.uri] = true;
                              return { ...prev };
                            }
                            return {
                              ...prev,
                              [target.uri]: !prev[target.uri],
                            };
                          });
                        }}
                      />
                    );
                  })}
                </tbody>
              </table>
            </div>
            {targets.length === 0 && (
              <div className="px-6 bg-hellgrau-20 rounded-b-md py-24">
                <div className="mx-auto max-w-2xl text-center">
                  <h2 className="text-xl font-bold">Keine Domains gefunden</h2>
                  <p className="mx-auto mt-6 max-w-xl">
                    Ihre Such- bzw. Filtereinstellungen haben keine Treffer
                    erzielt oder Sie haben noch keine Domains hinterlegt.
                  </p>
                  <div className="mt-10 flex items-center justify-center gap-x-6">
                    {!isGuest && (
                      <Button
                        type="button"
                        loading={false}
                        onClick={() => setIsOpen(true)}
                      >
                        Domains hinzufügen
                      </Button>
                    )}
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
        <div className="mt-5 flex flex-row justify-center">
          <Pagination
            onPageChange={(page) => {
              patchQuery({ page: page.toString() });
            }}
            {...props.targets}
          />
        </div>
      </div>
      <Modal
        title="Domains hinzufügen"
        isOpen={isOpen}
        onClose={() => setIsOpen(false)}
      >
        <AddDomainForm
          onNewDomain={handleAddRecord}
          onFileFormSubmit={handleFileFormSubmit}
        />
      </Modal>
    </>
  );
};

export default withAuthProvider(Content);
