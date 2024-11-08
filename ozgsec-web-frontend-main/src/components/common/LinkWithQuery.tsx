"use client";
import Link, { LinkProps } from "next/link";
import { useSearchParams } from "next/navigation";
import React, { FunctionComponent } from "react";

const LinkWithQuery: FunctionComponent<
  Omit<React.AnchorHTMLAttributes<HTMLAnchorElement>, keyof LinkProps> &
    LinkProps & {
      children?: React.ReactNode;
    } & React.RefAttributes<HTMLAnchorElement>
> = (props) => {
  const query = useSearchParams();
  if (Object.keys(Object.fromEntries(query ?? [])).length === 0) {
    return <Link {...props} />;
  }

  return <Link {...props} href={`${props.href}?${query?.toString()}`} />;
};

export default LinkWithQuery;
