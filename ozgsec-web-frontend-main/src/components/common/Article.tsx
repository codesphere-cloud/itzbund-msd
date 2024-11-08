import { FunctionComponent, PropsWithChildren } from "react";

interface Props {
  title: string;
  teaser: string;
}
const Article: FunctionComponent<PropsWithChildren<Props>> = ({
  title,
  teaser,
  children,
}) => {
  return (
    <article>
      <div className="bg-hellblau-20 py-5">
        <div className="container">
          <h1>{title}</h1>
          <p className="text-lg">{teaser}</p>
        </div>
      </div>
      <div className="container pb-20">
        <div className="md:mx-20 mx-0">{children}</div>
      </div>
    </article>
  );
};

export default Article;
