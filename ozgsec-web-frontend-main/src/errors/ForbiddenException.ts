import HttpError from "./HttpError";

export default class ForbiddenException extends HttpError {
  constructor() {
    super("ForbiddenException", 403, "Forbidden");
  }
}
