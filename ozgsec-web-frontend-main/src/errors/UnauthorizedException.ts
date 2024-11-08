import HttpError from "./HttpError";

export class UnauthorizedException extends HttpError {
  constructor(msg: string = "Unauthorized") {
    super("Unauthorized", 401, msg);
  }
}
